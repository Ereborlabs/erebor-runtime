use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use snafu::ResultExt as _;

use super::NativeStore;
use crate::{AnalysisBackupFileV1, AnalysisBackupManifestV1, IoSnafu, NativeStateSnafu, Result};

pub(super) struct BackupBudget<'a> {
    store: &'a NativeStore,
    pub manifest: AnalysisBackupManifestV1,
    entries: BTreeMap<PathBuf, Option<u64>>,
    seen: BTreeSet<PathBuf>,
    block: u64,
    manifest_bytes: u64,
    raw_bytes: u64,
    evidence: usize,
    diagnostics: usize,
}

impl<'a> BackupBudget<'a> {
    pub fn new(store: &'a NativeStore, manifest: AnalysisBackupManifestV1) -> Result<Self> {
        let block = rustix::fs::statvfs(&store.root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &store.root })?
            .f_frsize;
        if block == 0 {
            return NativeStateSnafu {
                field: "backup allocation unit",
            }
            .fail();
        }
        let raw_bytes = manifest
            .segments
            .iter()
            .try_fold(0u64, |total, segment| {
                total.checked_add(segment.bytes.checked_next_multiple_of(block)?)
            })
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "backup raw allocation",
                }
                .build()
            })?;
        let diagnostics = manifest
            .segments
            .iter()
            .filter(|segment| segment.file_name.split('.').nth(1) == Some("d"))
            .count();
        let evidence = manifest.segments.len() - diagnostics;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .context(crate::JsonSnafu { path: &store.root })?
            .len() as u64;
        store.storage.check_manifest(manifest_bytes)?;
        Ok(Self {
            store,
            manifest,
            entries: BTreeMap::new(),
            seen: BTreeSet::new(),
            block,
            manifest_bytes,
            raw_bytes,
            evidence,
            diagnostics,
        })
    }

    pub fn check(&mut self, extra: usize) -> Result<()> {
        let mut entries = self.evidence.checked_add(extra).ok_or_else(|| {
            NativeStateSnafu {
                field: "backup entry count",
            }
            .build()
        })?;
        let manifest_bytes = self
            .store
            .storage
            .manifest_max_bytes
            .map_or(self.manifest_bytes, |limit| self.manifest_bytes.min(limit));
        let mut bytes = self
            .raw_bytes
            .checked_add(
                manifest_bytes
                    .checked_next_multiple_of(self.block)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "backup manifest allocation",
                        }
                        .build()
                    })?,
            )
            .and_then(|bytes| bytes.checked_add(self.manifest.reserved_bytes))
            .and_then(|bytes| bytes.checked_add(self.block.checked_mul((extra - 1) as u64)?))
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "backup pending allocation",
                }
                .build()
            })?;
        let mut completed = Vec::new();
        for (path, length) in &self.entries {
            if path.try_exists().context(IoSnafu { path })? {
                completed.push(path.clone());
            } else {
                entries = entries.checked_add(1).ok_or_else(|| {
                    NativeStateSnafu {
                        field: "backup entry count",
                    }
                    .build()
                })?;
                bytes = bytes
                    .checked_add(match length {
                        Some(bytes) => {
                            bytes.checked_next_multiple_of(self.block).ok_or_else(|| {
                                NativeStateSnafu {
                                    field: "backup file allocation",
                                }
                                .build()
                            })?
                        }
                        None => self.block,
                    })
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "backup allocation",
                        }
                        .build()
                    })?;
            }
        }
        for path in completed {
            self.entries.remove(&path);
        }
        let limits = self.store.storage;
        if limits.disk_max_bytes.is_none()
            && limits.policy_reserve_bytes.is_none()
            && limits.write_reserve_bytes.is_none()
            && limits.storage_entries.is_none()
            && limits.diagnostic_entries.is_none()
        {
            return limits.check_copy(crate::StorageUsageV1::free_bytes(&self.store.root)?, bytes);
        }
        let diagnostics = self
            .diagnostics
            .checked_add(self.manifest.reserved_entries)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "backup diagnostic entries",
                }
                .build()
            })?;
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let usage = crate::StorageUsageV1::inspect(
            &self.store.root,
            entries,
            diagnostics,
            Some(&raw),
            self.store.storage,
        )?;
        self.store.storage.check_backup(usage, bytes)
    }

    pub fn admit(&mut self, root: &Path, path: &Path, length: Option<u64>) -> Result<()> {
        if !self.seen.insert(path.to_owned()) {
            return NativeStateSnafu {
                field: "duplicate checkpoint admission",
            }
            .fail();
        }
        self.entries.insert(path.to_owned(), length);
        if let Some(bytes) = length {
            let name = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "checkpoint admission path",
                    }
                    .build()
                })?;
            // Admit the largest encoded CRC field before the file exists.
            let file = AnalysisBackupFileV1 {
                file_name: name.into(),
                bytes,
                crc32c: u32::MAX,
            };
            let encoded = serde_json::to_vec(&file)
                .context(crate::JsonSnafu { path })?
                .len() as u64;
            let prior = self.manifest.database_bytes.to_string().len();
            self.manifest.database_bytes = self
                .manifest
                .database_bytes
                .checked_add(bytes)
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "backup database size",
                    }
                    .build()
                })?;
            self.manifest_bytes = self
                .manifest_bytes
                .checked_add(encoded)
                .and_then(|bytes| {
                    bytes.checked_add(u64::from(!self.manifest.database_files.is_empty()))
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        (self.manifest.database_bytes.to_string().len() - prior) as u64,
                    )
                })
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "backup manifest size",
                    }
                    .build()
                })?;
            self.manifest.database_files.push(file);
        }
        self.check(2)
    }
}
