use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{IoSnafu, Result, StorageCapacitySnafu};

const WRITE_RESERVE: u64 = 256 * 1024 * 1024;
const MAX_STORAGE_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageLimitsV1 {
    pub disk_max_bytes: u64,
    pub policy_reserve_bytes: u64,
    pub logical_max_bytes: u64,
    pub tenant_max_bytes: u64,
    pub witness_max_bytes: u64,
}

impl Default for StorageLimitsV1 {
    fn default() -> Self {
        Self {
            disk_max_bytes: 8 * 1024 * 1024 * 1024,
            policy_reserve_bytes: 256 * 1024 * 1024,
            logical_max_bytes: 8 * 1024 * 1024 * 1024,
            tenant_max_bytes: 2 * 1024 * 1024 * 1024,
            witness_max_bytes: 512 * 1024 * 1024,
        }
    }
}

impl StorageLimitsV1 {
    pub fn valid(&self) -> bool {
        self.disk_max_bytes >= 4 * WRITE_RESERVE
            && self.policy_reserve_bytes >= WRITE_RESERVE
            && self.tenant_max_bytes > 0
            && self.tenant_max_bytes <= self.logical_max_bytes
            && self.witness_max_bytes > 0
            && self
                .policy_reserve_bytes
                .checked_add(self.disk_max_bytes)
                .is_some()
    }

    pub(super) fn check(&self, usage: StorageUsageV1, maintenance: bool) -> Result<()> {
        let reserve = self.maintenance_bytes();
        let reserve = if maintenance {
            reserve
        } else {
            reserve + self.disk_max_bytes / 4
        };
        if usage.available_bytes < reserve {
            return StorageCapacitySnafu {
                resource: "filesystem reserve",
            }
            .fail();
        }
        if !maintenance && usage.file_bytes > self.disk_max_bytes - WRITE_RESERVE {
            return StorageCapacitySnafu {
                resource: "data files",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn maintenance_bytes(&self) -> u64 {
        self.policy_reserve_bytes + WRITE_RESERVE
    }

    pub(super) fn check_copy(&self, available: u64, bytes: u64) -> Result<()> {
        let required = bytes
            .checked_add(bytes / 4)
            .and_then(|size| size.checked_add(self.policy_reserve_bytes))
            .and_then(|size| size.checked_add(WRITE_RESERVE));
        if required.is_none_or(|size| available < size) {
            return StorageCapacitySnafu {
                resource: "copy reserve",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn check_backup(&self, usage: StorageUsageV1, bytes: u64) -> Result<()> {
        self.check_copy(usage.available_bytes, bytes)?;
        let reserve = bytes
            .checked_add(bytes / 4)
            .and_then(|size| size.checked_add(4096));
        let projected = reserve.and_then(|reserve| {
            Some(StorageUsageV1 {
                file_bytes: usage.file_bytes.checked_add(reserve)?,
                available_bytes: usage.available_bytes.checked_sub(reserve)?,
                ..usage
            })
        });
        let projected = projected.ok_or_else(|| {
            StorageCapacitySnafu {
                resource: "backup files",
            }
            .build()
        })?;
        self.check(projected, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, RetentionLimitsV1,
        ValidatedEvidenceBatchV1,
    };

    #[test]
    fn analysis_store_copy_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::default();
        for bytes in [0, 1, 3, 4, 1024 * 1024] {
            let required = bytes + bytes / 4 + limits.maintenance_bytes();
            limits.check_copy(required, bytes)?;
            assert!(matches!(
                limits.check_copy(required - 1, bytes),
                Err(crate::Error::StorageCapacity {
                    resource: "copy reserve",
                    ..
                })
            ));
        }
        assert!(limits.check_copy(u64::MAX, u64::MAX).is_err());
        assert!(limits.check_copy(u64::MAX, u64::MAX / 5 * 4).is_err());
        let bytes = 1024 * 1024;
        let reserve = bytes + bytes / 4 + 4096;
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes - WRITE_RESERVE - reserve,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes() + limits.disk_max_bytes / 4 + reserve,
        };
        limits.check_backup(usage, bytes)?;
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    file_bytes: usage.file_bytes + 1,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    available_bytes: usage.available_bytes - 1,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits
            .check_backup(
                StorageUsageV1 {
                    file_bytes: u64::MAX,
                    available_bytes: u64::MAX,
                    ..usage
                },
                bytes
            )
            .is_err());
        assert!(limits.check_backup(usage, u64::MAX).is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_capacity_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let limits = StorageLimitsV1::default();
        assert!(limits.valid());
        assert!(!StorageLimitsV1 {
            disk_max_bytes: u64::MAX,
            ..limits
        }
        .valid());
        let usage = StorageUsageV1 {
            file_bytes: limits.disk_max_bytes - WRITE_RESERVE,
            allocated_bytes: 0,
            available_bytes: limits.maintenance_bytes() + limits.disk_max_bytes / 4,
        };
        limits.check(usage, false)?;
        assert!(limits
            .check(
                StorageUsageV1 {
                    file_bytes: usage.file_bytes + 1,
                    ..usage
                },
                false
            )
            .is_err());
        assert!(limits
            .check(
                StorageUsageV1 {
                    available_bytes: usage.available_bytes - 1,
                    ..usage
                },
                false
            )
            .is_err());
        limits.check(
            StorageUsageV1 {
                file_bytes: u64::MAX,
                available_bytes: limits.maintenance_bytes(),
                ..usage
            },
            true,
        )?;
        assert!(limits
            .check(
                StorageUsageV1 {
                    available_bytes: limits.maintenance_bytes() - 1,
                    ..usage
                },
                true
            )
            .is_err());

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(&root, RetentionLimitsV1::default(), limits)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let first = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        };
        store.accept_validated_batch(identity.clone(), first.clone())?;
        let before = store.meta()?;
        let padding = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota-test"))?;
        padding.set_len(limits.disk_max_bytes)?;
        let usage = store.storage_usage()?;
        assert!(usage.file_bytes >= limits.disk_max_bytes);
        assert!(usage.allocated_bytes < usage.file_bytes);
        let mut next = first.clone();
        next.first_cursor = 2;
        next.last_cursor = 2;
        assert!(matches!(
            store.accept_validated_batch(identity.clone(), next.clone()),
            Err(crate::Error::StorageCapacity { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store.accept_validated_batch(identity.clone(), first)?,
            EvidenceStoreOutcomeV1::Accepted
        );
        store.checkpoint()?;
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
        assert!(store
            .accept_validated_batch(identity.clone(), next.clone())
            .is_err());
        padding.set_len(0)?;
        store.accept_validated_batch(identity, next)?;
        assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
        Ok(())
    }

    #[test]
    fn analysis_store_native_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let reader_guard = store.reader()?;
        let reader = reader_guard.get()?;
        let settings: (String, String, String, u64, u64, String) = reader.query_row(
            "SELECT current_setting('memory_limit'), current_setting('wal_autocheckpoint'), current_setting('max_temp_directory_size'), current_setting('threads'), current_setting('vacuum_rebuild_indexes'), current_setting('allocator_bulk_deallocation_flush_threshold')",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )?;
        assert_eq!(
            settings,
            (
                "128.0 MiB".into(),
                "64.0 MiB".into(),
                "128.0 MiB".into(),
                2,
                u64::MAX,
                "0 bytes".into(),
            )
        );
        Ok(())
    }

    #[test]
    #[ignore = "release-only isolated process RSS qualification on Linux"]
    fn analysis_store_thread_memory() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::{sync::mpsc, thread};

        if cfg!(debug_assertions) {
            return Err("run this test alone with --release --ignored --exact".into());
        }
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let memory =
            |store: &AnalysisStore| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let status = fs::read_to_string("/proc/self/status")?;
                let peak: u64 = status
                    .lines()
                    .find(|line| line.starts_with("VmHWM:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .ok_or("the process memory peak is absent")?
                    .parse()?;
                if peak > 256 * 1024 {
                    let reader = store.reader()?;
                    let mut query = reader.get()?.prepare(
                    "SELECT tag, memory_usage_bytes FROM duckdb_memory() WHERE memory_usage_bytes > 0 ORDER BY tag",
                )?;
                    let native = query
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
                        })?
                        .collect::<duckdb::Result<Vec<_>>>()?;
                    let cursor = store
                        .source_receipt(&identity)?
                        .ok_or("receipt absent")?
                        .contiguous_cursor;
                    return Err(format!("process peak {peak} KiB exceeds 256 MiB at cursor {cursor}; native bytes: {native:?}").into());
                }
                Ok(())
            };
        let limit_cursor = thread::scope(
            |scope| -> std::result::Result<u64, Box<dyn std::error::Error>> {
                let workers: Vec<_> = (0..4)
                    .map(|_| {
                        let (send, requests) = mpsc::sync_channel::<ValidatedEvidenceBatchV1>(1);
                        let (reply, receive) = mpsc::sync_channel(1);
                        let store = &store;
                        let identity = &identity;
                        scope.spawn(move || {
                            for batch in requests {
                                if reply
                                    .send(store.accept_validated_batch(identity.clone(), batch))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        (send, receive)
                    })
                    .collect();
                for group in 0..8192_u64 {
                    let mut frames = vec![0_u8; 128 * 1024];
                    for index in 0..1024 {
                        let cursor = group * 1024 + index as u64 + 1;
                        frames[index * 128..index * 128 + 8].copy_from_slice(&cursor.to_be_bytes());
                    }
                    let batch = ValidatedEvidenceBatchV1 {
                        cpu_id: 0,
                        first_cursor: group * 1024 + 1,
                        last_cursor: (group + 1) * 1024,
                        intake_utc_ns: 1_800_000_000_000_000_000,
                        framed_records: frames.into(),
                        frame_ends: (1..=1024).map(|index| index * 128).collect(),
                    };
                    let (send, receive) = &workers[group as usize % workers.len()];
                    send.send(batch)?;
                    match receive.recv()? {
                        Ok(outcome) => assert_eq!(outcome, EvidenceStoreOutcomeV1::Accepted),
                        Err(crate::Error::StorageCapacity {
                            resource: "tenant logical bytes",
                            ..
                        }) => {
                            memory(&store)?;
                            return Ok(group * 1024);
                        }
                        Err(error) => return Err(error.into()),
                    }
                    assert_eq!(
                        store
                            .source_receipt(&identity)?
                            .ok_or("receipt absent")?
                            .contiguous_cursor,
                        (group + 1) * 1024
                    );
                    memory(&store)?;
                }
                Err("the default tenant quota was not reached".into())
            },
        )?;
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, limit_cursor);
        store.checkpoint()?;
        memory(&store)?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.source_receipt(&identity)?, Some(receipt));
        let last = store.read_page(&identity, limit_cursor)?;
        let mut expected = vec![0_u8; 128];
        expected[..8].copy_from_slice(&limit_cursor.to_be_bytes());
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.records[0].framed_record, expected);
        memory(&store)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StorageUsageV1 {
    pub file_bytes: u64,
    pub allocated_bytes: u64,
    pub available_bytes: u64,
}

impl StorageUsageV1 {
    pub(super) fn free_bytes(root: &Path) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        volume.f_bavail.checked_mul(volume.f_frsize).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: root,
                reason: "the available storage size is invalid",
            }
            .build()
        })
    }
}

impl AnalysisStore {
    pub fn storage_usage(&self) -> Result<StorageUsageV1> {
        self.storage_with_entries(0)
    }

    pub(super) fn storage_with_entries(&self, mut entries: usize) -> Result<StorageUsageV1> {
        let mut usage = StorageUsageV1 {
            available_bytes: StorageUsageV1::free_bytes(&self.root)?,
            ..Default::default()
        };
        let mut pending = vec![self.root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let entry = entry.context(IoSnafu { path: &directory })?;
                entries += 1;
                if entries > MAX_STORAGE_ENTRIES {
                    return self.reject("the data directory exceeds its entry bound");
                }
                let path = entry.path();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                if metadata.is_dir() {
                    pending.push(path);
                } else if !metadata.is_file() {
                    return self.reject("the data directory contains a non-file entry");
                }
                let allocated = metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| self.state_error("allocated data bytes overflow"))?;
                usage.allocated_bytes = usage
                    .allocated_bytes
                    .checked_add(allocated)
                    .ok_or_else(|| self.state_error("allocated data bytes overflow"))?;
                usage.file_bytes = usage
                    .file_bytes
                    .checked_add(metadata.len().max(allocated))
                    .ok_or_else(|| self.state_error("data file bytes overflow"))?;
            }
        }
        Ok(usage)
    }

    pub(super) fn require_capacity(&self, maintenance: bool) -> Result<()> {
        self.storage.check(self.storage_usage()?, maintenance)
    }
}
