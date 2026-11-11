use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use snafu::ResultExt as _;

use super::NativeStore;
use crate::{
    AnalysisBackupManifestV1, AnalysisBackupSegmentV1, IoSnafu, NativeStateSnafu,
    NativeStorageSnafu, Result,
};

mod budget;
mod files;
mod restore;
use budget::BackupBudget;

impl NativeStore {
    pub fn checkpoint(&self) -> Result<()> {
        self.check()?;
        self.checkpoint_inputs()?;
        let _writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        self.check()?;
        self.require_capacity(true)?;
        let _maintenance = self.maintenance.write().map_err(|_| {
            NativeStateSnafu {
                field: "maintenance lock",
            }
            .build()
        })?;
        self.seal_raw()?;
        self.database
            .inner()
            .flush_memtables()
            .inspect_err(|_| self.poison())
            .context(NativeStorageSnafu {
                operation: "flush native checkpoint",
            })?;
        self.inputs.collect_journals().inspect_err(|_| {
            if self.database.inner().is_poisoned() {
                self.poison();
            }
        })
    }

    pub fn backup(&self, destination: &Path) -> Result<AnalysisBackupManifestV1> {
        let parent = destination.parent().ok_or_else(|| {
            NativeStateSnafu {
                field: "backup parent",
            }
            .build()
        })?;
        if parent != self.root.join("backups")
            || destination
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| {
                    name.is_empty()
                        || name.len() > 128
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
        {
            return crate::Error::reject_path(
                destination,
                "the backup must have one name in the owned backups directory",
            );
        }
        self.check()?;
        let _writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        self.check()?;
        self.require_capacity(true)?;
        let create_parent = match fs::symlink_metadata(parent) {
            Ok(_) => {
                Self::private_directory(parent)?;
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(source) => return Err(source).context(IoSnafu { path: parent }),
        };
        let _maintenance = self.maintenance.write().map_err(|_| {
            NativeStateSnafu {
                field: "maintenance lock",
            }
            .build()
        })?;
        self.seal_raw()?;
        let view = self.view()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(&self.root, "backup.sealed");
        let raw = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let segments = raw
            .segments
            .iter()
            .map(|(id, segment)| {
                Ok(AnalysisBackupSegmentV1 {
                    segment_id: *id,
                    bytes: segment.end,
                    file_name: segment
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| {
                            NativeStateSnafu {
                                field: "backup segment name",
                            }
                            .build()
                        })?
                        .into(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let reserve = raw.budget.trace_reserve;
        let slots = raw.budget.trace_slots;
        drop(raw);
        let manifest = AnalysisBackupManifestV1 {
            store_uuid: view.store_uuid.to_string(),
            schema_version: view.schema_version,
            recovery_epoch: view.recovery_epoch,
            commit_revision: view.revision,
            database_bytes: 0,
            database_files: Vec::new(),
            segments,
            reserved_bytes: reserve,
            reserved_entries: slots,
        };
        let mut budget = BackupBudget::new(self, manifest)?;
        budget.check(3 + usize::from(create_parent))?;
        if create_parent {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(parent)
                .context(IoSnafu { path: parent })?;
            Self::sync_directory(&self.root)?;
        }
        let staged = tempfile::Builder::new()
            .prefix(".backup-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .context(IoSnafu { path: parent })?;
        let engine = staged.path().join("fjall");
        let mut denied = None;
        let exported = self
            .database
            .checkpoint_with(&engine, |path, bytes| {
                budget.admit(&engine, path, bytes).map_err(|error| {
                    denied = Some(error);
                    std::io::Error::other("checkpoint admission refused")
                })
            })
            .inspect_err(|_| {
                if self.database.inner().is_poisoned() {
                    self.poison();
                }
            });
        if let Some(error) = denied {
            return Err(error);
        }
        exported.context(NativeStorageSnafu {
            operation: "export native checkpoint",
        })?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(&self.root, "backup.exported");
        let database_files = Self::checkpoint_files(&engine, true)?;
        let database_bytes = database_files
            .iter()
            .try_fold(0u64, |bytes, file| bytes.checked_add(file.bytes))
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "checkpoint size",
                }
                .build()
            })?;
        budget
            .manifest
            .database_files
            .sort_unstable_by(|left, right| left.file_name.cmp(&right.file_name));
        if database_files
            .iter()
            .map(|file| (&file.file_name, file.bytes))
            .ne(budget
                .manifest
                .database_files
                .iter()
                .map(|file| (&file.file_name, file.bytes)))
        {
            return NativeStateSnafu {
                field: "checkpoint admission inventory",
            }
            .fail();
        }
        budget.check(2)?;
        let mut manifest = budget.manifest;
        manifest.database_bytes = database_bytes;
        manifest.database_files = database_files;
        let path = staged.path().join("manifest.json");
        let encoded = serde_json::to_vec(&manifest).context(crate::JsonSnafu { path: &path })?;
        self.storage.check_manifest(encoded.len() as u64)?;
        crate::analysis::raw::RawJournal::directory(staged.path())?;
        for segment in &manifest.segments {
            Self::copy_bundle_file(
                &self.root.join("segments").join(&segment.file_name),
                &staged.path().join("segments").join(&segment.file_name),
                segment.bytes,
            )?;
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        output
            .write_all(&encoded)
            .and_then(|()| output.sync_all())
            .context(IoSnafu { path: &path })?;
        Self::validate_bundle(&manifest, staged.path())?;
        Self::sync_directory(&staged.path().join("segments"))?;
        Self::sync_directory(staged.path())?;
        let raw = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let usage = crate::StorageUsageV1::inspect(&self.root, 0, slots, Some(&raw), self.storage)?;
        self.storage.check_append(usage, reserve)?;
        drop(raw);
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(&self.root, "backup.synced");
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staged.path(),
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: destination })?;
        Self::sync_directory(parent)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(&self.root, "backup.published");
        Ok(manifest)
    }
}

impl NativeStore {
    fn seal_raw(&self) -> Result<()> {
        let mut raw = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        if let Err(error) = raw.seal_all() {
            self.poison();
            return Err(error);
        }
        let sealed = raw.index.clone();
        drop(raw);
        let mut published = self.published.write().map_err(|_| {
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })?;
        let mut view = (**published).clone();
        view.raw = sealed;
        *published = std::sync::Arc::new(view);
        Ok(())
    }
}
