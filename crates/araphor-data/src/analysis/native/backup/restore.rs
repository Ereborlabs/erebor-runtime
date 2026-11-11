use std::{
    fs::{self, OpenOptions},
    io::Read as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::Path,
};

use snafu::ResultExt as _;

use super::NativeStore;
use crate::{AnalysisBackupManifestV1, IoSnafu, NativeStateSnafu, NativeStorageSnafu, Result};

impl NativeStore {
    pub fn restore(backup: &Path, root: &Path) -> Result<Self> {
        if !backup.is_absolute() || !root.is_absolute() {
            return crate::Error::reject_path(root, "the restore paths are invalid");
        }
        Self::private_directory(backup)?;
        let path = backup.join("manifest.json");
        let file = Self::bundle_file(&path)?;
        let length = file.metadata().context(IoSnafu { path: &path })?.len();
        let mut bytes = Vec::new();
        file.take(length.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "backup manifest size",
            }
            .build()
        })?)
        .read_to_end(&mut bytes)
        .context(IoSnafu { path: &path })?;
        if bytes.len() as u64 != length {
            return crate::Error::reject_path(backup, "the backup manifest changed size");
        }
        let manifest: AnalysisBackupManifestV1 =
            serde_json::from_slice(&bytes).context(crate::JsonSnafu { path: &path })?;
        Self::validate_bundle(&manifest, backup)?;
        let directories = Self::checkpoint_dirs(&manifest.database_files)?;
        let lease = crate::analysis::read::AnalysisLease::acquire(root)?;
        for entry in fs::read_dir(root).context(IoSnafu { path: root })? {
            if entry.context(IoSnafu { path: root })?.file_name() != "analysis.lock" {
                return crate::Error::reject_path(root, "the restore target is not empty");
            }
        }
        let pending = root.join("restore.pending");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&pending)
            .and_then(|file| file.sync_all())
            .context(IoSnafu { path: &pending })?;
        Self::sync_directory(root)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(root, "restore.pending");
        let engine = root.join("fjall");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&engine)
            .context(IoSnafu { path: &engine })?;
        for directory in &directories {
            let path = engine.join(directory);
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .context(IoSnafu { path: &path })?;
        }
        for file in &manifest.database_files {
            Self::copy_bundle_file(
                &backup.join("fjall").join(&file.file_name),
                &engine.join(&file.file_name),
                file.bytes,
            )?;
        }
        if Self::checkpoint_files(&engine, false)? != manifest.database_files {
            return crate::Error::reject_path(
                root,
                "the copied checkpoint differs from its manifest",
            );
        }
        crate::analysis::raw::RawJournal::directory(root)?;
        for segment in &manifest.segments {
            Self::copy_bundle_file(
                &backup.join("segments").join(&segment.file_name),
                &root.join("segments").join(&segment.file_name),
                segment.bytes,
            )?;
        }
        for directory in directories.iter().rev() {
            Self::sync_directory(&engine.join(directory))?;
        }
        Self::sync_directory(&engine)?;
        Self::sync_directory(&root.join("segments"))?;
        Self::sync_directory(root)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(root, "restore.copied");
        let store = Self::open_leased(root, Default::default(), lease, true)?;
        let view = store.view()?;
        if view.store_uuid.to_string() != manifest.store_uuid
            || view.schema_version != manifest.schema_version
            || view.recovery_epoch != manifest.recovery_epoch
            || view.revision != manifest.commit_revision
        {
            return crate::Error::reject_path(
                root,
                "the restored identity differs from its manifest",
            );
        }
        let raw = store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "restored raw owner",
            }
            .build()
        })?;
        if raw.budget.trace_reserve != manifest.reserved_bytes
            || raw.budget.trace_slots != manifest.reserved_entries
            || raw.segments.len() != manifest.segments.len()
            || raw
                .segments
                .iter()
                .zip(&manifest.segments)
                .any(|((id, raw), saved)| *id != saved.segment_id || raw.end != saved.bytes)
        {
            return crate::Error::reject_path(
                root,
                "the restored catalogue differs from its manifest",
            );
        }
        drop(raw);
        let epoch = manifest.recovery_epoch.checked_add(1).ok_or_else(|| {
            NativeStateSnafu {
                field: "recovery epoch exhausted",
            }
            .build()
        })?;
        let mut tx = store.branch.write_tx().context(NativeStorageSnafu {
            operation: "begin restored epoch",
        })?;
        tx.insert(super::super::RECOVERY, epoch.to_be_bytes());
        let receipt = tx
            .commit_stamped([Self::cut(view.metadata_revision)])
            .context(NativeStorageSnafu {
                operation: "commit restored epoch",
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "restored epoch commit",
                }
                .build()
            })?;
        let snapshot = store
            .branch
            .read_at(receipt.revision)
            .context(NativeStorageSnafu {
                operation: "capture restored epoch",
            })?;
        let mut restored = Self::decode_view(snapshot)?;
        restored.revision = view.revision;
        restored.raw = view.raw.clone();
        restored.graphs = view.graphs.clone();
        restored.contexts = view.contexts.clone();
        *store.published.write().map_err(|_| {
            NativeStateSnafu {
                field: "restored publication lock",
            }
            .build()
        })? = std::sync::Arc::new(restored);
        store.recover_managed_startup()?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(root, "restore.epoch");
        fs::remove_file(&pending).context(IoSnafu { path: &pending })?;
        Self::sync_directory(root)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        Self::crash_path(root, "restore.complete");
        Ok(store)
    }
}
