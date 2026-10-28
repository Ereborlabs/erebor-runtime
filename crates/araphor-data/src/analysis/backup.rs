use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::Ordering;

use duckdb::{params, AccessMode};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use uuid::Uuid;

use super::{
    capacity::StorageLimitsV1, AnalysisStore, AnalysisStoreMetaV1, ANALYSIS_SCHEMA_VERSION,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, IoSnafu, JsonSnafu, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupManifestV1 {
    pub store_uuid: String,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
    pub database_bytes: u64,
    pub segments: Vec<AnalysisBackupSegmentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupSegmentV1 {
    pub segment_id: u64,
    pub file_name: String,
    pub bytes: u64,
}

impl AnalysisBackupManifestV1 {
    fn copy_bytes(&self, root: &Path, manifest_bytes: u64) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        [self.database_bytes, manifest_bytes]
            .into_iter()
            .chain(self.segments.iter().map(|segment| segment.bytes))
            .try_fold(0_u64, |total, bytes| {
                total.checked_add(bytes.checked_next_multiple_of(volume.f_frsize)?)
            })
            .ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the backup allocation size is invalid",
                }
                .build()
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisRecoveryStatusV1 {
    Complete,
    Partial { first_cursor: u64, last_cursor: u64 },
}

impl AnalysisStore {
    pub fn record_recovery_floor(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        node_retained_floor: u64,
    ) -> Result<AnalysisRecoveryStatusV1> {
        if !identity.valid() {
            return self.reject("the recovery source identity is invalid");
        }
        let key = identity.key();
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin source recovery",
            })?;
        let stored = Self::read_receipt_from(&transaction, &self.root, identity, &key)?
            .map_or(0, |receipt| receipt.contiguous_cursor);
        if node_retained_floor <= stored {
            return Ok(AnalysisRecoveryStatusV1::Complete);
        }
        let first = stored
            .checked_add(1)
            .ok_or_else(|| self.state_error("the recovery source cursor is exhausted"))?;
        let prior: Option<u64> = transaction
            .query_row(
                "SELECT MAX(last_cursor) FROM recovery_gaps WHERE stream_key = ? AND tenant_id = ?",
                params![key.as_slice(), identity.tenant_id.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read known recovery gaps",
            })?;
        if prior.is_none_or(|last| last < node_retained_floor) {
            let next = prior
                .and_then(|last| last.checked_add(1))
                .map_or(first, |cursor| cursor.max(first));
            let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
                .commit_revision
                .checked_add(1)
                .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
            transaction
                .execute(
                    "INSERT INTO recovery_gaps VALUES (?, ?, ?, ?, ?)",
                    params![
                        key.as_slice(),
                        identity.tenant_id.as_slice(),
                        next,
                        node_retained_floor,
                        revision,
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "record unrecoverable source range",
                })?;
            self.check_revision_limits(&transaction, identity.tenant_id)?;
            Self::record_revision(&transaction, revision, &["recovery_gaps"])?;
            #[cfg(test)]
            self.crash_at("recovery.before");
            self.commit_metadata(transaction, "commit source recovery")?;
            #[cfg(test)]
            self.crash_at("recovery.after");
            self.revision.send_replace(revision);
        }
        Ok(AnalysisRecoveryStatusV1::Partial {
            first_cursor: first,
            last_cursor: node_retained_floor,
        })
    }

    pub fn checkpoint(&self) -> Result<()> {
        let writer = self.maintenance_writer()?;
        let _maintenance = self
            .maintenance
            .write()
            .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?;
        writer
            .get()?
            .execute_batch("CHECKPOINT")
            .context(AnalysisDatabaseSnafu {
                operation: "checkpoint analysis database",
            })
    }

    pub fn backup(&self, destination: &Path) -> Result<AnalysisBackupManifestV1> {
        let parent = destination
            .parent()
            .ok_or_else(|| self.state_error("the backup path has no parent"))?;
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
            return self.reject(
                "the backup must be one named directory under the owned backups directory",
            );
        }
        let mut writer = self.maintenance_writer()?;
        match fs::symlink_metadata(parent) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.storage_with_entries(1)?;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(parent)
                    .context(IoSnafu { path: parent })?;
                File::open(&self.root)
                    .context(IoSnafu { path: &self.root })?
                    .sync_all()
                    .context(IoSnafu { path: &self.root })?;
            }
            Err(source) => return Err(source).context(IoSnafu { path: parent }),
        }
        let parent_meta = fs::symlink_metadata(parent).context(IoSnafu { path: parent })?;
        if !parent_meta.is_dir() || parent_meta.permissions().mode() & 0o077 != 0 {
            return self.reject("the backup directory is not private");
        }
        let _maintenance = self
            .maintenance
            .write()
            .map_err(|_| self.state_error("the analysis maintenance lock is poisoned"))?;
        let mut readers = [
            self.readers[0]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
            self.readers[1]
                .lock()
                .map_err(|_| self.state_error("the analysis reader lock is poisoned"))?,
        ];
        self.write_ready.store(false, Ordering::Release);
        {
            let mut raw = self
                .raw
                .lock()
                .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
            raw.seal_all()?;
            raw.project_paths(writer.get()?)?;
            raw.refresh_budget(writer.get()?, self.retention)?;
        }
        let files = Self::backup_segments(writer.get()?)?;
        for (_, bytes, name) in &files {
            let file =
                super::SegmentFile::open(&super::raw::RawJournal::file_path(&self.root, name)?)?;
            if file.length()? != *bytes {
                return self.reject("the backup segment size differs from its committed end");
            }
            file.sync()?;
        }
        writer
            .get()?
            .execute_batch("CHECKPOINT")
            .context(AnalysisDatabaseSnafu {
                operation: "checkpoint before backup",
            })?;
        let source = self.root.join("analysis.duckdb");
        let meta = Self::read_meta_from(writer.get()?, &source)?;
        #[cfg(test)]
        self.crash_at("backup.sealed");
        for reader in &mut readers {
            drop(reader.take());
        }
        drop(writer.connection.take());
        #[cfg(test)]
        self.crash_at("backup.closed");
        let result = self.copy_backup(destination, &meta, &files);
        let connection = self.reopen_backup(&meta)?;
        let first = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "reopen first trusted reader",
        })?;
        let second = connection.try_clone().context(AnalysisDatabaseSnafu {
            operation: "reopen second trusted reader",
        })?;
        *readers[0] = Some(first);
        *readers[1] = Some(second);
        *writer.connection = Some(connection);
        self.write_ready.store(true, Ordering::Release);
        #[cfg(test)]
        self.crash_at("backup.ready");
        result
    }

    fn reopen_backup(&self, meta: &AnalysisStoreMetaV1) -> Result<duckdb::Connection> {
        let source = self.root.join("analysis.duckdb");
        let saved = fs::symlink_metadata(&source).context(IoSnafu { path: &source })?;
        if !saved.is_file() || saved.permissions().mode() & 0o077 != 0 {
            return self.reject("the analysis database file is not private");
        }
        let mut connection = Self::open_native(&source, self.storage, AccessMode::Automatic)?;
        if Self::read_meta_from(&connection, &source)? != *meta {
            return self.reject("the analysis identity changed during backup");
        }
        Self::validate_tables(&connection)?;
        Self::validate_state(&connection, &self.root)?;
        Self::recover_segments(&mut connection, &self.root, self.retention)?;
        Ok(connection)
    }

    fn backup_segments(writer: &duckdb::Connection) -> Result<Vec<(u64, u64, String)>> {
        let pending: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM segments WHERE state <> 'Live')",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check complete backup catalog",
            })?;
        if pending {
            return Self::reject_path(
                Path::new("<backup-catalog>"),
                "the backup catalog has unfinished segment work",
            );
        }
        let mut statement = writer
            .prepare(
                "SELECT segment_id, committed_end, file_name FROM segments ORDER BY segment_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare backup segment list",
            })?;
        let files = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context(AnalysisDatabaseSnafu {
                operation: "read backup segment list",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode backup segment list",
            })?;
        Ok(files)
    }

    fn copy_backup(
        &self,
        destination: &Path,
        meta: &AnalysisStoreMetaV1,
        files: &[(u64, u64, String)],
    ) -> Result<AnalysisBackupManifestV1> {
        let parent = destination
            .parent()
            .ok_or_else(|| self.state_error("the backup path has no parent"))?;
        let source = self.root.join("analysis.duckdb");
        let wal = self.root.join("analysis.duckdb.wal");
        match fs::symlink_metadata(&wal) {
            Ok(_) => return self.reject("the closed database still has a native WAL"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source).context(IoSnafu { path: &wal }),
        }
        let source_bytes = fs::metadata(&source)
            .context(IoSnafu { path: &source })?
            .len();
        let mut manifest = AnalysisBackupManifestV1 {
            store_uuid: meta.store_uuid.to_string(),
            schema_version: meta.schema_version,
            recovery_epoch: meta.recovery_epoch,
            commit_revision: meta.commit_revision,
            database_bytes: source_bytes,
            segments: Vec::with_capacity(files.len()),
        };
        for (segment_id, bytes, name) in files {
            manifest.segments.push(AnalysisBackupSegmentV1 {
                segment_id: *segment_id,
                file_name: name.clone(),
                bytes: *bytes,
            });
        }
        let manifest_path = destination.join("manifest.json");
        let bytes = serde_json::to_vec(&manifest).context(JsonSnafu {
            path: &manifest_path,
        })?;
        self.storage.check_manifest(bytes.len() as u64)?;
        let (trace_slots, trace_reserve) = {
            let raw = self
                .raw
                .lock()
                .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
            (raw.budget.trace_slots, raw.budget.trace_reserve)
        };
        let diagnostics = files
            .iter()
            .filter(|(_, _, name)| name.split('.').nth(1) == Some("d"))
            .count();
        let copy_bytes = manifest
            .copy_bytes(&self.root, bytes.len() as u64)?
            .checked_add(trace_reserve)
            .ok_or_else(|| self.state_error("the backup reservation size is invalid"))?;
        let entries = files
            .len()
            .checked_sub(diagnostics)
            .and_then(|entries| entries.checked_add(2))
            .ok_or_else(|| self.state_error("the backup entry count overflows"))?;
        let diagnostics = diagnostics
            .checked_add(trace_slots)
            .ok_or_else(|| self.state_error("the diagnostic slot reserve overflows"))?;
        self.storage_with_reserve(
            entries
                .checked_add(2)
                .ok_or_else(|| self.state_error("the backup entry count overflows"))?,
            diagnostics,
        )?;
        let staging = tempfile::Builder::new()
            .prefix(".backup-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .context(IoSnafu { path: parent })?;
        let staged = staging.path();
        Self::segment_directory(staged)?;
        self.storage
            .check_backup(self.storage_with_reserve(entries, diagnostics)?, copy_bytes)?;
        Self::copy_bundle_file(&source, &staged.join("analysis.duckdb"), source_bytes)?;
        for segment in &manifest.segments {
            Self::copy_bundle_file(
                &super::raw::RawJournal::file_path(&self.root, &segment.file_name)?,
                &super::raw::RawJournal::file_path(staged, &segment.file_name)?,
                segment.bytes,
            )?;
        }
        #[cfg(test)]
        self.crash_at("backup.copied");
        Self::validate_bundle(&manifest, staged, self.storage)?;
        let manifest_path = staged.join("manifest.json");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest_path)
            .context(IoSnafu {
                path: &manifest_path,
            })?;
        output.write_all(&bytes).context(IoSnafu {
            path: &manifest_path,
        })?;
        output.sync_all().context(IoSnafu {
            path: &manifest_path,
        })?;
        for directory in [staged.join("segments"), staged.to_owned()] {
            File::open(&directory)
                .context(IoSnafu { path: &directory })?
                .sync_all()
                .context(IoSnafu { path: &directory })?;
        }
        self.storage
            .check_append(self.storage_with_reserve(0, trace_slots)?, trace_reserve)?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staged,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: destination })?;
        File::open(parent)
            .context(IoSnafu { path: parent })?
            .sync_all()
            .context(IoSnafu { path: parent })?;
        Ok(manifest)
    }

    fn copy_bundle_file(source: &Path, target: &Path, bytes: u64) -> Result<()> {
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(source)
            .context(IoSnafu { path: source })?;
        let metadata = input.metadata().context(IoSnafu { path: source })?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != bytes
        {
            return Self::reject_path(
                source,
                "the backup input is not a private file of the declared size",
            );
        }
        let bound = bytes.checked_add(1).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path: source,
                reason: "the backup file size is invalid",
            }
            .build()
        })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)
            .context(IoSnafu { path: target })?;
        let copied =
            std::io::copy(&mut input.take(bound), &mut output).context(IoSnafu { path: target })?;
        if copied != bytes {
            return Self::reject_path(target, "the backup input changed size during copy");
        }
        output.sync_all().context(IoSnafu { path: target })?;
        Ok(())
    }

    fn validate_bundle(
        manifest: &AnalysisBackupManifestV1,
        root: &Path,
        storage: StorageLimitsV1,
    ) -> Result<(u64, usize)> {
        if manifest.schema_version != ANALYSIS_SCHEMA_VERSION as u32
            || Uuid::parse_str(&manifest.store_uuid).is_err()
            || manifest.database_bytes == 0
            || manifest
                .segments
                .windows(2)
                .any(|pair| pair[0].segment_id >= pair[1].segment_id)
            || manifest.segments.iter().any(|segment| {
                segment.segment_id == 0
                    || segment.bytes < 70
                    || !segment.file_name.ends_with(".seg")
            })
        {
            return Self::reject_path(root, "the backup manifest identity or bounds are invalid");
        }
        let directory = root.join("segments");
        for path in [root, directory.as_path()] {
            let metadata = fs::symlink_metadata(path).context(IoSnafu { path })?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Self::reject_path(path, "the backup directory is not private");
            }
        }
        let database = root.join("analysis.duckdb");
        let metadata = fs::symlink_metadata(&database).context(IoSnafu { path: &database })?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != manifest.database_bytes
        {
            return Self::reject_path(root, "the backup database differs from its manifest");
        }
        let mut count = 0;
        for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
            let entry = entry.context(IoSnafu { path: &directory })?;
            count += 1;
            if count > manifest.segments.len() {
                return Self::reject_path(root, "the backup contains an unlisted segment");
            }
            let name = entry.file_name();
            let segment_id = name
                .to_str()
                .and_then(|name| name.split('.').next())
                .filter(|stem| stem.len() == 16)
                .and_then(|stem| u64::from_str_radix(stem, 16).ok())
                .ok_or_else(|| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the backup segment name is invalid",
                    }
                    .build()
                })?;
            let index = manifest
                .segments
                .binary_search_by_key(&segment_id, |segment| segment.segment_id)
                .map_err(|_| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the backup segment is unlisted",
                    }
                    .build()
                })?;
            let segment = &manifest.segments[index];
            let path = super::raw::RawJournal::file_path(root, &segment.file_name)?;
            if path != entry.path() || super::SegmentFile::reader(&path)?.length()? != segment.bytes
            {
                return Self::reject_path(root, "the backup segment differs from its manifest");
            }
        }
        if count != manifest.segments.len() {
            return Self::reject_path(root, "the backup is missing a listed segment");
        }
        let writer = Self::open_native(&database, storage, AccessMode::ReadOnly)?;
        let meta = Self::read_meta_from(&writer, &database)?;
        if meta.store_uuid.to_string() != manifest.store_uuid
            || meta.schema_version != manifest.schema_version
            || meta.recovery_epoch != manifest.recovery_epoch
            || meta.commit_revision != manifest.commit_revision
        {
            return Self::reject_path(
                root,
                "the backup database identity differs from its manifest",
            );
        }
        Self::validate_tables(&writer)?;
        Self::validate_state(&writer, root)?;
        let files = Self::backup_segments(&writer)?;
        if files
            .iter()
            .map(|(id, bytes, name)| (*id, *bytes, name.as_str()))
            .ne(manifest.segments.iter().map(|segment| {
                (
                    segment.segment_id,
                    segment.bytes,
                    segment.file_name.as_str(),
                )
            }))
        {
            return Self::reject_path(root, "the backup catalog differs from its segment manifest");
        }
        let unsealed: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM segments WHERE NOT sealed)",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate sealed backup catalog",
            })?;
        if unsealed {
            return Self::reject_path(root, "the backup catalog contains an unsealed segment");
        }
        let committed = files.iter().map(|(id, bytes, _)| (*id, *bytes)).collect();
        let mut raw = super::raw::RawJournal::read_sealed(root, &committed)?;
        if raw.revision > meta.commit_revision {
            return Self::reject_path(root, "the backup contains an unprojected raw commit");
        }
        raw.restore_receipts(&writer)?;
        raw.validate_catalog(&writer)?;
        Self::terminal_reserve(&writer)
    }

    pub fn restore(backup: &Path, root: &Path) -> Result<Self> {
        Self::restore_with_limits(backup, root, StorageLimitsV1::default())
    }

    pub fn restore_with_limits(
        backup: &Path,
        root: &Path,
        storage: StorageLimitsV1,
    ) -> Result<Self> {
        if !storage.valid() {
            return Self::reject_path(root, "the storage limits are invalid");
        }
        if !backup.is_absolute() || !root.is_absolute() {
            return Self::reject_path(root, "backup and restore paths must be absolute");
        }
        let manifest_path = backup.join("manifest.json");
        let backup_meta = fs::symlink_metadata(backup).context(IoSnafu { path: backup })?;
        let manifest_meta = fs::symlink_metadata(&manifest_path).context(IoSnafu {
            path: &manifest_path,
        })?;
        if !backup_meta.is_dir()
            || !manifest_meta.is_file()
            || backup_meta.permissions().mode() & 0o077 != 0
            || manifest_meta.permissions().mode() & 0o077 != 0
        {
            return Self::reject_path(root, "the backup files are unsafe or exceed their bounds");
        }
        storage.check_manifest(manifest_meta.len())?;
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&manifest_path)
            .context(IoSnafu {
                path: &manifest_path,
            })?
            .take(manifest_meta.len().checked_add(1).ok_or_else(|| {
                crate::StorageCapacitySnafu {
                    resource: "backup manifest bytes",
                }
                .build()
            })?)
            .read_to_end(&mut bytes)
            .context(IoSnafu {
                path: &manifest_path,
            })?;
        if bytes.len() as u64 != manifest_meta.len() {
            return Self::reject_path(backup, "the backup manifest changed size during read");
        }
        storage.check_manifest(bytes.len() as u64)?;
        let manifest: AnalysisBackupManifestV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu {
                path: &manifest_path,
            })?;
        let (trace_reserve, trace_slots) = Self::validate_bundle(&manifest, backup, storage)?;
        for (index, entry) in fs::read_dir(backup)
            .context(IoSnafu { path: backup })?
            .enumerate()
        {
            let name = entry.context(IoSnafu { path: backup })?.file_name();
            if index >= 3
                || !matches!(
                    name.to_str(),
                    Some("analysis.duckdb" | "segments" | "manifest.json")
                )
            {
                return Self::reject_path(backup, "the backup contains an unlisted entry");
            }
        }
        let diagnostics = manifest
            .segments
            .iter()
            .filter(|segment| segment.file_name.split('.').nth(1) == Some("d"))
            .count();
        storage.check_entries(
            manifest
                .segments
                .len()
                .checked_sub(diagnostics)
                .and_then(|entries| entries.checked_add(5))
                .ok_or_else(|| {
                    crate::StorageCapacitySnafu {
                        resource: "storage entries",
                    }
                    .build()
                })?,
            diagnostics.checked_add(trace_slots).ok_or_else(|| {
                crate::StorageCapacitySnafu {
                    resource: "diagnostic storage entries",
                }
                .build()
            })?,
        )?;
        let lease = super::connection::AnalysisLease::acquire(root)?;
        for entry in fs::read_dir(root).context(IoSnafu { path: root })? {
            if entry.context(IoSnafu { path: root })?.file_name() != "analysis.lock" {
                return Self::reject_path(root, "the restore directory is not empty and private");
            }
        }
        let pending = root.join("restore.pending");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .context(IoSnafu { path: &pending })?
            .sync_all()
            .context(IoSnafu { path: &pending })?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        #[cfg(test)]
        Self::crash_path(root, "restore.marked");
        let copy_bytes = manifest
            .copy_bytes(root, 0)?
            .checked_add(trace_reserve)
            .ok_or_else(|| {
                crate::StorageCapacitySnafu {
                    resource: "copy reserve",
                }
                .build()
            })?;
        storage.check_append(Self::storage_at(root, 0, 0)?, copy_bytes)?;
        Self::segment_directory(root)?;
        Self::copy_bundle_file(
            &backup.join("analysis.duckdb"),
            &root.join("analysis.duckdb"),
            manifest.database_bytes,
        )?;
        for segment in &manifest.segments {
            Self::copy_bundle_file(
                &super::raw::RawJournal::file_path(backup, &segment.file_name)?,
                &super::raw::RawJournal::file_path(root, &segment.file_name)?,
                segment.bytes,
            )?;
        }
        let segments = root.join("segments");
        File::open(&segments)
            .context(IoSnafu { path: &segments })?
            .sync_all()
            .context(IoSnafu { path: &segments })?;
        Self::validate_bundle(&manifest, root, storage)?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        let store = Self::open_leased(root.to_path_buf(), Default::default(), storage, lease)?;
        let meta = store.meta()?;
        if meta.store_uuid.to_string() != manifest.store_uuid
            || meta.schema_version != ANALYSIS_SCHEMA_VERSION as u32
            || meta.recovery_epoch != manifest.recovery_epoch
            || meta.commit_revision != manifest.commit_revision
        {
            return Self::reject_path(
                root,
                "the restored database identity differs from its manifest",
            );
        }
        {
            let mut writer = store.writer()?;
            let files = Self::backup_segments(writer.get()?)?;
            if files
                .iter()
                .map(|(id, bytes, name)| (*id, *bytes, name.as_str()))
                .ne(manifest.segments.iter().map(|segment| {
                    (
                        segment.segment_id,
                        segment.bytes,
                        segment.file_name.as_str(),
                    )
                }))
            {
                return store.reject("the restored catalog differs from its segment manifest");
            }
            let unsealed: bool = writer
                .get()?
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM segments WHERE NOT sealed)",
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "validate sealed restore catalog",
                })?;
            if unsealed {
                return store.reject("the backup catalog contains an unsealed segment");
            }
            let transaction = writer
                .get_mut()?
                .transaction()
                .context(AnalysisDatabaseSnafu {
                    operation: "begin restore epoch",
                })?;
            let epoch = meta
                .recovery_epoch
                .checked_add(1)
                .ok_or_else(|| store.state_error("the recovery epoch is exhausted"))?;
            transaction
                .execute(
                    "UPDATE store_meta SET recovery_epoch = ? WHERE singleton = true",
                    params![epoch],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "advance restore epoch",
                })?;
            #[cfg(test)]
            store.crash_at("restore.before");
            store.commit_metadata(transaction, "commit restore epoch")?;
            #[cfg(test)]
            store.crash_at("restore.after");
        }
        store.recover_managed_startup()?;
        fs::remove_file(&pending).context(IoSnafu { path: &pending })?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        #[cfg(test)]
        store.crash_at("restore.ready");
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;

    use super::*;
    use crate::{EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1};

    fn identity() -> EvidenceIntakeIdentityV1 {
        crate::analysis::tests::identity()
    }

    fn batch(cursor: u64) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 1_000_000_000,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        }
    }

    #[test]
    fn observability_backup_incomplete() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        use crate::{AnalysisReadControl, TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let intent = trace_intent()?;
        let trace = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let frame = TraceFrameV1 {
            execution_id: trace.execution_id,
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: b"output".to_vec(),
        };
        let mut input = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![frame.clone()],
            terminal: None,
        };
        let receipt = store.append_trace(trace, &input, 200)?;
        let before = store.read_trace(trace, 1, &AnalysisReadControl::default())?;
        let backup = root.join("backups/saved");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.segments.len(), 2);
        let trace_file = manifest
            .segments
            .iter()
            .find(|segment| segment.file_name.split('.').nth(1) == Some("d"))
            .ok_or("diagnostic backup segment absent")?;
        let path = super::super::raw::RawJournal::file_path(&backup, &trace_file.file_name)?;
        let moved = directory.path().join("saved-segment");
        fs::rename(&path, &moved)?;
        let target = directory.path().join("restored");
        assert!(AnalysisStore::restore(&backup, &target).is_err());
        assert!(!target.exists());
        fs::rename(&moved, &path)?;
        input.frames[0].sequence = 2;
        store.append_trace(trace, &input, 201)?;
        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
        assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
        assert_eq!(restored.trace_receipt(trace)?, Some(receipt));
        assert_eq!(
            restored
                .trace_intent(intent.tenant_id, intent.request_id)?
                .ok_or("intent absent")?
                .1,
            intent
        );
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame.clone()]);
        assert_eq!(page.positions, before.positions);
        assert_eq!(page.terminal, None);
        let terminal = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(1, 6)),
        };
        let receipt = restored.append_trace(trace, &terminal, 202)?;
        assert_eq!(
            store
                .trace_receipt(trace)?
                .ok_or("receipt absent")?
                .last_sequence,
            2
        );
        assert!(store
            .trace_receipt(trace)?
            .ok_or("receipt absent")?
            .terminal
            .is_none());
        drop(restored);
        let restored = AnalysisStore::open(&target)?;
        assert_eq!(restored.append_trace(trace, &terminal, 203)?, receipt);
        let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame]);
        assert_eq!(page.terminal, terminal.terminal);
        Ok(())
    }

    #[test]
    fn backup_manifest_limit_is_optional() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let mut store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let backup = root.join("backups/first");
        let manifest = store.backup(&backup)?;
        let bytes = fs::metadata(backup.join("manifest.json"))?.len();
        let limits = StorageLimitsV1 {
            manifest_max_bytes: Some(bytes - 1),
            ..Default::default()
        };
        store.storage = limits;
        let before = store.meta()?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "backup manifest bytes",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.meta()?, before);
        let restored = directory.path().join("restored");
        assert!(matches!(
            AnalysisStore::restore_with_limits(&backup, &restored, limits),
            Err(crate::Error::StorageCapacity {
                resource: "backup manifest bytes",
                ..
            })
        ));
        assert!(!restored.exists());
        let entries = StorageLimitsV1 {
            storage_entries: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            AnalysisStore::restore_with_limits(&backup, &restored, entries),
            Err(crate::Error::StorageCapacity {
                resource: "storage entries",
                ..
            })
        ));
        assert!(!restored.exists());
        let store = AnalysisStore::restore(&backup, &restored)?;
        assert_eq!(store.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn backup_accounts_manifest_allocation() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let mut store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let manifest = store.backup(&root.join("backups/first"))?;
        let bytes = serde_json::to_vec(&manifest)?.len() as u64;
        let block = rustix::fs::statvfs(&root)?.f_frsize;
        let allocated = bytes
            .checked_next_multiple_of(block)
            .ok_or("allocation overflow")?;
        assert!(allocated > bytes);
        let copied = manifest.copy_bytes(&root, 0)?;
        let actual = manifest.copy_bytes(&root, bytes)?;
        assert_eq!(
            actual,
            copied.checked_add(allocated).ok_or("copy overflow")?
        );
        let usage = store.storage_usage()?;
        let unrounded = copied.checked_add(bytes).ok_or("copy overflow")?;
        store.storage = StorageLimitsV1 {
            disk_max_bytes: Some(
                usage
                    .file_bytes
                    .checked_add(unrounded)
                    .ok_or("quota overflow")?,
            ),
            ..Default::default()
        };
        store.storage.check_backup(usage, unrounded)?;
        let before = store.meta()?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.meta()?, before);
        let usage = store.storage_usage()?;
        store.storage.disk_max_bytes = Some(
            usage
                .file_bytes
                .checked_add(actual)
                .ok_or("quota overflow")?,
        );
        store.storage.check_backup(usage, actual)?;
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert!(fs::read_dir(root.join("backups"))?.all(|entry| entry
            .is_ok_and(|entry| { !entry.file_name().to_string_lossy().starts_with(".backup-") })));
        let limits = StorageLimitsV1 {
            policy_reserve_bytes: Some(1),
            ..Default::default()
        };
        assert!(limits.check_copy(actual, actual).is_err());
        limits.check_copy(actual.checked_add(1).ok_or("reserve overflow")?, actual)?;
        Ok(())
    }

    #[test]
    fn observability_backup_reserve() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        use crate::{TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let limits = StorageLimitsV1 {
            disk_max_bytes: Some(1024 * 1024 * 1024),
            ..StorageLimitsV1::fixture()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        let intent = trace_intent()?;
        let trace = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let input = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: trace.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        };
        let receipt = store.append_trace(trace, &input, 200)?;
        let manifest = store.backup(&root.join("backups/first"))?;
        let copy_bytes = manifest.copy_bytes(&root, serde_json::to_vec(&manifest)?.len() as u64)?;
        let usage = store.storage_usage()?;
        let padding = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("quota"))?;
        padding.set_len(
            limits.disk_max_bytes.ok_or("configured disk limit")?
                - 256 * 1024 * 1024
                - usage.file_bytes
                - copy_bytes
                - 8192,
        )?;
        limits.check_backup(store.storage_usage()?, copy_bytes)?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.trace_receipt(trace)?, Some(receipt.clone()));
        padding.set_len(0)?;
        let held = root.join("backups/held");
        DirBuilder::new().mode(0o700).create(&held)?;
        for index in 0..limits.diagnostic_entries.ok_or("configured entry limit")? - 3 {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(held.join(format!("{index:016x}.d.reserve")))?;
        }
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "diagnostic storage entries",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert_eq!(store.trace_receipt(trace)?, Some(receipt));
        fs::rename(
            held.join("0000000000000000.d.reserve"),
            directory.path().join("saved-entry"),
        )?;
        store.backup(&blocked)?;
        assert_eq!(
            store.accept_validated_batch(identity(), batch(1))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let terminal = TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![],
            terminal: Some(trace_terminal(1, 1)),
        };
        assert_eq!(
            store.append_trace(trace, &terminal, 201)?.terminal,
            terminal.terminal
        );
        Ok(())
    }

    #[test]
    fn analysis_store_backup_quota() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = StorageLimitsV1 {
            disk_max_bytes: Some(1024 * 1024 * 1024),
            ..StorageLimitsV1::fixture()
        };
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        store.accept_validated_batch(identity(), batch(1))?;
        store.checkpoint()?;
        let before = store.storage_usage()?;
        let meta = store.meta()?;
        for invalid in [
            directory.path().join("outside.duckdb"),
            root.join("analysis.duckdb"),
            root.join("backups/nested/copy.duckdb"),
            root.join("backups/../escape.duckdb"),
            root.join("backups/copy.manifest.json"),
        ] {
            assert!(store.backup(&invalid).is_err());
        }
        let backup = root.join("backups/first");
        let manifest = store.backup(&backup)?;
        let saved = fs::read(backup.join("analysis.duckdb"))?;
        let usage = store.storage_usage()?;
        assert!(usage.file_bytes >= before.file_bytes + manifest.database_bytes);
        assert!(usage.allocated_bytes > before.allocated_bytes);
        assert_eq!(
            fs::metadata(root.join("backups"))?.permissions().mode() & 0o777,
            0o700
        );
        assert!(store.storage_with_entries(4096).is_err());
        let padding = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("quota"))?;
        padding.set_len(limits.disk_max_bytes.ok_or("configured disk limit")?)?;
        let blocked = root.join("backups/blocked");
        assert!(matches!(
            store.backup(&blocked),
            Err(crate::Error::StorageCapacity {
                resource: "data files",
                ..
            })
        ));
        assert!(!blocked.exists());
        assert!(!blocked.join("manifest.json").exists());
        assert_eq!(store.meta()?, meta);
        assert_eq!(fs::read(backup.join("analysis.duckdb"))?, saved);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        padding.set_len(0)?;
        store.backup(&blocked)?;
        let usage = store.storage_usage()?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
        assert_eq!(store.storage_usage()?.file_bytes, usage.file_bytes);
        assert_eq!(store.meta()?, meta);
        let external = directory.path().join("external");
        fs::rename(&backup, &external)?;
        let restored = AnalysisStore::restore(&external, &directory.path().join("restored"))?;
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_backup_window() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::{sync::mpsc, thread, time::Duration};

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let meta = store.meta()?;
        let backups = root.join("backups");
        let destination = backups.join("saved");
        let reader = store.reader()?;
        let (sender, receiver) = mpsc::channel();
        thread::scope(
            |scope| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let worker = scope.spawn(|| {
                    sender
                        .send(store.backup(&destination))
                        .map_err(|_| "backup receiver closed")
                });
                let pending = receiver.recv_timeout(Duration::from_millis(50));
                drop(reader);
                assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
                let manifest = receiver.recv_timeout(Duration::from_secs(10))??;
                assert_eq!(manifest.commit_revision, meta.commit_revision);
                worker.join().map_err(|_| "backup panicked")??;
                Ok(())
            },
        )?;
        assert_eq!(store.meta()?, meta);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        let saved = fs::read(destination.join("analysis.duckdb"))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(store.backup(&destination).is_err());
        assert_eq!(store.meta()?, meta);
        store.accept_validated_batch(identity(), batch(2))?;
        let restored = AnalysisStore::restore(&destination, &directory.path().join("restored"))?;
        assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
        let blocked = backups.join("blocked");
        DirBuilder::new().mode(0o700).create(&blocked)?;
        store.checkpoint()?;
        let before_failure = store.storage_usage()?;
        assert!(store.backup(&blocked).is_err());
        assert_eq!(store.storage_usage()?.file_bytes, before_failure.file_bytes);
        assert_eq!(fs::read_dir(&blocked)?.count(), 0);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
        assert!(AnalysisStore::restore(&blocked, &directory.path().join("invalid")).is_err());
        assert_eq!(fs::read(destination.join("analysis.duckdb"))?, saved);
        Ok(())
    }

    #[test]
    fn analysis_store_closed_access() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        store.checkpoint()?;
        let mut meta = store.meta()?;
        store.write_ready.store(false, Ordering::Release);
        for reader in &store.readers {
            drop(reader.lock().map_err(|_| "reader poisoned")?.take());
        }
        drop(store.writer.lock().map_err(|_| "writer poisoned")?.take());
        assert!(store.meta().is_err());
        assert!(store.checkpoint().is_err());
        assert!(store.accept_validated_batch(identity(), batch(2)).is_err());
        assert!(store.read_page(&identity(), 1).is_err());
        assert!(!store.storage_health()?.write_ready);
        assert!(AnalysisStore::open(&root).is_err());
        meta.commit_revision += 1;
        assert!(store.reopen_backup(&meta).is_err());
        assert!(store.meta().is_err());
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_backup_restore() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("original"))?;
        let source = identity();
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(1))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let backup_dir = store.root.join("backups");
        let backup = backup_dir.join("saved");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.commit_revision, 1);
        assert_eq!(manifest.recovery_epoch, 1);
        assert_eq!(manifest.schema_version, ANALYSIS_SCHEMA_VERSION as u32);
        assert_eq!(
            manifest.database_bytes,
            fs::metadata(backup.join("analysis.duckdb"))?.len()
        );
        assert_eq!(manifest.segments.len(), 1);
        assert!(store.backup(&backup).is_err());
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(2))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
        assert_eq!(restored.meta()?.recovery_epoch, 2);
        assert_eq!(restored.meta()?.commit_revision, 1);
        assert_eq!(
            restored
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert_eq!(
            restored.record_recovery_floor(&source, 2)?,
            AnalysisRecoveryStatusV1::Partial {
                first_cursor: 2,
                last_cursor: 2,
            }
        );
        assert_eq!(restored.meta()?.commit_revision, 2);
        assert_eq!(
            restored.record_recovery_floor(&source, 2)?,
            AnalysisRecoveryStatusV1::Partial {
                first_cursor: 2,
                last_cursor: 2,
            }
        );
        assert_eq!(restored.meta()?.commit_revision, 2);
        assert_eq!(
            restored
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert!(AnalysisStore::restore(&backup, &directory.path().join("restored")).is_err());
        drop(restored);
        let mut output = OpenOptions::new()
            .append(true)
            .open(backup.join("analysis.duckdb"))?;
        output.write_all(b"corrupt")?;
        assert!(AnalysisStore::restore(&backup, &directory.path().join("corrupt")).is_err());
        assert!(!directory.path().join("corrupt").exists());
        Ok(())
    }

    #[test]
    fn large_segment_backup_restores() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("original");
        let store = AnalysisStore::open(&root)?;
        let payload = vec![7; 17 * 1_024 * 1_024];
        let mut input = batch(1);
        input.framed_records = payload.clone().into();
        input.frame_ends = vec![payload.len()];
        store.accept_validated_batch(identity(), input)?;
        store.accept_validated_batch(identity(), batch(2))?;
        let positions = store.read_page(&identity(), 1)?;
        assert_eq!(positions.records.len(), 1);
        assert_eq!(positions.records[0].framed_record, payload);
        assert_eq!(positions.next_cursor, Some(2));
        let tail = store.read_page(&identity(), 2)?;
        assert_eq!(tail.records.len(), 1);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.read_page(&identity(), 1)?, positions);
        let backup = root.join("backups/large");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.segments.len(), 2);
        assert!(manifest.segments[0].bytes > super::super::EVIDENCE_SEGMENT_BYTES as u64);
        let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
        let restored_page = restored.read_page(&identity(), 1)?;
        assert_eq!(restored_page.records, positions.records);
        assert_eq!(restored_page.next_cursor, positions.next_cursor);
        assert_eq!(restored.read_page(&identity(), 2)?.records, tail.records);
        Ok(())
    }

    #[test]
    fn analysis_store_bundle_checks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let backup = root.join("backups/saved");
        let manifest = store.backup(&backup)?;
        let value = serde_json::to_value(&manifest)?;
        assert!(value.get("database_sha256").is_none());
        assert!(value["segments"][0].get("sha256").is_none());
        let segment =
            super::super::raw::RawJournal::file_path(&backup, &manifest.segments[0].file_name)?;
        let bytes = fs::read(&segment)?;
        let target = directory.path().join("restored");
        let rejected = || {
            assert!(AnalysisStore::restore(&backup, &target).is_err());
            assert!(!target.exists());
        };

        let moved = directory.path().join("saved-segment");
        fs::rename(&segment, &moved)?;
        rejected();
        symlink(&moved, &segment)?;
        rejected();
        fs::remove_file(&segment)?;
        fs::rename(&moved, &segment)?;

        let mut changed = bytes.clone();
        *changed.last_mut().ok_or("segment is empty")? ^= 1;
        fs::write(&segment, &changed)?;
        rejected();
        fs::write(&segment, &bytes)?;
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o644))?;
        rejected();
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o600))?;

        let unknown = backup.join("segments/unknown");
        fs::write(&unknown, b"do not remove")?;
        rejected();
        assert_eq!(fs::read(&unknown)?, b"do not remove");
        fs::remove_file(&unknown)?;
        let manifest_path = backup.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path)?;
        let mut changed = manifest.clone();
        changed.segments.push(changed.segments[0].clone());
        fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
        rejected();
        fs::write(&manifest_path, &manifest_bytes)?;

        let active_name = format!(
            "{}.open",
            manifest.segments[0]
                .file_name
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        );
        let active = segment.with_file_name(&active_name);
        fs::rename(&segment, &active)?;
        let mut changed = manifest.clone();
        changed.segments[0].file_name = active_name;
        fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
        rejected();
        assert_eq!(fs::read(&active)?, bytes);
        fs::rename(&active, &segment)?;
        fs::write(&manifest_path, &manifest_bytes)?;

        let database = backup.join("analysis.duckdb");
        let database_bytes = fs::read(&database)?;
        for sql in [
            "UPDATE source_receipts SET contiguous_cursor = contiguous_cursor + 1",
            "DROP TABLE coverage",
        ] {
            let writer = duckdb::Connection::open(&database)?;
            writer.execute_batch(sql)?;
            writer.execute_batch("CHECKPOINT")?;
            drop(writer);
            let mut changed = manifest.clone();
            changed.database_bytes = fs::metadata(&database)?.len();
            fs::write(&manifest_path, serde_json::to_vec(&changed)?)?;
            rejected();
            fs::write(&database, &database_bytes)?;
            fs::write(&manifest_path, &manifest_bytes)?;
        }

        fs::set_permissions(&database, fs::Permissions::from_mode(0o400))?;
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o400))?;

        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(
            restored.read_page(&identity(), 1)?.records[0].framed_record,
            b"frame"
        );
        assert_eq!(fs::read(&segment)?, bytes);
        assert_eq!(fs::read(&manifest_path)?, manifest_bytes);
        assert_eq!(fs::read(&database)?, database_bytes);
        assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
        Ok(())
    }

    #[test]
    fn analysis_store_backup_crashes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
            let root = PathBuf::from(root);
            AnalysisStore::open(&root)?.backup(&root.join("backups/saved"))?;
            return Err("the requested backup crash did not occur".into());
        }
        for point in [
            "backup.sealed",
            "backup.closed",
            "backup.copied",
            "backup.ready",
        ] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open(&root)?;
            store.accept_validated_batch(identity(), batch(1))?;
            let meta = store.meta()?;
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "analysis::backup::tests::analysis_store_backup_crashes",
                ])
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}");
            let store = AnalysisStore::open(&root)?;
            assert_eq!(store.meta()?, meta, "{point}");
            assert_eq!(
                store.read_page(&identity(), 1)?.records[0].framed_record,
                b"frame"
            );
            let saved = root.join("backups/saved");
            let restored = AnalysisStore::restore(&saved, &directory.path().join("restored"));
            if point == "backup.ready" {
                assert_eq!(restored?.read_page(&identity(), 1)?.records.len(), 1);
            } else {
                assert!(restored.is_err(), "{point}");
            }
            store.accept_validated_batch(identity(), batch(2))?;
            let retry = root.join("backups/retry");
            store.backup(&retry)?;
            assert_eq!(
                AnalysisStore::restore(&retry, &directory.path().join("retry"))?
                    .read_page(&identity(), 1)?
                    .records
                    .len(),
                2
            );
        }
        Ok(())
    }
}
