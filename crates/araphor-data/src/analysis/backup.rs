use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::Ordering;

use duckdb::params;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use uuid::Uuid;

use super::{
    capacity::{StorageLimitsV1, StorageUsageV1},
    source_key, AnalysisStore, AnalysisStoreMetaV1, ANALYSIS_SCHEMA_VERSION,
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
    pub database_sha256: [u8; 32],
    pub segments: Vec<AnalysisBackupSegmentV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBackupSegmentV1 {
    pub segment_id: u64,
    pub file_name: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

impl AnalysisBackupManifestV1 {
    fn copy_bytes(&self, root: &Path) -> Result<u64> {
        let volume = rustix::fs::statvfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        std::iter::once(self.database_bytes)
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
        let key = source_key(identity);
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
            super::quota::UsageChange::from(256).apply(&transaction, &identity.tenant_id)?;
            self.check_logical(&transaction, identity.tenant_id, true)?;
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
            raw.segments.seal_all()?;
            raw.project_paths(writer.get()?)?;
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
        let mut connection = Self::open_native(&source)?;
        if Self::read_meta_from(&connection, &source)? != *meta {
            return self.reject("the analysis identity changed during backup");
        }
        Self::validate_tables(&connection)?;
        Self::validate_state(&connection, &self.root)?;
        Self::recover_segments(&mut connection, &self.root)?;
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
            .prepare("SELECT segment_id, committed_end, file_name FROM segments ORDER BY segment_id LIMIT ?")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare backup segment list",
            })?;
        let files = statement
            .query_map(
                params![
                    (super::capacity::MAX_STORAGE_ENTRIES + super::capacity::MAX_DIAGNOSTIC_ENTRIES)
                        as u64
                        + 1
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read backup segment list",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode backup segment list",
            })?;
        if files.len()
            > super::capacity::MAX_STORAGE_ENTRIES + super::capacity::MAX_DIAGNOSTIC_ENTRIES
        {
            return Self::reject_path(
                Path::new("<backup-catalog>"),
                "the backup has too many segments",
            );
        }
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
            database_sha256: Self::file_digest(&source)?,
            segments: Vec::with_capacity(files.len()),
        };
        for (segment_id, bytes, name) in files {
            let path = super::raw::RawJournal::file_path(&self.root, name)?;
            manifest.segments.push(AnalysisBackupSegmentV1 {
                segment_id: *segment_id,
                file_name: name.clone(),
                bytes: *bytes,
                sha256: Self::file_digest(&path)?,
            });
        }
        let manifest_path = destination.join("manifest.json");
        let bytes = serde_json::to_vec(&manifest).context(JsonSnafu {
            path: &manifest_path,
        })?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return self.reject("the backup manifest exceeds its size bound");
        }
        let copy_bytes = manifest
            .copy_bytes(&self.root)?
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| self.state_error("the backup reservation size is invalid"))?;
        self.storage
            .check_backup(self.storage_with_entries(files.len() + 4)?, copy_bytes)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(destination)
            .context(IoSnafu { path: destination })?;
        Self::segment_directory(destination)?;
        Self::copy_bundle_file(&source, &destination.join("analysis.duckdb"), source_bytes)?;
        for segment in &manifest.segments {
            Self::copy_bundle_file(
                &super::raw::RawJournal::file_path(&self.root, &segment.file_name)?,
                &super::raw::RawJournal::file_path(destination, &segment.file_name)?,
                segment.bytes,
            )?;
        }
        #[cfg(test)]
        self.crash_at("backup.copied");
        Self::validate_bundle(&manifest, destination)?;
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
        for directory in [
            destination.join("segments"),
            destination.to_owned(),
            parent.to_owned(),
        ] {
            File::open(&directory)
                .context(IoSnafu { path: &directory })?
                .sync_all()
                .context(IoSnafu { path: &directory })?;
        }
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

    fn validate_bundle(manifest: &AnalysisBackupManifestV1, root: &Path) -> Result<()> {
        if manifest.schema_version != ANALYSIS_SCHEMA_VERSION as u32
            || Uuid::parse_str(&manifest.store_uuid).is_err()
            || manifest.database_bytes == 0
            || manifest.segments.len()
                > super::capacity::MAX_STORAGE_ENTRIES + super::capacity::MAX_DIAGNOSTIC_ENTRIES
            || manifest
                .segments
                .windows(2)
                .any(|pair| pair[0].segment_id >= pair[1].segment_id)
            || manifest.segments.iter().any(|segment| {
                segment.segment_id == 0
                    || segment.bytes < 70
                    || segment.bytes > super::MAX_EVIDENCE_SEGMENT_BYTES as u64
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
            || Self::file_digest(&database)? != manifest.database_sha256
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
            if path != entry.path()
                || super::SegmentFile::reader(&path)?.length()? != segment.bytes
                || Self::file_digest(&path)? != segment.sha256
            {
                return Self::reject_path(root, "the backup segment differs from its manifest");
            }
        }
        if count != manifest.segments.len() {
            return Self::reject_path(root, "the backup is missing a listed segment");
        }
        Ok(())
    }

    pub fn restore(backup: &Path, root: &Path) -> Result<Self> {
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
            || manifest_meta.len() > MAX_MANIFEST_BYTES
        {
            return Self::reject_path(root, "the backup files are unsafe or exceed their bounds");
        }
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
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .context(IoSnafu {
                path: &manifest_path,
            })?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Self::reject_path(backup, "the backup manifest exceeds its size bound");
        }
        let manifest: AnalysisBackupManifestV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu {
                path: &manifest_path,
            })?;
        Self::validate_bundle(&manifest, backup)?;
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
        if manifest.segments.len() - diagnostics + 5 > super::capacity::MAX_STORAGE_ENTRIES
            || diagnostics > super::capacity::MAX_DIAGNOSTIC_ENTRIES
        {
            return Self::reject_path(backup, "the restored store would exceed its entry bound");
        }
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
        let storage = StorageLimitsV1::default();
        storage.check_copy(
            StorageUsageV1::free_bytes(root)?,
            manifest.copy_bytes(root)?,
        )?;
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
        Self::validate_bundle(&manifest, root)?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        let store = Self::open_leased(root.to_path_buf(), Default::default(), storage, lease)?;
        let meta = store.meta()?;
        if meta.store_uuid.to_string() != manifest.store_uuid
            || meta.schema_version != manifest.schema_version
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
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
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
    fn analysis_store_backup_quota() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = StorageLimitsV1 {
            disk_max_bytes: 1024 * 1024 * 1024,
            ..Default::default()
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
        padding.set_len(limits.disk_max_bytes)?;
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
        assert_eq!(
            AnalysisStore::file_digest(&backup.join("analysis.duckdb"))?,
            manifest.database_sha256
        );
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
        let saved_digest = AnalysisStore::file_digest(&destination.join("analysis.duckdb"))?;
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
        assert_eq!(
            AnalysisStore::file_digest(&destination.join("analysis.duckdb"))?,
            saved_digest
        );
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
    fn analysis_store_bundle_checks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        let backup = root.join("backups/saved");
        let manifest = store.backup(&backup)?;
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

        let restored = AnalysisStore::restore(&backup, &target)?;
        assert_eq!(
            restored.read_page(&identity(), 1)?.records[0].framed_record,
            b"frame"
        );
        assert_eq!(fs::read(&segment)?, bytes);
        assert_eq!(fs::read(&manifest_path)?, manifest_bytes);
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
