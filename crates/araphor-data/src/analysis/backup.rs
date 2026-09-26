use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use duckdb::params;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use uuid::Uuid;

use super::{source_key, valid_source_identity, AnalysisStore, ANALYSIS_SCHEMA_VERSION};
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
        if !valid_source_identity(identity) {
            return self.reject("the recovery source identity is invalid");
        }
        let key = source_key(identity);
        let mut writer = self.writer()?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
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
            Self::record_revision(&transaction, revision, &["recovery_gaps"])?;
            transaction.commit().context(AnalysisDatabaseSnafu {
                operation: "commit source recovery",
            })?;
            self.revision.send_replace(revision);
        }
        Ok(AnalysisRecoveryStatusV1::Partial {
            first_cursor: first,
            last_cursor: node_retained_floor,
        })
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.writer()?
            .execute_batch("CHECKPOINT")
            .context(AnalysisDatabaseSnafu {
                operation: "checkpoint analysis database",
            })
    }

    pub fn backup(&self, destination: &Path) -> Result<AnalysisBackupManifestV1> {
        let parent = destination
            .parent()
            .ok_or_else(|| self.state_error("the backup path has no parent"))?;
        if !destination.is_absolute() || destination == self.root.join("analysis.duckdb") {
            return self.reject("the backup path is not an independent absolute file");
        }
        let parent_meta = fs::symlink_metadata(parent).context(IoSnafu { path: parent })?;
        if !parent_meta.is_dir() || parent_meta.permissions().mode() & 0o077 != 0 {
            return self.reject("the backup directory is not private");
        }
        let writer = self.writer()?;
        writer
            .execute_batch("CHECKPOINT")
            .context(AnalysisDatabaseSnafu {
                operation: "checkpoint before backup",
            })?;
        let source = self.root.join("analysis.duckdb");
        let source_bytes = fs::metadata(&source)
            .context(IoSnafu { path: &source })?
            .len();
        let volume = rustix::fs::statfs(parent)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: parent })?;
        let block_bytes = u64::try_from(volume.f_bsize)
            .map_err(|_| self.state_error("the backup block size is invalid"))?;
        let available = volume
            .f_bavail
            .checked_mul(block_bytes)
            .ok_or_else(|| self.state_error("the backup available space is invalid"))?;
        let required = source_bytes
            .checked_add(source_bytes / 4)
            .ok_or_else(|| self.state_error("the backup maintenance reserve is invalid"))?;
        if available < required {
            return self.reject("the backup cannot preserve maintenance free space");
        }
        let mut source_file = File::open(&source).context(IoSnafu { path: &source })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .context(IoSnafu { path: destination })?;
        std::io::copy(&mut source_file, &mut output).context(IoSnafu { path: destination })?;
        output.sync_all().context(IoSnafu { path: destination })?;
        let meta = Self::read_meta_from(&writer, &source)?;
        let manifest = AnalysisBackupManifestV1 {
            store_uuid: meta.store_uuid.to_string(),
            schema_version: meta.schema_version,
            recovery_epoch: meta.recovery_epoch,
            commit_revision: meta.commit_revision,
            database_bytes: source_bytes,
            database_sha256: Self::file_digest(destination)?,
        };
        let manifest_path = destination.with_extension("manifest.json");
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest_path)
            .context(IoSnafu {
                path: &manifest_path,
            })?;
        let bytes = serde_json::to_vec(&manifest).context(JsonSnafu {
            path: &manifest_path,
        })?;
        manifest_file.write_all(&bytes).context(IoSnafu {
            path: &manifest_path,
        })?;
        manifest_file.sync_all().context(IoSnafu {
            path: &manifest_path,
        })?;
        File::open(parent)
            .context(IoSnafu { path: parent })?
            .sync_all()
            .context(IoSnafu { path: parent })?;
        Ok(manifest)
    }

    pub fn restore(backup: &Path, root: &Path) -> Result<Self> {
        if !backup.is_absolute() || !root.is_absolute() {
            return Self::reject_path(root, "backup and restore paths must be absolute");
        }
        let manifest_path = backup.with_extension("manifest.json");
        let backup_meta = fs::symlink_metadata(backup).context(IoSnafu { path: backup })?;
        let manifest_meta = fs::symlink_metadata(&manifest_path).context(IoSnafu {
            path: &manifest_path,
        })?;
        if !backup_meta.is_file()
            || !manifest_meta.is_file()
            || backup_meta.permissions().mode() & 0o077 != 0
            || manifest_meta.permissions().mode() & 0o077 != 0
            || manifest_meta.len() > 4096
        {
            return Self::reject_path(root, "the backup files are unsafe or exceed their bounds");
        }
        let mut bytes = Vec::new();
        File::open(&manifest_path)
            .context(IoSnafu {
                path: &manifest_path,
            })?
            .read_to_end(&mut bytes)
            .context(IoSnafu {
                path: &manifest_path,
            })?;
        let manifest: AnalysisBackupManifestV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu {
                path: &manifest_path,
            })?;
        if manifest.schema_version != ANALYSIS_SCHEMA_VERSION as u32
            || Uuid::parse_str(&manifest.store_uuid).is_err()
            || backup_meta.len() != manifest.database_bytes
            || Self::file_digest(backup)? != manifest.database_sha256
        {
            return Self::reject_path(root, "the backup manifest or database differs");
        }
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: root }),
        }
        let root_meta = fs::symlink_metadata(root).context(IoSnafu { path: root })?;
        if !root_meta.is_dir()
            || root_meta.permissions().mode() & 0o077 != 0
            || fs::read_dir(root)
                .context(IoSnafu { path: root })?
                .next()
                .is_some()
        {
            return Self::reject_path(root, "the restore directory is not empty and private");
        }
        let target = root.join("analysis.duckdb");
        let mut input = File::open(backup).context(IoSnafu { path: backup })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .context(IoSnafu { path: &target })?;
        std::io::copy(&mut input, &mut output).context(IoSnafu { path: &target })?;
        output.sync_all().context(IoSnafu { path: &target })?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        let store = Self::open(root)?;
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
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
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
            transaction.commit().context(AnalysisDatabaseSnafu {
                operation: "commit restore epoch",
            })?;
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
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
    fn analysis_store_backup_restore() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("original"))?;
        let source = identity();
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(1))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        let backup_dir = directory.path().join("backups");
        DirBuilder::new().mode(0o700).create(&backup_dir)?;
        let backup = backup_dir.join("analysis.duckdb");
        let manifest = store.backup(&backup)?;
        assert_eq!(manifest.commit_revision, 1);
        assert_eq!(manifest.recovery_epoch, 1);
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.database_bytes, fs::metadata(&backup)?.len());
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
        let mut output = OpenOptions::new().append(true).open(&backup)?;
        output.write_all(b"corrupt")?;
        assert!(AnalysisStore::restore(&backup, &directory.path().join("corrupt")).is_err());
        assert!(!directory.path().join("corrupt").exists());
        Ok(())
    }
}
