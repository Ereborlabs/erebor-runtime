use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{
    source_key, valid_source_identity, AnalysisStore, AnalysisStoreMetaV1, ANALYSIS_SCHEMA_VERSION,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, IoSnafu, JsonSnafu, Result};

#[derive(Deserialize, Serialize)]
struct UpgradeMarker {
    store_uuid: String,
    commit_revision: u64,
    from_schema: u32,
    to_schema: u32,
}

impl EvidenceIntakeIdentityV1 {
    fn epoch_key(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ARAPHOR-ANALYSIS-EPOCH-V1\0");
        hash.update(self.tenant_id);
        hash.update((self.node_id.len() as u64).to_be_bytes());
        hash.update(self.node_id.as_bytes());
        hash.update(self.source_id);
        hash.update(self.source_epoch.to_be_bytes());
        hash.finalize().into()
    }
}

impl AnalysisStore {
    pub fn source_binding(
        &self,
        tenant_id: [u8; 16],
        node_id: &str,
        source_id: [u8; 16],
        source_epoch: u64,
    ) -> Result<Option<EvidenceIntakeIdentityV1>> {
        let mut identity = EvidenceIntakeIdentityV1 {
            tenant_id,
            node_id: node_id.to_owned(),
            node_boot_id: [0; 16],
            label_epoch: 0,
            source_id,
            source_epoch,
        };
        if !crate::node_id_is_valid(node_id)
            || tenant_id == [0; 16]
            || source_id == [0; 16]
            || source_epoch == 0
        {
            return Self::reject_path(&self.root, "the source epoch lookup is invalid");
        }
        let writer = self.writer()?;
        let saved: Option<(Vec<u8>, Vec<u8>, u64)> = writer
            .query_row(
                "SELECT tenant_id, node_boot_id, label_epoch FROM source_bindings WHERE epoch_key = ?",
                params![identity.epoch_key().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read source epoch binding",
            })?;
        let Some((tenant, boot, label)) = saved else {
            return Ok(None);
        };
        identity.node_boot_id = boot
            .try_into()
            .map_err(|_| self.state_error("the source epoch boot identity is invalid"))?;
        identity.label_epoch = label;
        if tenant != identity.tenant_id
            || !valid_source_identity(&identity)
            || Self::read_receipt_from(&writer, &self.root, &identity, &source_key(&identity))?
                .is_none()
        {
            return Self::reject_path(
                &self.root,
                "the source epoch binding has no matching receipt",
            );
        }
        Ok(Some(identity))
    }

    pub(super) fn bind_source(
        writer: &Connection,
        root: &Path,
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<bool> {
        let key = identity.epoch_key();
        let saved: Option<(Vec<u8>, Vec<u8>, u64)> = writer
            .query_row(
                "SELECT tenant_id, node_boot_id, label_epoch FROM source_bindings WHERE epoch_key = ?",
                params![key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read source epoch binding",
            })?;
        if let Some((tenant, boot, label)) = saved {
            if tenant != identity.tenant_id
                || boot != identity.node_boot_id
                || label != identity.label_epoch
            {
                return Self::reject_path(root, "one source epoch changed its boot or label");
            }
            return Ok(false);
        }
        writer
            .execute(
                "INSERT INTO source_bindings VALUES (?, ?, ?, ?)",
                params![
                    key.as_slice(),
                    identity.tenant_id.as_slice(),
                    identity.node_boot_id.as_slice(),
                    identity.label_epoch,
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "bind source epoch",
            })?;
        Ok(true)
    }

    pub(super) fn populate_bindings(writer: &Connection, root: &Path) -> Result<()> {
        let mut statement = writer
            .prepare("SELECT identity_json FROM source_receipts")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare source binding validation",
            })?;
        let saved = statement
            .query_map([], |row| row.get::<_, String>(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read source binding identities",
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context(AnalysisDatabaseSnafu {
                operation: "read source binding identities",
            })?;
        drop(statement);
        for json in saved {
            let identity: EvidenceIntakeIdentityV1 =
                serde_json::from_str(&json).context(JsonSnafu {
                    path: root.join("analysis.duckdb"),
                })?;
            Self::bind_source(writer, root, &identity)?;
        }
        Ok(())
    }

    pub(super) fn prepare_upgrade(
        writer: &Connection,
        root: &Path,
        path: &Path,
        meta: &AnalysisStoreMetaV1,
    ) -> Result<()> {
        let marker_path = root.join("analysis.upgrade.json");
        let backup_path = root.join("analysis.schema1.backup.duckdb");
        let marker = UpgradeMarker {
            store_uuid: meta.store_uuid.to_string(),
            commit_revision: meta.commit_revision,
            from_schema: 1,
            to_schema: ANALYSIS_SCHEMA_VERSION as u32,
        };
        if marker_path.exists() {
            let saved: UpgradeMarker = serde_json::from_slice(
                &fs::read(&marker_path).context(IoSnafu { path: &marker_path })?,
            )
            .context(JsonSnafu { path: &marker_path })?;
            if saved.store_uuid != marker.store_uuid
                || saved.commit_revision != marker.commit_revision
                || saved.from_schema != marker.from_schema
                || saved.to_schema != marker.to_schema
            {
                return Self::reject_path(root, "the interrupted schema upgrade marker changed");
            }
        } else {
            if backup_path.exists() {
                return Self::reject_path(
                    root,
                    "a schema backup exists without its upgrade marker",
                );
            }
            let bytes = serde_json::to_vec(&marker).context(JsonSnafu { path: &marker_path })?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&marker_path)
                .context(IoSnafu { path: &marker_path })?;
            file.write_all(&bytes)
                .context(IoSnafu { path: &marker_path })?;
            file.sync_all().context(IoSnafu { path: &marker_path })?;
            File::open(root)
                .context(IoSnafu { path: root })?
                .sync_all()
                .context(IoSnafu { path: root })?;
        }
        writer
            .execute_batch("CHECKPOINT")
            .context(AnalysisDatabaseSnafu {
                operation: "checkpoint before schema upgrade",
            })?;
        if backup_path.exists() {
            let metadata =
                fs::symlink_metadata(&backup_path).context(IoSnafu { path: &backup_path })?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || Self::file_digest(&backup_path)? != Self::file_digest(path)?
            {
                return Self::reject_path(root, "the existing schema backup differs from source");
            }
        } else {
            let temporary = root.join("analysis.schema1.backup.tmp");
            if temporary.exists() {
                let metadata =
                    fs::symlink_metadata(&temporary).context(IoSnafu { path: &temporary })?;
                if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
                    return Self::reject_path(root, "the interrupted schema backup is unsafe");
                }
                fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
            }
            let mut input = File::open(path).context(IoSnafu { path })?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .context(IoSnafu { path: &temporary })?;
            std::io::copy(&mut input, &mut output).context(IoSnafu { path: &temporary })?;
            output.sync_all().context(IoSnafu { path: &temporary })?;
            fs::rename(&temporary, &backup_path).context(IoSnafu { path: &backup_path })?;
            File::open(root)
                .context(IoSnafu { path: root })?
                .sync_all()
                .context(IoSnafu { path: root })?;
        }
        Ok(())
    }

    pub(super) fn finish_upgrade(root: &Path, meta: &AnalysisStoreMetaV1) -> Result<()> {
        let marker_path = root.join("analysis.upgrade.json");
        if !marker_path.exists() {
            return Ok(());
        }
        let saved: UpgradeMarker = serde_json::from_slice(
            &fs::read(&marker_path).context(IoSnafu { path: &marker_path })?,
        )
        .context(JsonSnafu { path: &marker_path })?;
        if saved.store_uuid != meta.store_uuid.to_string()
            || saved.to_schema != meta.schema_version
            || saved.commit_revision != meta.commit_revision
            || !root.join("analysis.schema1.backup.duckdb").is_file()
        {
            return Self::reject_path(root, "the schema upgrade marker cannot be completed");
        }
        fs::remove_file(&marker_path).context(IoSnafu { path: &marker_path })?;
        File::open(root)
            .context(IoSnafu { path: root })?
            .sync_all()
            .context(IoSnafu { path: root })?;
        Ok(())
    }

    pub(super) fn file_digest(path: &Path) -> Result<[u8; 32]> {
        let mut input = File::open(path).context(IoSnafu { path })?;
        let mut digest = Sha256::new();
        let mut chunk = [0_u8; 1024 * 1024];
        loop {
            let bytes = input.read(&mut chunk).context(IoSnafu { path })?;
            if bytes == 0 {
                break;
            }
            digest.update(&chunk[..bytes]);
        }
        Ok(digest.finalize().into())
    }

    pub(super) fn reject_path<T>(root: &Path, reason: &str) -> Result<T> {
        crate::AnalysisStateSnafu {
            path: root.to_path_buf(),
            reason: reason.to_owned(),
        }
        .fail()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use duckdb::{params, Connection};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{EvidenceIntakeIdentityV1, EvidenceRetentionOwner, RetentionLimitsV1};

    #[test]
    fn source_binding_keeps_the_committed_boot_and_label(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 7,
            source_id: [3; 16],
            source_epoch: 9,
        };
        let lookup = || {
            store.source_binding(
                identity.tenant_id,
                &identity.node_id,
                identity.source_id,
                identity.source_epoch,
            )
        };
        assert_eq!(lookup()?, None);
        store.accept_validated_batch(
            identity.clone(),
            super::super::ValidatedEvidenceBatchV1 {
                cpu_id: 1,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: prost::bytes::Bytes::from_static(b"frame"),
                frame_ends: vec![5],
            },
        )?;
        assert_eq!(lookup()?, Some(identity.clone()));
        assert_eq!(
            store.source_binding([4; 16], &identity.node_id, identity.source_id, 9)?,
            None
        );
        store.writer()?.execute(
            "UPDATE source_bindings SET node_boot_id = ? WHERE epoch_key = ?",
            params![[5_u8; 16].as_slice(), identity.epoch_key().as_slice()],
        )?;
        assert!(lookup().is_err());
        Ok(())
    }

    fn legacy_store(
        root: &Path,
    ) -> std::result::Result<EvidenceIntakeIdentityV1, Box<dyn std::error::Error>> {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let path = root.join("analysis.duckdb");
        let writer = Connection::open(&path)?;
        writer.execute_batch(
            "CREATE TABLE store_meta (
                singleton BOOLEAN PRIMARY KEY CHECK (singleton),
                store_uuid VARCHAR NOT NULL, schema_version INTEGER NOT NULL,
                recovery_epoch UBIGINT NOT NULL, commit_revision UBIGINT NOT NULL
            );
            CREATE TABLE relation_revisions (
                relation_name VARCHAR PRIMARY KEY, last_changed_revision UBIGINT NOT NULL
            );
            CREATE TABLE source_receipts (
                stream_key BLOB PRIMARY KEY, identity_json VARCHAR NOT NULL,
                tenant_id BLOB NOT NULL, cpu_id UINTEGER NOT NULL,
                contiguous_cursor UBIGINT NOT NULL, coverage_revision UBIGINT NOT NULL,
                retained_floor UBIGINT NOT NULL
            );
            CREATE TABLE events (
                stream_key BLOB NOT NULL, tenant_id BLOB NOT NULL,
                durable_cursor UBIGINT NOT NULL, cpu_id UINTEGER NOT NULL,
                framed_record BLOB NOT NULL, frame_sha256 BLOB NOT NULL,
                commit_revision UBIGINT NOT NULL, ordinal UINTEGER NOT NULL,
                PRIMARY KEY (stream_key, durable_cursor)
            );
            CREATE TABLE coverage (
                stream_key BLOB NOT NULL, tenant_id BLOB NOT NULL,
                revision UBIGINT NOT NULL, report BLOB NOT NULL,
                report_sha256 BLOB NOT NULL, commit_revision UBIGINT NOT NULL,
                ordinal UINTEGER NOT NULL, PRIMARY KEY (stream_key, revision)
            );",
        )?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let key = super::super::source_key(&identity);
        let frame = b"legacy-frame";
        let digest: [u8; 32] = Sha256::digest(frame).into();
        writer.execute(
            "INSERT INTO store_meta VALUES (true, ?, 1, 1, 1)",
            params!["58106452-3e31-4c16-8c43-254f0874136b"],
        )?;
        writer.execute(
            "INSERT INTO source_receipts VALUES (?, ?, ?, 0, 1, 0, 0)",
            params![
                key.as_slice(),
                serde_json::to_string(&identity)?,
                identity.tenant_id.as_slice()
            ],
        )?;
        writer.execute(
            "INSERT INTO events VALUES (?, ?, 1, 0, ?, ?, 1, 0)",
            params![
                key.as_slice(),
                identity.tenant_id.as_slice(),
                frame.as_slice(),
                digest.as_slice()
            ],
        )?;
        writer.execute("INSERT INTO relation_revisions VALUES ('events', 1)", [])?;
        drop(writer);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(identity)
    }

    #[test]
    fn analysis_upgrade_resume() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for interrupted in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let identity = legacy_store(&root)?;
            if interrupted {
                let path = root.join("analysis.duckdb");
                let writer = Connection::open(&path)?;
                let meta = AnalysisStore::read_meta_from(&writer, &path)?;
                AnalysisStore::prepare_upgrade(&writer, &root, &path, &meta)?;
                drop(writer);
                assert!(root.join("analysis.upgrade.json").exists());
            }
            let store = AnalysisStore::open(&root)?;
            assert_eq!(store.meta()?.schema_version, 2);
            assert_eq!(store.meta()?.commit_revision, 1);
            assert_eq!(
                store.read_page(&identity, 1)?.records[0].framed_record,
                b"legacy-frame"
            );
            let age_only = EvidenceRetentionOwner::new(
                &store,
                RetentionLimitsV1 {
                    raw_max_age_ns: 1,
                    raw_max_bytes: 100,
                },
            )?;
            assert_eq!(age_only.retain(&identity, 100)?.removed_records, 0);
            let byte_pressure = EvidenceRetentionOwner::new(
                &store,
                RetentionLimitsV1 {
                    raw_max_age_ns: 1,
                    raw_max_bytes: 1,
                },
            )?;
            assert_eq!(byte_pressure.retain(&identity, 100)?.removed_records, 1);
            assert!(!root.join("analysis.upgrade.json").exists());
            assert!(root.join("analysis.schema1.backup.duckdb").exists());
            drop(store);
            assert_eq!(AnalysisStore::open(&root)?.meta()?.schema_version, 2);
        }
        Ok(())
    }
}
