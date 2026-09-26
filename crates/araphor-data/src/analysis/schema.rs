use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, IoSnafu, Result};

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
    pub(super) fn validate_tables(writer: &Connection) -> Result<()> {
        let projections = [
            "singleton, store_uuid, schema_version, recovery_epoch, commit_revision FROM store_meta",
            "relation_name, last_changed_revision FROM relation_revisions",
            "stream_key, identity_json, tenant_id, cpu_id, contiguous_cursor, coverage_revision, retained_floor FROM source_receipts",
            "epoch_key, tenant_id, node_boot_id, label_epoch FROM source_bindings",
            "stream_key, tenant_id, durable_cursor, cpu_id, framed_record, frame_sha256, commit_revision, ordinal, intake_utc_ns FROM events",
            "stream_key, tenant_id, revision, report, report_sha256, commit_revision, ordinal FROM coverage",
            "tenant_id, owner_id, entity_key, lifetime_key, owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, content_sha256, commit_revision FROM context_versions",
            "processor_id, method_version, tenant_id, stream_key, class, consumed_cursor, resume_floor, coverage_revision, context_revision, start_cursor, required_floor, retired FROM processor_progress",
            "ref_id, tenant_id, stream_key, durable_cursor, expires_utc_ns FROM evidence_refs",
            "ref_id, tenant_id, owner_id, entity_key, lifetime_key, owner_revision, content_sha256 FROM context_refs",
            "result_id, tenant_id, processor_id, body, body_sha256, request_sha256, commit_revision FROM analysis_results",
            "processor_id, method_version, tenant_id, stream_key, first_cursor, last_cursor, commit_revision FROM processor_gaps",
            "stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM recovery_gaps",
            "stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM expired_ranges",
        ];
        for projection in projections {
            writer
                .prepare(&format!("SELECT {projection} LIMIT 0"))
                .context(AnalysisDatabaseSnafu {
                    operation: "validate stored schema",
                })?;
        }
        Ok(())
    }

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
    use duckdb::{params, Connection};

    use super::*;
    use crate::EvidenceIntakeIdentityV1;

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

    #[test]
    fn analysis_rejects_older_schema() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store
            .writer()?
            .execute("UPDATE store_meta SET schema_version = 2", [])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        let writer = Connection::open(root.join("analysis.duckdb"))?;
        let version: u32 =
            writer.query_row("SELECT schema_version FROM store_meta", [], |row| {
                row.get(0)
            })?;
        assert_eq!(version, 2);
        Ok(())
    }

    #[test]
    fn analysis_rejects_missing_table() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store
            .writer()?
            .execute("ALTER TABLE events RENAME TO missing_events", [])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        let writer = Connection::open(root.join("analysis.duckdb"))?;
        assert!(writer.prepare("SELECT * FROM events").is_err());
        assert!(writer.prepare("SELECT * FROM missing_events").is_ok());
        Ok(())
    }
}
