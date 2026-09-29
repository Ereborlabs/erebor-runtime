use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{source_key, valid_source_identity, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, IoSnafu, JsonSnafu, Result};

const MAX_SOURCES: u64 = 4096;

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
    pub(super) fn validate_state(writer: &Connection, root: &Path) -> Result<()> {
        let meta = Self::read_meta_from(writer, &root.join("analysis.duckdb"))?;
        if meta.store_uuid.is_nil() || meta.recovery_epoch == 0 {
            return Self::reject_path(root, "the stored identity or recovery epoch is invalid");
        }
        Self::validate_sources(writer, root)?;
        Self::validate_contexts(writer, root)?;
        let checks = [
            ("invalid source key", "SELECT 1 FROM source_receipts WHERE octet_length(stream_key) <> 32"),
            ("invalid segment identity or state", "SELECT 1 FROM segments e
                LEFT JOIN source_receipts s USING (stream_key)
                WHERE e.segment_id = 0 OR e.segment_id >= (SELECT next_segment_id FROM store_meta)
                OR e.state NOT IN ('Live', 'Deleting') OR e.stream_kind <> 'records'
                OR e.committed_end < 70 OR e.committed_end > 16777216
                OR s.stream_key IS NULL OR e.tenant_id <> s.tenant_id
                OR e.cpu_id <> s.cpu_id OR e.identity_json <> s.identity_json"),
            ("invalid coverage source or digest", "SELECT 1 FROM coverage c LEFT JOIN source_receipts s USING (stream_key)
                WHERE s.stream_key IS NULL OR c.tenant_id <> s.tenant_id OR c.revision = 0
                OR c.revision > s.coverage_revision OR sha256(c.report) <> lower(hex(c.report_sha256))"),
            ("invalid coverage receipt", "SELECT 1 FROM source_receipts s WHERE s.coverage_revision <>
                COALESCE((SELECT MAX(c.revision) FROM coverage c WHERE c.stream_key = s.stream_key), 0)"),
            ("invalid expiry range", "SELECT 1 FROM expired_ranges x LEFT JOIN source_receipts s USING (stream_key)
                WHERE s.stream_key IS NULL OR x.tenant_id <> s.tenant_id OR x.first_cursor = 0 OR x.segment_id = 0
                OR x.segment_id >= (SELECT next_segment_id FROM store_meta)
                OR x.last_cursor < x.first_cursor OR x.last_cursor > s.contiguous_cursor
                OR EXISTS (SELECT 1 FROM expired_ranges y WHERE y.stream_key = x.stream_key
                    AND y.first_cursor > x.first_cursor AND y.first_cursor <= x.last_cursor)"),
            ("invalid result body", "SELECT 1 FROM analysis_results WHERE octet_length(tenant_id) <> 16
                OR result_id = '' OR length(result_id) > 256 OR processor_id = ''
                OR octet_length(body) = 0 OR octet_length(body) > 16777216 OR sha256(body) <> lower(hex(body_sha256))
                OR octet_length(request_sha256) <> 32"),
            ("invalid witness reference", "SELECT 1 FROM evidence_refs r
                LEFT JOIN analysis_results a ON a.result_id = r.ref_id AND a.tenant_id = r.tenant_id
                LEFT JOIN segments e ON e.segment_id = r.segment_id AND e.state = 'Live'
                    AND e.stream_key = r.stream_key AND e.tenant_id = r.tenant_id
                WHERE a.result_id IS NULL OR e.segment_id IS NULL OR r.expires_utc_ns = 0
                    OR r.durable_cursor = 0"),
            ("invalid context reference", "SELECT 1 FROM context_refs r
                LEFT JOIN analysis_results a ON a.result_id = r.ref_id AND a.tenant_id = r.tenant_id
                LEFT JOIN context_versions c ON c.tenant_id = r.tenant_id AND c.owner_id = r.owner_id
                    AND c.entity_key = r.entity_key AND c.lifetime_key = r.lifetime_key
                    AND c.owner_revision = r.owner_revision AND c.content_sha256 = r.content_sha256
                WHERE a.result_id IS NULL OR c.owner_id IS NULL"),
            ("invalid processor progress", "SELECT 1 FROM processor_progress p
                LEFT JOIN source_receipts s ON s.stream_key = p.stream_key AND s.tenant_id = p.tenant_id
                WHERE p.class NOT IN ('required', 'optional') OR p.processor_id = '' OR p.method_version = 0
                OR octet_length(p.tenant_id) <> 16 OR octet_length(p.stream_key) <> 32
                OR p.start_cursor = 0 OR p.required_floor <> p.consumed_cursor
                OR p.consumed_cursor > COALESCE(s.contiguous_cursor, 0)
                OR p.resume_floor > COALESCE(s.contiguous_cursor, 0)
                OR p.coverage_revision > COALESCE(s.coverage_revision, 0)
                OR p.context_revision > (SELECT commit_revision FROM store_meta)"),
            ("invalid processor retirement", "SELECT 1 FROM processor_progress p
                LEFT JOIN source_receipts s ON s.stream_key = p.stream_key AND s.tenant_id = p.tenant_id
                WHERE (NOT p.retired AND (p.retirement_id <> '' OR p.retirement_reason <> ''
                    OR p.retirement_cursor <> 0 OR p.retirement_revision <> 0))
                OR (p.retired AND (p.class <> 'required'
                    OR NOT regexp_full_match(p.retirement_id, '[A-Za-z0-9_.:-]{1,128}')
                    OR trim(p.retirement_reason) = '' OR octet_length(encode(p.retirement_reason)) > 512
                    OR p.retirement_cursor < p.consumed_cursor
                    OR p.retirement_cursor > COALESCE(s.contiguous_cursor, 0)
                    OR p.retirement_revision = 0
                    OR p.retirement_revision > (SELECT commit_revision FROM store_meta)
                    OR p.retirement_revision > COALESCE((SELECT last_changed_revision
                        FROM relation_revisions WHERE relation_name = 'processor_progress'), 0)
                    OR (p.retirement_cursor > p.consumed_cursor AND NOT EXISTS (
                        SELECT 1 FROM processor_gaps g WHERE g.processor_id = p.processor_id
                            AND g.method_version = p.method_version AND g.tenant_id = p.tenant_id
                            AND g.stream_key = p.stream_key
                            AND g.first_cursor::HUGEINT = p.consumed_cursor::HUGEINT + 1
                            AND g.last_cursor = p.retirement_cursor
                            AND g.commit_revision = p.retirement_revision))))"),
            ("invalid processor gap", "SELECT 1 FROM processor_gaps g LEFT JOIN processor_progress p
                ON p.processor_id = g.processor_id AND p.method_version = g.method_version
                    AND p.tenant_id = g.tenant_id AND p.stream_key = g.stream_key
                WHERE p.processor_id IS NULL OR g.first_cursor = 0 OR g.last_cursor < g.first_cursor
                    OR (p.class = 'optional' AND g.last_cursor > p.resume_floor)
                    OR (p.class = 'required' AND (NOT p.retired
                        OR g.first_cursor::HUGEINT <> p.consumed_cursor::HUGEINT + 1
                        OR g.last_cursor <> p.retirement_cursor
                        OR g.commit_revision <> p.retirement_revision))"),
            ("invalid recovery gap", "SELECT 1 FROM recovery_gaps WHERE octet_length(stream_key) <> 32
                OR octet_length(tenant_id) <> 16 OR first_cursor = 0 OR last_cursor < first_cursor"),
        ];
        for (reason, query) in checks {
            let invalid: bool = writer
                .query_row(&format!("SELECT EXISTS ({query})"), [], |row| row.get(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "validate retained state",
                })?;
            if invalid {
                return Self::reject_path(root, reason);
            }
        }
        for (relation, notice) in [
            ("coverage", "coverage"),
            ("context_versions", "context_versions"),
            ("analysis_results", "analysis_results"),
            ("processor_gaps", "processor_gaps"),
            ("recovery_gaps", "recovery_gaps"),
            ("expired_ranges", "expired_ranges"),
        ] {
            let invalid: bool = writer.query_row(&format!(
                "SELECT EXISTS (SELECT 1 FROM {relation} WHERE commit_revision = 0 OR commit_revision > ?
                    OR commit_revision > COALESCE((SELECT last_changed_revision FROM relation_revisions
                        WHERE relation_name = ?), 0))"),
                params![meta.commit_revision, notice], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "validate committed revisions" })?;
            if invalid {
                return Self::reject_path(root, "the stored relation revision is invalid");
            }
        }
        let invalid: bool = writer.query_row(
            "SELECT EXISTS (SELECT 1 FROM relation_revisions WHERE last_changed_revision = 0 OR last_changed_revision > ?)
                OR EXISTS (SELECT 1 FROM store_meta WHERE next_segment_id = 0)",
            params![meta.commit_revision], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate revision and pending bounds" })?;
        if invalid {
            return Self::reject_path(root, "the stored revision or pending bound is invalid");
        }
        Self::validate_usage(writer, root)?;
        Ok(())
    }

    fn validate_contexts(writer: &Connection, root: &Path) -> Result<()> {
        let mut after = -1_i64;
        loop {
            let mut statement = writer
                .prepare(
                    "SELECT rowid, tenant_id, owner_id, entity_key, lifetime_key, owner_revision
                FROM context_versions WHERE rowid > ? ORDER BY rowid LIMIT 256",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare context validation",
                })?;
            let rows = statement
                .query_map(params![after], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read validation contexts",
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode validation contexts",
                })?;
            if rows.is_empty() {
                break;
            }
            for (position, tenant, owner_id, entity_key, lifetime_key, owner_revision) in rows {
                let tenant_id = tenant.try_into().map_err(|_| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the stored context tenant is invalid",
                    }
                    .build()
                })?;
                let key = super::AnalysisContextKeyV1 {
                    tenant_id,
                    owner_id,
                    entity_key,
                    lifetime_key,
                    owner_revision,
                };
                if Self::read_context_from(writer, root, &key)?.is_none() {
                    return Self::reject_path(root, "the stored context version is absent");
                }
                after = position;
            }
        }
        Ok(())
    }

    fn validate_sources(writer: &Connection, root: &Path) -> Result<()> {
        let mut after = Vec::new();
        loop {
            let mut statement = writer
                .prepare(
                    "SELECT stream_key, identity_json FROM source_receipts
                WHERE stream_key > ? ORDER BY stream_key LIMIT 256",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare receipt validation",
                })?;
            let rows = statement
                .query_map(params![after], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read validation receipts",
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode validation receipts",
                })?;
            if rows.is_empty() {
                break;
            }
            for (key, json) in rows {
                let identity: EvidenceIntakeIdentityV1 =
                    serde_json::from_str(&json).context(JsonSnafu {
                        path: root.join("analysis.duckdb"),
                    })?;
                if !valid_source_identity(&identity) || key != source_key(&identity) {
                    return Self::reject_path(root, "the stored source identity or key is invalid");
                }
                let receipt =
                    Self::read_receipt_from(writer, root, &identity, &source_key(&identity))?
                        .ok_or_else(|| {
                            crate::AnalysisStateSnafu {
                                path: root,
                                reason: "the stored receipt is absent",
                            }
                            .build()
                        })?;
                if receipt.retained_floor > receipt.contiguous_cursor {
                    return Self::reject_path(root, "the retained floor exceeds accepted evidence");
                }
                let binding: Option<(Vec<u8>, Vec<u8>, u64)> = writer.query_row(
                    "SELECT tenant_id, node_boot_id, label_epoch FROM source_bindings WHERE epoch_key = ?",
                    params![identity.epoch_key().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                ).optional().context(AnalysisDatabaseSnafu { operation: "validate source binding" })?;
                if binding
                    != Some((
                        identity.tenant_id.to_vec(),
                        identity.node_boot_id.to_vec(),
                        identity.label_epoch,
                    ))
                {
                    return Self::reject_path(
                        root,
                        "the stored source has no matching epoch binding",
                    );
                }
                after = key;
            }
        }
        let counts: (u64, u64) = writer.query_row(
            "SELECT (SELECT COUNT(*) FROM source_receipts), (SELECT COUNT(*) FROM source_bindings)",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "validate binding count" })?;
        if counts.0 > MAX_SOURCES || counts.1 > MAX_SOURCES {
            return Self::reject_path(root, "the stored source count exceeds its limit");
        }
        if counts.0 != counts.1 {
            return Self::reject_path(root, "the stored epoch binding has no receipt");
        }
        Ok(())
    }

    pub(super) fn validate_tables(writer: &Connection) -> Result<()> {
        let projections = [
            "tenant_id, logical_bytes, coverage_count, context_count, result_count FROM tenant_usage",
            "singleton, store_uuid, schema_version, recovery_epoch, commit_revision FROM store_meta",
            "relation_name, last_changed_revision FROM relation_revisions",
            "stream_key, identity_json, tenant_id, cpu_id, contiguous_cursor, coverage_revision, retained_floor FROM source_receipts",
            "epoch_key, tenant_id, node_boot_id, label_epoch FROM source_bindings",
            "next_segment_id FROM store_meta",
            "segment_id, stream_key, tenant_id, identity_json, cpu_id, stream_kind, state, sealed, committed_end FROM segments",
            "stream_key, tenant_id, revision, report, report_sha256, commit_revision, ordinal FROM coverage",
            "tenant_id, owner_id, entity_key, lifetime_key, owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, content_sha256, commit_revision FROM context_versions",
            "processor_id, method_version, tenant_id, stream_key, class, consumed_cursor, resume_floor, coverage_revision, context_revision, start_cursor, required_floor, retired, retirement_id, retirement_reason, retirement_cursor, retirement_revision FROM processor_progress",
            "ref_id, tenant_id, stream_key, durable_cursor, expires_utc_ns, segment_id FROM evidence_refs",
            "ref_id, tenant_id, owner_id, entity_key, lifetime_key, owner_revision, content_sha256 FROM context_refs",
            "result_id, tenant_id, processor_id, body, body_sha256, request_sha256, commit_revision FROM analysis_results",
            "processor_id, method_version, tenant_id, stream_key, first_cursor, last_cursor, commit_revision FROM processor_gaps",
            "stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM recovery_gaps",
            "segment_id, stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM expired_ranges",
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
        if !crate::node_id_is_valid(node_id)
            || tenant_id == [0; 16]
            || source_id == [0; 16]
            || source_epoch == 0
        {
            return Self::reject_path(&self.root, "the source epoch lookup is invalid");
        }
        let raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        Ok(raw
            .sources
            .values()
            .map(|source| &source.receipt.identity)
            .find(|identity| {
                identity.tenant_id == tenant_id
                    && identity.node_id == node_id
                    && identity.source_id == source_id
                    && identity.source_epoch == source_epoch
            })
            .cloned())
    }

    pub(super) fn bind_source(
        writer: &duckdb::Transaction<'_>,
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
        let count: u64 = writer
            .query_row("SELECT COUNT(*) FROM source_bindings", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "check source count",
            })?;
        if count >= MAX_SOURCES {
            return crate::StorageCapacitySnafu {
                resource: "source bindings",
            }
            .fail();
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
        super::quota::UsageChange::from(256).apply(writer, &identity.tenant_id)?;
        Ok(true)
    }

    pub(super) fn file_digest(path: &Path) -> Result<[u8; 32]> {
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .context(IoSnafu { path })?;
        let metadata = input.metadata().context(IoSnafu { path })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Self::reject_path(path, "the digest input is not a private regular file");
        }
        let bound = metadata.len().checked_add(1).ok_or_else(|| {
            crate::AnalysisStateSnafu {
                path,
                reason: "the digest input size is invalid",
            }
            .build()
        })?;
        let mut input = input.take(bound);
        let mut total = 0;
        let mut digest = Sha256::new();
        let mut chunk = [0_u8; 1024 * 1024];
        loop {
            let bytes = input.read(&mut chunk).context(IoSnafu { path })?;
            if bytes == 0 {
                break;
            }
            total += bytes as u64;
            digest.update(&chunk[..bytes]);
        }
        if total != metadata.len() {
            return Self::reject_path(path, "the digest input changed size during read");
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
    fn analysis_source_count_bound() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut writer = store.writer()?;
        let transaction = writer.get_mut()?.transaction()?;
        // These count-only rows remain inside an uncommitted test transaction.
        transaction.execute(
            "INSERT INTO source_bindings
            SELECT encode(md5(i::VARCHAR)), ?, ?, 1 FROM range(?::BIGINT) t(i)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                MAX_SOURCES - 1
            ],
        )?;
        let mut identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "n".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        assert!(AnalysisStore::bind_source(
            &transaction,
            &store.root,
            &identity
        )?);
        assert!(!AnalysisStore::bind_source(
            &transaction,
            &store.root,
            &identity
        )?);
        identity.source_epoch = 2;
        assert!(matches!(
            AnalysisStore::bind_source(&transaction, &store.root, &identity),
            Err(crate::Error::StorageCapacity {
                resource: "source bindings",
                ..
            })
        ));
        assert_eq!(
            transaction.query_row("SELECT COUNT(*) FROM source_bindings", [], |row| row
                .get::<_, u64>(0))?,
            MAX_SOURCES
        );
        transaction.rollback()?;
        drop(writer);
        assert_eq!(store.meta()?.commit_revision, 0);
        Ok(())
    }

    #[test]
    fn analysis_rejects_broken_state() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let faults = [
            "UPDATE source_receipts SET contiguous_cursor = 2",
            "UPDATE source_receipts SET retained_floor = 2",
            "DELETE FROM source_receipts",
            "UPDATE source_bindings SET label_epoch = 9",
            "UPDATE segments SET cpu_id = 9",
            "UPDATE segments SET committed_end = committed_end + 1",
            "DELETE FROM segments",
            "UPDATE store_meta SET next_segment_id = 1",
            "UPDATE evidence_refs SET durable_cursor = 2",
            "UPDATE evidence_refs SET segment_id = segment_id + 1",
            "UPDATE evidence_refs SET tenant_id = 'foreign'::BLOB",
            "UPDATE context_refs SET content_sha256 = 'changed'::BLOB",
            "DELETE FROM context_versions",
            "UPDATE context_versions SET body = 'changed'::BLOB",
            "UPDATE processor_progress SET consumed_cursor = 2",
            "UPDATE analysis_results SET body = 'changed'::BLOB",
            "UPDATE relation_revisions SET last_changed_revision = 99",
            "UPDATE store_meta SET recovery_epoch = 0",
        ];
        for fault in faults {
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
            let scope = crate::ProcessorScopeV1 {
                processor_id: "required".into(),
                method_version: 1,
                identity: identity.clone(),
            };
            store.register_processor(&scope, crate::ProcessorClassV1::Required, 1)?;
            store.accept_validated_batch(
                identity.clone(),
                crate::ValidatedEvidenceBatchV1 {
                    cpu_id: 1,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1,
                    framed_records: prost::bytes::Bytes::from_static(b"frame"),
                    frame_ends: vec![5],
                },
            )?;
            let context = crate::AnalysisContextVersionV1 {
                key: crate::AnalysisContextKeyV1 {
                    tenant_id: identity.tenant_id,
                    owner_id: "policy".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![2],
                    owner_revision: 1,
                },
                valid_from_utc_ns: Some(1),
                valid_until_utc_ns: None,
                sensitivity: crate::ContextSensitivityV1::Tenant,
                body: b"policy".to_vec(),
            };
            let revision = store.commit_context(&context)?;
            store.commit_result(&crate::AnalysisResultCommitV1 {
                scope,
                expected_cursor: 0,
                consumed_cursor: 1,
                coverage_revision: 0,
                context_revision: revision,
                result_id: "result".into(),
                body: b"result".to_vec(),
                created_utc_ns: 2,
                witnesses: vec![crate::AnalysisWitnessV1 {
                    identity,
                    cursor: 1,
                    expires_utc_ns: 3,
                }],
                context_refs: vec![crate::AnalysisContextRefV1 {
                    content_sha256: context.content_digest()?,
                    key: context.key,
                }],
            })?;
            drop(store);
            let store = AnalysisStore::open(&root)?;
            store.writer()?.get()?.execute_batch(fault)?;
            drop(store);
            assert!(AnalysisStore::open(&root).is_err(), "accepted {fault}");
        }
        Ok(())
    }

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
        let _readers = store.read_slots.try_acquire_many(16)?;
        assert_eq!(lookup()?, None);
        assert!(store.source_receipt(&identity)?.is_none());
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
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        assert!(matches!(
            store.source_status(&identity),
            Err(crate::Error::AnalysisBusy {
                resource: "reader",
                ..
            })
        ));
        assert_eq!(
            store.source_binding([4; 16], &identity.node_id, identity.source_id, 9)?,
            None
        );
        store.writer()?.get()?.execute(
            "UPDATE source_bindings SET node_boot_id = ? WHERE epoch_key = ?",
            params![[5_u8; 16].as_slice(), identity.epoch_key().as_slice()],
        )?;
        assert_eq!(lookup()?, Some(identity.clone()));
        assert!(AnalysisStore::validate_sources(store.writer()?.get()?, &store.root).is_err());
        Ok(())
    }

    #[test]
    fn analysis_rejects_older_schema() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store
            .writer()?
            .get()?
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
    fn analysis_rejects_missing_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        store.accept_validated_batch(
            identity.clone(),
            super::super::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: vec![7].into(),
                frame_ends: vec![1],
            },
        )?;
        let scope = crate::ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, crate::ProcessorClassV1::Required, 1)?;
        let health = store.processor_health(&scope)?.ok_or("health absent")?;
        let meta = store.meta()?;
        let records = store.read_page(&identity, 1)?.records;
        drop(store);
        let database = root.join("analysis.duckdb");
        let saved = directory.path().join("saved.duckdb");
        std::fs::rename(&database, &saved)?;
        for _ in 0..2 {
            assert!(matches!(
                AnalysisStore::open(&root),
                Err(crate::Error::AnalysisState { reason, .. })
                    if reason == "the analysis metadata is missing from a nonempty data directory"
            ));
            assert!(!database.exists());
        }
        std::fs::rename(&saved, &database)?;
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?, meta);
        assert_eq!(store.read_page(&identity, 1)?.records, records);
        assert_eq!(store.processor_health(&scope)?, Some(health));
        Ok(())
    }

    #[test]
    fn analysis_rejects_missing_table() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store
            .writer()?
            .get()?
            .execute("ALTER TABLE segments RENAME TO missing_segments", [])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
        let writer = Connection::open(root.join("analysis.duckdb"))?;
        assert!(writer.prepare("SELECT * FROM segments").is_err());
        assert!(writer.prepare("SELECT * FROM missing_segments").is_ok());
        Ok(())
    }
}
