use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{
    AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, GraphInvalidSnafu, JsonSnafu, Result,
};

const MAX_SOURCES: u64 = 4096;

impl EvidenceIntakeIdentityV1 {
    pub(crate) const MAX_KEY_BYTES: usize = 67 + crate::MAX_NODE_ID_BYTES;

    pub fn exact_key(&self) -> Vec<u8> {
        self.key()
    }

    pub(crate) fn valid(&self) -> bool {
        crate::node_id_is_valid(&self.node_id)
            && self.tenant_id != [0; 16]
            && self.node_boot_id != [0; 16]
            && self.source_id != [0; 16]
            && self.label_epoch != 0
            && self.source_epoch != 0
    }

    pub(crate) fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(67 + self.node_id.len());
        key.push(0);
        key.extend_from_slice(&self.tenant_id);
        key.extend_from_slice(&self.node_boot_id);
        key.extend_from_slice(&self.source_id);
        key.extend_from_slice(&self.label_epoch.to_be_bytes());
        key.extend_from_slice(&self.source_epoch.to_be_bytes());
        key.extend_from_slice(&(self.node_id.len() as u16).to_be_bytes());
        key.extend_from_slice(self.node_id.as_bytes());
        key
    }

    pub(super) fn epoch_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(42 + self.node_id.len());
        key.extend_from_slice(&self.tenant_id);
        key.extend_from_slice(&(self.node_id.len() as u16).to_be_bytes());
        key.extend_from_slice(self.node_id.as_bytes());
        key.extend_from_slice(&self.source_id);
        key.extend_from_slice(&self.source_epoch.to_be_bytes());
        key
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
        Self::validate_traces(writer, root)?;
        Self::validate_trace_receipts(writer, root)?;
        let graph_limit = if meta.schema_version == super::ANALYSIS_SCHEMA_VERSION as u32 {
            super::graph_rows::GraphHeader::MAX_BYTES
        } else {
            super::MAX_RESULT_BYTES
        };
        let oversized: bool = writer.query_row(
            "SELECT EXISTS(SELECT 1 FROM analysis_results
            WHERE processor_id = 'graph-findings' AND stream_key IS NOT NULL AND octet_length(body) > ?)",
            params![graph_limit as u64], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate graph header size" })?;
        if oversized {
            return Self::reject_path(root, "the stored graph header size is invalid");
        }
        let checks = [
            ("invalid source key", "SELECT 1 FROM source_receipts WHERE octet_length(stream_key) NOT BETWEEN 68 AND 195"),
            ("invalid segment identity or state", "SELECT 1 FROM segments e
                LEFT JOIN (SELECT stream_key, tenant_id, identity_json, cpu_id, 'records' AS kind FROM source_receipts
                    UNION ALL SELECT stream_key, tenant_id, identity_json, NULL, 'diagnostic' FROM trace_receipts) s USING (stream_key)
                WHERE e.segment_id = 0 OR e.segment_id >= (SELECT next_segment_id FROM store_meta)
                OR e.state NOT IN ('Live', 'Deleting') OR e.stream_kind <> s.kind
                OR e.committed_end < 70 OR e.committed_end > 16777216
                OR s.stream_key IS NULL OR e.tenant_id <> s.tenant_id
                OR e.cpu_id IS DISTINCT FROM s.cpu_id OR e.identity_json <> s.identity_json"),
            ("invalid coverage source or size", "SELECT 1 FROM coverage c LEFT JOIN source_receipts s USING (stream_key)
                WHERE s.stream_key IS NULL OR c.tenant_id <> s.tenant_id OR c.revision = 0
                OR c.revision > s.coverage_revision OR octet_length(c.report) = 0
                OR octet_length(c.report) > 4194304"),
            ("invalid coverage receipt", "SELECT 1 FROM source_receipts s WHERE s.coverage_revision <>
                COALESCE((SELECT MAX(c.revision) FROM coverage c WHERE c.stream_key = s.stream_key), 0)"),
            ("invalid expiry range", "SELECT 1 FROM expired_ranges x LEFT JOIN (
                SELECT stream_key, tenant_id, contiguous_cursor FROM source_receipts UNION ALL
                SELECT stream_key, tenant_id, last_sequence + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END FROM trace_receipts
                ) s USING (stream_key)
                WHERE s.stream_key IS NULL OR x.tenant_id <> s.tenant_id OR x.first_cursor = 0 OR x.segment_id = 0
                OR x.segment_id >= (SELECT next_segment_id FROM store_meta)
                OR x.last_cursor < x.first_cursor OR x.last_cursor > s.contiguous_cursor
                OR EXISTS (SELECT 1 FROM expired_ranges y WHERE y.stream_key = x.stream_key
                    AND y.first_cursor > x.first_cursor AND y.first_cursor <= x.last_cursor)"),
            ("invalid replay floor", "SELECT 1 FROM replay_floors f
                WHERE octet_length(f.tenant_id) <> 16 OR f.commit_revision = 0
                OR f.commit_revision >= COALESCE((SELECT MAX(x.commit_revision)
                    FROM expired_ranges x WHERE x.tenant_id = f.tenant_id), 0)
                UNION ALL SELECT 1 FROM expired_ranges x
                WHERE NOT EXISTS (SELECT 1 FROM replay_floors f WHERE f.tenant_id = x.tenant_id)"),
            ("invalid result body", "SELECT 1 FROM analysis_results WHERE octet_length(tenant_id) <> 16
                OR result_id = '' OR length(result_id) > 256 OR processor_id = ''
                OR octet_length(body) = 0 OR (octet_length(body) > 16777216
                    AND (processor_id <> 'graph-findings' OR stream_key IS NULL))
                OR octet_length(request_meta) = 0 OR octet_length(request_meta) > 16777216"),
            ("invalid profile header", "SELECT 1 FROM analysis_results
                WHERE (stream_key IS NULL AND (method_version IS NOT NULL OR interval_id IS NOT NULL
                    OR profile_revision IS NOT NULL OR facts_revision IS NOT NULL
                    OR coverage_revision IS NOT NULL OR first_cursor IS NOT NULL))
                OR (stream_key IS NOT NULL AND (processor_id NOT IN ('discovery', 'graph-findings')
                    OR octet_length(stream_key) NOT BETWEEN 68 AND 195
                    OR method_version IS NULL OR method_version = 0
                    OR interval_id IS NULL OR interval_id = '' OR length(interval_id) > 256
                    OR (processor_id = 'discovery' AND (profile_revision IS NULL OR profile_revision = 0))
                    OR (processor_id = 'graph-findings' AND (profile_revision IS NOT NULL
                        OR interval_id <> first_cursor::VARCHAR))
                    OR facts_revision IS NULL OR coverage_revision IS NULL OR first_cursor IS NULL))"),
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
                    AND c.owner_revision = r.owner_revision AND c.commit_revision = r.commit_revision
                WHERE a.result_id IS NULL OR c.owner_id IS NULL OR r.commit_revision = 0"),
            ("invalid processor result", "SELECT 1 FROM processor_progress p
                LEFT JOIN analysis_results r ON r.tenant_id = p.tenant_id AND r.result_id = p.result_id
                WHERE length(p.result_id) > 256
                    OR (p.result_id <> '' AND (r.result_id IS NULL OR r.processor_id <> p.processor_id))"),
            ("invalid processor progress", "SELECT 1 FROM processor_progress p
                LEFT JOIN source_receipts s ON s.stream_key = p.stream_key AND s.tenant_id = p.tenant_id
                WHERE p.class NOT IN ('required', 'optional') OR p.processor_id = '' OR p.method_version = 0
                OR octet_length(p.tenant_id) <> 16 OR octet_length(p.stream_key) NOT BETWEEN 68 AND 195
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
            ("invalid recovery gap", "SELECT 1 FROM recovery_gaps WHERE octet_length(stream_key) NOT BETWEEN 68 AND 195
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
            ("replay_floors", "replay_floors"),
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
                OR EXISTS (SELECT 1 FROM store_meta WHERE next_segment_id = 0)
                OR EXISTS (SELECT 1 FROM replay_floors WHERE ordinal >= ?)",
            params![meta.commit_revision, crate::MAX_EVIDENCE_BATCH_RECORDS as u64], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "validate revision and pending bounds" })?;
        if invalid {
            return Self::reject_path(root, "the stored revision or pending bound is invalid");
        }
        Self::validate_usage(writer, root)?;
        if meta.schema_version == super::ANALYSIS_SCHEMA_VERSION as u32 {
            Self::validate_encoding(writer, root)?;
            Self::validate_graphs(writer, root)?;
        }
        Ok(())
    }

    fn validate_encoding(writer: &Connection, root: &Path) -> Result<()> {
        let invalid: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM analysis_results
                WHERE (processor_id = 'graph-findings' AND stream_key IS NOT NULL
                    AND graph_encoding IS NULL)
                OR ((processor_id <> 'graph-findings' OR stream_key IS NULL)
                    AND graph_encoding IS NOT NULL)
                OR octet_length(graph_encoding) > ?)",
                params![super::graph_rows::GraphRows::MAX_ENCODING as u64],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate retained graph encoding",
            })?;
        if invalid {
            return Self::reject_path(root, "the stored graph encoding is invalid");
        }
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
                if !identity.valid() || key != identity.key() {
                    return Self::reject_path(root, "the stored source identity or key is invalid");
                }
                let receipt =
                    Self::read_receipt_from(writer, root, &identity, &key)?.ok_or_else(|| {
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
        let mut statement = writer
            .prepare(
                "SELECT stream_key, tenant_id FROM processor_progress
             UNION ALL SELECT stream_key, tenant_id FROM recovery_gaps",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare source key validation",
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read source keys",
            })?;
        for row in rows {
            let (key, tenant) = row.context(AnalysisDatabaseSnafu {
                operation: "decode source key",
            })?;
            if key.first() != Some(&0)
                || !super::raw::RawIdentity::valid_key(&key)
                || &key[1..17] != tenant.as_slice()
            {
                return Self::reject_path(root, "the stored source key or tenant is invalid");
            }
        }
        Ok(())
    }

    fn validate_trace_receipts(writer: &Connection, root: &Path) -> Result<()> {
        let invalid: bool = writer.query_row(
            "SELECT (SELECT COUNT(*) FROM trace_receipts) > 1024 OR EXISTS (
             SELECT 1 FROM trace_receipts WHERE octet_length(stream_key) <> 33 OR octet_length(tenant_id) <> 16
             OR octet_length(encode(identity_json)) > 4096 OR octet_length(encode(terminal)) > 4096
             OR last_sequence > 4096 OR output_bytes > 16777216 OR output_bytes < last_sequence
             OR retained_floor > last_sequence + CASE WHEN terminal IS NULL THEN 0 ELSE 1 END
             OR commit_revision > (SELECT commit_revision FROM store_meta)
             OR ((last_sequence > 0 OR terminal IS NOT NULL) AND commit_revision = 0))", [], |row| row.get(0)
        ).context(AnalysisDatabaseSnafu { operation: "validate diagnostic receipt bounds" })?;
        if invalid {
            return Self::reject_path(root, "the stored diagnostic receipt bounds are invalid");
        }
        let mut statement = writer.prepare("SELECT stream_key, tenant_id, identity_json, last_sequence, output_bytes, terminal FROM trace_receipts")
            .context(AnalysisDatabaseSnafu { operation: "prepare diagnostic receipt validation" })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read diagnostic receipt validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read diagnostic validation row",
        })? {
            let key: Vec<u8> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic source key",
            })?;
            let tenant: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic source tenant",
            })?;
            let json: String = row.get(2).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic source identity",
            })?;
            let identity: crate::TraceIdentityV1 = serde_json::from_str(&json).map_err(|_| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the stored diagnostic identity is invalid",
                }
                .build()
            })?;
            let source = super::raw::RawIdentity::Diagnostic(identity.clone());
            if !source.valid() || key != source.key() || tenant != identity.tenant_id {
                return Self::reject_path(root, "the diagnostic receipt identity differs");
            }
            let (_, intent) =
                Self::read_trace_intent(writer, root, identity.tenant_id, identity.request_id)?
                    .ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the diagnostic intent is absent",
                        }
                        .build()
                    })?;
            if !intent
                .bindings
                .iter()
                .any(|binding| binding.identity == identity)
            {
                return Self::reject_path(root, "the diagnostic receipt has no admitted binding");
            }
            let last: u64 = row.get(3).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic last sequence",
            })?;
            let bytes: u64 = row.get(4).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic output bytes",
            })?;
            let terminal: Option<String> = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "read diagnostic lifecycle",
            })?;
            if let Some(json) = terminal {
                let terminal: crate::TraceTerminalV1 =
                    serde_json::from_str(&json).map_err(|_| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the stored diagnostic terminal is invalid",
                        }
                        .build()
                    })?;
                if terminal.validate().is_err()
                    || terminal.execution_id != identity.execution_id
                    || terminal.last_sequence != last
                    || terminal.output_bytes != bytes
                    || serde_json::to_string(&terminal).context(JsonSnafu { path: root })? != json
                {
                    return Self::reject_path(
                        root,
                        "the diagnostic terminal differs from its receipt",
                    );
                }
            } else if last == 0 && bytes != 0 {
                return Self::reject_path(root, "the empty diagnostic receipt has output bytes");
            }
        }
        let mut statement =
            writer
                .prepare("SELECT bindings FROM traces")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare admitted diagnostic bindings",
                })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read admitted diagnostic bindings",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read admitted binding row",
        })? {
            let json: String = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "read stored diagnostic bindings",
            })?;
            let bindings: Vec<super::TraceBindingV1> =
                serde_json::from_str(&json).context(JsonSnafu { path: root })?;
            for binding in bindings {
                let source = super::raw::RawIdentity::Diagnostic(binding.identity);
                let present: bool = writer.query_row("SELECT EXISTS(SELECT 1 FROM trace_receipts WHERE stream_key = ? AND identity_json = ?)",
                    params![source.key().as_slice(), source.json(root)?], |row| row.get(0))
                    .context(AnalysisDatabaseSnafu { operation: "validate admitted diagnostic reservation" })?;
                if !present {
                    return Self::reject_path(root, "the admitted diagnostic receipt is absent");
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_tables(writer: &Connection) -> Result<()> {
        let projections = [
            "tenant_id, logical_bytes, coverage_count, context_count, result_count FROM tenant_usage",
            "singleton, store_uuid, schema_version, recovery_epoch, commit_revision FROM store_meta",
            "relation_name, last_changed_revision FROM relation_revisions",
            "stream_key, identity_json, tenant_id, cpu_id, contiguous_cursor, coverage_revision, retained_floor FROM source_receipts",
            "stream_key, identity_json, tenant_id, last_sequence, output_bytes, terminal, retained_floor, commit_revision FROM trace_receipts",
            "epoch_key, tenant_id, node_boot_id, label_epoch FROM source_bindings",
            "next_segment_id FROM store_meta",
            "segment_id, stream_key, tenant_id, identity_json, cpu_id, stream_kind, state, sealed, committed_end FROM segments",
            "stream_key, tenant_id, revision, report, commit_revision, ordinal FROM coverage",
            "tenant_id, owner_id, entity_key, lifetime_key, owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, commit_revision FROM context_versions",
            "processor_id, method_version, tenant_id, stream_key, class, consumed_cursor, resume_floor, coverage_revision, context_revision, start_cursor, required_floor, retired, retirement_id, retirement_reason, retirement_cursor, retirement_revision, result_id FROM processor_progress",
            "ref_id, tenant_id, stream_key, durable_cursor, expires_utc_ns, segment_id FROM evidence_refs",
            "ref_id, tenant_id, owner_id, entity_key, lifetime_key, owner_revision, commit_revision FROM context_refs",
            "result_id, tenant_id, processor_id, body, request_meta, commit_revision,
             stream_key, method_version, interval_id, profile_revision, facts_revision,
             coverage_revision, first_cursor FROM analysis_results",
            "processor_id, method_version, tenant_id, stream_key, first_cursor, last_cursor, commit_revision FROM processor_gaps",
            "stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM recovery_gaps",
            "segment_id, stream_key, tenant_id, first_cursor, last_cursor, commit_revision FROM expired_ranges",
            "tenant_id, commit_revision, ordinal FROM replay_floors",
            "tenant_id, request_id, source, source_sha256, bindings, authority, accepted_unix_ns, deadline_unix_ns, host_sensitive, revision, cancel_requested, read_revoked FROM traces",
        ];
        for projection in projections {
            writer
                .prepare(&format!("SELECT {projection} LIMIT 0"))
                .context(AnalysisDatabaseSnafu {
                    operation: "validate stored schema",
                })?;
        }
        let version: u32 = writer
            .query_row("SELECT schema_version FROM store_meta", [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read stored schema version",
            })?;
        if version == super::ANALYSIS_SCHEMA_VERSION as u32 {
            let encoding: bool = writer
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'main' AND table_name = 'analysis_results'
                    AND column_name = 'graph_encoding' AND data_type = 'BLOB'
                    AND is_nullable = 'YES')",
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "validate graph encoding schema",
                })?;
            if !encoding {
                return GraphInvalidSnafu {
                    field: "graph encoding schema",
                }
                .fail();
            }
            super::graph_rows::GraphRows::validate_tables(writer)?;
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
            .filter_map(|source| source.receipt.evidence().map(|receipt| &receipt.identity))
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
        super::quota::UsageChange::from(256 + key.len() as i64)
            .apply(writer, &identity.tenant_id)?;
        Ok(true)
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
    fn analysis_keys_preserve_identity() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        };
        let header = super::super::segment_file::SegmentFile::encode_identity(&identity)?;
        let key = identity.key();
        assert_eq!(key[0], 0);
        assert_eq!(&key[1..], &header[..header.len() - 4]);
        assert!(super::super::raw::RawIdentity::valid_key(&key));
        for changed in [
            EvidenceIntakeIdentityV1 {
                tenant_id: [4; 16],
                ..identity.clone()
            },
            EvidenceIntakeIdentityV1 {
                node_id: "node-b".into(),
                ..identity.clone()
            },
            EvidenceIntakeIdentityV1 {
                source_id: [4; 16],
                ..identity.clone()
            },
            EvidenceIntakeIdentityV1 {
                source_epoch: 2,
                ..identity.clone()
            },
        ] {
            assert_ne!(changed.key(), key);
            assert_ne!(changed.epoch_key(), identity.epoch_key());
        }
        for changed in [
            EvidenceIntakeIdentityV1 {
                node_boot_id: [4; 16],
                ..identity.clone()
            },
            EvidenceIntakeIdentityV1 {
                label_epoch: 2,
                ..identity.clone()
            },
        ] {
            assert_ne!(changed.key(), key);
            assert_eq!(changed.epoch_key(), identity.epoch_key());
        }
        for size in [1, 128] {
            let changed = EvidenceIntakeIdentityV1 {
                node_id: "n".repeat(size),
                ..identity.clone()
            };
            assert_eq!(changed.key().len(), 67 + size);
            assert!(super::super::raw::RawIdentity::valid_key(&changed.key()));
        }
        let mut invalid = key.clone();
        invalid[66] = 0;
        assert!(!super::super::raw::RawIdentity::valid_key(&invalid));
        assert!(!super::super::raw::RawIdentity::valid_key(
            &key[..key.len() - 1]
        ));
        assert!(!super::super::raw::RawIdentity::valid_key(&[1; 32]));
        Ok(())
    }

    #[test]
    fn analysis_keys_validate_orphans() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let scope = super::super::ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "n".repeat(128),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        };
        let key_bytes = scope.identity.key().len() as u64;
        assert_eq!(key_bytes, 195);
        let progress_bytes = 256 + scope.processor_id.len() as u64 + key_bytes;
        let store = AnalysisStore::open(&root)?;
        store.register_processor(&scope, super::super::ProcessorClassV1::Required, 1)?;
        assert_eq!(
            store.writer()?.get()?.query_row(
                "SELECT logical_bytes FROM tenant_usage",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            progress_bytes
        );
        store.record_recovery_floor(&scope.identity, 3)?;
        let total = progress_bytes + 256 + key_bytes;
        assert_eq!(
            store.writer()?.get()?.query_row(
                "SELECT logical_bytes FROM tenant_usage",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            total
        );
        store.record_recovery_floor(&scope.identity, 3)?;
        assert_eq!(
            store.writer()?.get()?.query_row(
                "SELECT logical_bytes FROM tenant_usage",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            total
        );
        assert!(store.source_receipt(&scope.identity)?.is_none());
        AnalysisStore::validate_usage(store.writer()?.get()?, &root)?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        let mut writer = store.writer()?;
        assert_eq!(
            writer
                .get()?
                .query_row("SELECT logical_bytes FROM tenant_usage", [], |row| {
                    row.get::<_, u64>(0)
                })?,
            total
        );
        AnalysisStore::validate_usage(writer.get()?, &root)?;
        AnalysisStore::validate_sources(writer.get()?, &root)?;
        for table in ["processor_progress", "recovery_gaps"] {
            let transaction = writer.get_mut()?.transaction()?;
            let mut invalid = scope.identity.key();
            invalid[66] = 0;
            transaction.execute(
                &format!("UPDATE {table} SET stream_key = ?"),
                params![invalid],
            )?;
            assert!(AnalysisStore::validate_sources(&transaction, &root).is_err());
            transaction.rollback()?;
            let transaction = writer.get_mut()?.transaction()?;
            transaction.execute(
                &format!("UPDATE {table} SET tenant_id = ?"),
                params![[4_u8; 16].as_slice()],
            )?;
            assert!(AnalysisStore::validate_sources(&transaction, &root).is_err());
            transaction.rollback()?;
        }
        Ok(())
    }

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
            "UPDATE context_refs SET lifetime_key = 'changed'::BLOB",
            "DELETE FROM context_versions",
            "UPDATE context_versions SET body = ''::BLOB",
            "UPDATE processor_progress SET consumed_cursor = 2",
            "UPDATE analysis_results SET body = ''::BLOB",
            "UPDATE analysis_results SET request_meta = ''::BLOB",
            "UPDATE context_refs SET commit_revision = commit_revision + 1",
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
                    identity: identity.into(),
                    cursor: 1,
                    expires_utc_ns: 3,
                }],
                context_refs: vec![crate::AnalysisContextRefV1 {
                    key: context.key,
                    commit_revision: revision,
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
    fn source_binding_preserves_identity() -> std::result::Result<(), Box<dyn std::error::Error>> {
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
