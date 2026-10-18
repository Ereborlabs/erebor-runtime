use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::{AnalysisReadControl, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, Result};

pub(super) const TRACE_RESERVE: u64 = 16 * 1024;
pub(super) const TRACE_CHARGES: &str = "SELECT tenant_id,
    256 + octet_length(source) + octet_length(encode(bindings)) + octet_length(authority) AS bytes FROM traces
    UNION ALL SELECT tenant_id, 256 + octet_length(stream_key) + octet_length(encode(identity_json))
        + CASE WHEN terminal IS NULL THEN 16 * 1024 ELSE octet_length(encode(terminal)) END FROM trace_receipts
    UNION ALL SELECT tenant_id, 256 + octet_length(stream_key) + committed_end + octet_length(encode(identity_json))
        FROM segments WHERE stream_kind = 'diagnostic'";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WitnessUsageV1 {
    pub read_revision: u64,
    pub referenced_bytes: u64,
    pub segment_bytes: u64,
    pub extra_segment_bytes: u64,
    pub context_bytes: u64,
    pub charged_bytes: u64,
}

impl TryFrom<&duckdb::Row<'_>> for WitnessUsageV1 {
    type Error = duckdb::Error;

    fn try_from(row: &duckdb::Row<'_>) -> duckdb::Result<Self> {
        Ok(Self {
            charged_bytes: row.get(0)?,
            segment_bytes: row.get(1)?,
            context_bytes: row.get(2)?,
            referenced_bytes: row.get(3)?,
            extra_segment_bytes: row.get(4)?,
            read_revision: row.get(5)?,
        })
    }
}

impl AnalysisStore {
    pub(super) fn reserve_trace(
        &self,
        transaction: &Transaction<'_>,
        intent: &super::TraceIntentV1,
    ) -> Result<()> {
        for binding in &intent.bindings {
            let identity = super::raw::RawIdentity::Diagnostic(binding.identity.clone());
            let key = identity.key();
            let json = identity.json(&self.root)?;
            let changed = transaction
                .execute(
                    "INSERT INTO trace_receipts VALUES (?, ?, ?, 0, 0, NULL, 0, 0)
                 ON CONFLICT DO NOTHING",
                    params![key.as_slice(), json, identity.tenant().as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "reserve diagnostic terminal state",
                })?;
            if changed != 1 {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        if self.storage.diagnostic_sources.is_some()
            || self.storage.tenant_diagnostic_sources.is_some()
        {
            let (total, scoped): (u64, u64) = transaction
                .query_row(
                    "SELECT COUNT(*)::UBIGINT,
                        COUNT(*) FILTER (WHERE tenant_id = ?)::UBIGINT FROM trace_receipts",
                    params![intent.tenant_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "count diagnostic sources",
                })?;
            self.storage.check_sources(
                usize::try_from(total)
                    .map_err(|_| self.state_error("the diagnostic source count overflows"))?,
                usize::try_from(scoped)
                    .map_err(|_| self.state_error("the tenant source count overflows"))?,
                true,
            )?;
        }
        if self.storage.logical_max_bytes.is_some() || self.storage.tenant_max_bytes.is_some() {
            let (total, scoped) = Self::diagnostic_usage(transaction, intent.tenant_id)?;
            self.storage.check_diagnostics(total, scoped)?;
        }
        let (reserved, slots) = Self::terminal_reserve(transaction)?;
        self.storage
            .check_append(self.storage_with_reserve(0, slots)?, reserved)
    }

    pub(super) fn diagnostic_usage(
        connection: &Connection,
        tenant: [u8; 16],
    ) -> Result<(u64, u64)> {
        connection
            .query_row(
                &format!(
                    "SELECT COALESCE(SUM(bytes), 0)::UBIGINT,
                COALESCE(SUM(bytes) FILTER (WHERE tenant_id = ?), 0)::UBIGINT
                FROM ({TRACE_CHARGES})"
                ),
                params![tenant.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count diagnostic logical bytes",
            })
    }

    pub(super) fn terminal_reserve(connection: &Connection) -> Result<(u64, usize)> {
        let (count, slots): (u64, u64) = connection.query_row(
            "SELECT COUNT(*)::UBIGINT,
                COALESCE(SUM(CASE WHEN EXISTS (SELECT 1 FROM segments s
                    WHERE s.stream_key = t.stream_key AND s.state = 'Live') THEN 1 ELSE 2 END), 0)::UBIGINT
                FROM trace_receipts t WHERE terminal IS NULL", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(AnalysisDatabaseSnafu { operation: "count diagnostic terminal reserves" })?;
        let bytes = count.checked_mul(TRACE_RESERVE).ok_or_else(|| {
            crate::StorageCapacitySnafu {
                resource: "diagnostic physical reserve",
            }
            .build()
        })?;
        let slots = usize::try_from(slots).map_err(|_| {
            crate::StorageCapacitySnafu {
                resource: "diagnostic storage entries",
            }
            .build()
        })?;
        Ok((bytes, slots))
    }

    const WITNESS_USAGE: &'static str = "WITH pins AS (
            SELECT DISTINCT segment_id FROM evidence_refs
            WHERE tenant_id = ? AND expires_utc_ns > ?
        ), usage AS (
            SELECT COALESCE((SELECT SUM(s.committed_end) FROM segments s
                SEMI JOIN pins p USING (segment_id) WHERE s.state = 'Live'), 0)::UBIGINT AS segments,
            COALESCE((SELECT SUM(256 + octet_length(c.body) + octet_length(encode(c.owner_id))
            + octet_length(c.entity_key) + octet_length(c.lifetime_key)) FROM context_versions c
            SEMI JOIN (
                SELECT tenant_id, owner_id, entity_key, lifetime_key, owner_revision
                FROM context_refs WHERE tenant_id = ?
            ) r USING (tenant_id, owner_id, entity_key, lifetime_key, owner_revision)), 0)::UBIGINT AS context
        ) SELECT segments + context, segments, context, 0::UBIGINT, segments,
            (SELECT commit_revision FROM store_meta) FROM usage";

    /// Count distinct live witnesses and their whole segments. This read does not pin data.
    pub fn witness_usage(&self, tenant: [u8; 16], now: u64) -> Result<WitnessUsageV1> {
        if tenant == [0; 16] || now == 0 {
            return self.reject("the witness usage tenant or time is invalid");
        }
        let control = AnalysisReadControl::default();
        let mut reader = self.reader_until(&control)?;
        control.run(&mut reader, |snapshot| {
            self.witness_totals(snapshot, tenant, now)
        })
    }

    pub(super) fn witness_base(
        connection: &Connection,
        tenant: [u8; 16],
        now: u64,
    ) -> Result<WitnessUsageV1> {
        connection
            .query_row(
                Self::WITNESS_USAGE,
                params![tenant.as_slice(), now, tenant.as_slice()],
                |row| WitnessUsageV1::try_from(row),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count exact witness storage",
            })
    }

    fn witness_totals(
        &self,
        connection: &Connection,
        tenant: [u8; 16],
        now: u64,
    ) -> Result<WitnessUsageV1> {
        let mut usage = Self::witness_base(connection, tenant, now)?;
        let mut statement = connection
            .prepare(
                "SELECT DISTINCT stream_key, durable_cursor, segment_id FROM evidence_refs
             WHERE tenant_id = ? AND expires_utc_ns > ? ORDER BY stream_key, durable_cursor",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare witness record sizes",
            })?;
        let rows = statement
            .query_map(params![tenant.as_slice(), now], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read witness record sizes",
            })?;
        let raw = self
            .raw
            .lock()
            .map_err(|_| self.state_error("the raw owner lock is poisoned"))?;
        let mut cached = None;
        for row in rows {
            let (key, cursor, segment) = row.context(AnalysisDatabaseSnafu {
                operation: "decode witness record size",
            })?;
            if !super::raw::RawIdentity::valid_key(&key) {
                return self.reject("the witness key is invalid");
            }
            let (entry, index) = raw.locate(&key, cursor, usage.read_revision)?;
            if entry.reference.id != segment {
                return self.reject("the witness segment differs");
            }
            if cached
                .as_ref()
                .is_none_or(|(revision, _)| *revision != entry.commit.revision)
            {
                cached = Some((entry.commit.revision, raw.read_entry(entry)?));
            }
            let span = &cached
                .as_ref()
                .ok_or_else(|| self.state_error("the witness batch is absent"))?
                .1
                .spans[index];
            let position = (cursor - span.first) as usize;
            let end = span.ends[position];
            let start = position.checked_sub(1).map_or(0, |prior| span.ends[prior]);
            usage.referenced_bytes += u64::from(end - start);
        }
        usage.extra_segment_bytes = usage
            .segment_bytes
            .checked_sub(usage.referenced_bytes)
            .ok_or_else(|| self.state_error("the witness byte count exceeds its segments"))?;
        Ok(usage)
    }

    const USAGE_CHARGES: &'static str = "
                    SELECT tenant_id, 'segments' AS family,
                        256 + octet_length(stream_key) + committed_end + octet_length(encode(identity_json)) AS bytes FROM segments
                    UNION ALL SELECT tenant_id, 'coverage',
                        256 + octet_length(stream_key) + octet_length(report) FROM coverage
                    UNION ALL SELECT tenant_id, 'receipts',
                        256 + octet_length(stream_key) + octet_length(encode(identity_json)) FROM source_receipts
                    UNION ALL SELECT tenant_id, 'bindings', 256 + octet_length(epoch_key) FROM source_bindings
                    UNION ALL SELECT tenant_id, 'context',
                        256 + octet_length(encode(owner_id)) + octet_length(entity_key)
                        + octet_length(lifetime_key) + octet_length(body) FROM context_versions
                    UNION ALL SELECT tenant_id, 'progress',
                        256 + octet_length(stream_key) + octet_length(encode(processor_id)) + octet_length(encode(retirement_id))
                        + octet_length(encode(retirement_reason)) + octet_length(encode(result_id)) FROM processor_progress
                    UNION ALL SELECT tenant_id, 'witnesses',
                        256 + octet_length(stream_key) + octet_length(encode(ref_id)) FROM evidence_refs
                    UNION ALL SELECT tenant_id, 'context_refs',
                        256 + octet_length(encode(ref_id)) + octet_length(encode(owner_id))
                        + octet_length(entity_key) + octet_length(lifetime_key) FROM context_refs
                    UNION ALL SELECT tenant_id, 'results',
                        256 + octet_length(encode(result_id)) + octet_length(encode(processor_id))
                        + octet_length(body) + octet_length(request_meta)
                        + COALESCE(octet_length(stream_key), 0)
                        + COALESCE(octet_length(encode(interval_id)), 0) FROM analysis_results
                    UNION ALL SELECT tenant_id, 'processor_gaps',
                        256 + octet_length(stream_key) + octet_length(encode(processor_id)) FROM processor_gaps
                    UNION ALL SELECT tenant_id, 'recovery_gaps', 256 + octet_length(stream_key) FROM recovery_gaps
                    UNION ALL SELECT tenant_id, 'expired_ranges', 256 + octet_length(stream_key) FROM expired_ranges
                    UNION ALL SELECT tenant_id, 'replay_floors', 256 FROM replay_floors
                    UNION ALL SELECT tenant_id, 'traces',
                        256 + octet_length(source) + octet_length(encode(bindings))
                        + octet_length(authority) FROM traces
                    UNION ALL SELECT tenant_id, 'trace_receipts',
                        256 + octet_length(stream_key) + octet_length(encode(identity_json))
                        + CASE WHEN terminal IS NULL THEN 16 * 1024
                            ELSE octet_length(encode(terminal)) END FROM trace_receipts";

    pub(super) fn usage_projection() -> String {
        let graphs = format!(
            " UNION ALL SELECT tenant_id, 'graph_rows', bytes FROM ({})
            UNION ALL SELECT tenant_id, 'package_rows', bytes FROM ({})",
            super::graph_rows::GraphRows::CHARGES,
            Self::PACKAGE_CHARGES,
        );
        format!(
            "WITH charges AS ({}{graphs}) SELECT tenant_id, SUM(bytes)::UBIGINT AS logical_bytes,
                    COUNT(*) FILTER (WHERE family = 'coverage')::UBIGINT AS coverage_count,
                    COUNT(*) FILTER (WHERE family = 'context')::UBIGINT AS context_count,
                    COUNT(*) FILTER (WHERE family = 'results')::UBIGINT AS result_count
                    FROM charges GROUP BY tenant_id",
            Self::USAGE_CHARGES
        )
    }

    pub(super) fn logical_usage(
        transaction: &Connection,
        tenant: [u8; 16],
    ) -> Result<(u64, u64, u64, u64)> {
        transaction
            .query_row(
                &format!(
                    "WITH usage AS ({}) SELECT COALESCE(SUM(logical_bytes), 0)::UBIGINT,
                    COALESCE(SUM(logical_bytes) FILTER (WHERE tenant_id = ?), 0)::UBIGINT,
                    GREATEST(COALESCE(SUM(coverage_count), 0), COALESCE(SUM(context_count), 0),
                        COALESCE(SUM(result_count), 0))::UBIGINT,
                    COALESCE(MAX(GREATEST(coverage_count, context_count, result_count))
                        FILTER (WHERE tenant_id = ?), 0)::UBIGINT FROM usage",
                    Self::usage_projection()
                ),
                params![tenant.as_slice(), tenant.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check retained logical quota",
            })
    }

    pub(super) fn check_logical(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        maintenance: bool,
    ) -> Result<()> {
        Self::check_logical_limits(transaction, self.storage, tenant, maintenance)
    }

    pub(super) fn check_logical_limits(
        transaction: &Transaction<'_>,
        storage: super::StorageLimitsV1,
        tenant: [u8; 16],
        maintenance: bool,
    ) -> Result<()> {
        if storage.logical_max_bytes.is_none()
            && storage.tenant_max_bytes.is_none()
            && storage.retained_revisions.is_none()
            && storage.tenant_revisions.is_none()
        {
            return Ok(());
        }
        let (total, scoped, revisions, tenant_revisions) =
            Self::logical_usage(transaction, tenant)?;
        storage.check_logical(total, scoped, maintenance)?;
        storage.check_revisions(revisions, tenant_revisions)
    }

    pub(super) fn logical_pressure(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
    ) -> Result<bool> {
        if self.storage.logical_max_bytes.is_none() && self.storage.tenant_max_bytes.is_none() {
            return Ok(false);
        }
        let (total, scoped, _, _) = Self::logical_usage(transaction, tenant)?;
        let pressure = |limit: u64, bytes| {
            let allowance = limit - limit / 4;
            bytes >= allowance - allowance / 10
        };
        Ok(self
            .storage
            .logical_max_bytes
            .is_some_and(|limit| pressure(limit, total))
            || self
                .storage
                .tenant_max_bytes
                .is_some_and(|limit| pressure(limit, scoped)))
    }

    pub(super) fn check_witnesses(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        now: u64,
    ) -> Result<()> {
        if self.storage.witness_max_bytes.is_none() {
            return Ok(());
        }
        let referenced: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM evidence_refs WHERE tenant_id = ? AND expires_utc_ns > ?)
                    OR EXISTS(SELECT 1 FROM context_refs WHERE tenant_id = ?)",
                params![tenant.as_slice(), now, tenant.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check tenant witness references",
            })?;
        if !referenced {
            return Ok(());
        }
        let usage = self.witness_totals(transaction, tenant, now)?;
        self.storage.check_witness(usage.charged_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
        AnalysisResultCommitV1, AnalysisWitnessV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
        ProcessorClassV1, ProcessorScopeV1, StorageLimitsV1, TraceBatchV1, TraceFrameKindV1,
        TraceFrameV1, ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn context(tenant: u8, revision: u64) -> AnalysisContextVersionV1 {
        AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [tenant; 16],
                owner_id: "p".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: revision,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        }
    }

    #[test]
    fn observability_terminal_pressure() -> TestResult {
        use super::super::raw::tests::{trace_intent, trace_terminal};

        for global in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let limits = StorageLimitsV1 {
                tenant_max_bytes: Some(1024 * 1024),
                logical_max_bytes: Some(if global { 1024 * 1024 } else { 2 * 1024 * 1024 }),
                ..Default::default()
            };
            let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
            let intent = trace_intent()?;
            let identity = &intent.bindings[0].identity;
            store.accept_trace(&intent)?;
            let tenants = if global { 2 } else { 1 };
            for tenant in 1..=tenants {
                let evidence = EvidenceIntakeIdentityV1 {
                    tenant_id: [tenant; 16],
                    node_id: "n".into(),
                    ..crate::analysis::tests::identity()
                };
                store.accept_validated_batch(
                    evidence.clone(),
                    ValidatedEvidenceBatchV1 {
                        cpu_id: 0,
                        first_cursor: 1,
                        last_cursor: 1,
                        intake_utc_ns: 100,
                        framed_records: b"frame".to_vec().into(),
                        frame_ends: vec![5],
                    },
                )?;
                let scope = ProcessorScopeV1 {
                    processor_id: "p".into(),
                    method_version: 1,
                    identity: evidence,
                };
                store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
                store.commit_result(&AnalysisResultCommitV1 {
                    body: vec![1; 800 * 1024 / usize::from(tenants)],
                    created_utc_ns: 101,
                    ..crate::analysis::tests::result(scope, format!("pressure-{tenant}"))
                })?;
            }
            {
                let reader = store.reader()?;
                let total: u64 = reader.get()?.query_row(
                    &format!(
                        "SELECT SUM(logical_bytes)::UBIGINT FROM ({})",
                        AnalysisStore::usage_projection()
                    ),
                    [],
                    |row| row.get(0),
                )?;
                let scoped: u64 = reader.get()?.query_row(
                    &format!(
                        "SELECT logical_bytes FROM ({}) WHERE tenant_id = ?",
                        AnalysisStore::usage_projection()
                    ),
                    params![identity.tenant_id.as_slice()],
                    |row| row.get(0),
                )?;
                assert!(
                    total < limits.logical_max_bytes.ok_or("configured logical limit")?
                        && scoped < limits.tenant_max_bytes.ok_or("configured tenant limit")?
                );
                assert_eq!(
                    total > limits.logical_max_bytes.ok_or("configured logical limit")? * 3 / 4,
                    global
                );
                assert_eq!(
                    scoped > limits.tenant_max_bytes.ok_or("configured tenant limit")? * 3 / 4,
                    !global
                );
            }
            let before = store.trace_receipt(identity)?.ok_or("receipt absent")?;
            let revision = store.meta()?;
            let resource = if global {
                "global logical bytes"
            } else {
                "tenant logical bytes"
            };
            let frame = TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![1],
            };
            for terminal in [None, Some(trace_terminal(1, 1))] {
                assert!(matches!(
                    store.append_trace(identity, &TraceBatchV1 {
                        execution_id: identity.execution_id,
                        frames: vec![frame.clone()],
                        terminal,
                    }, 102),
                    Err(crate::Error::StorageCapacity { resource: found, .. }) if found == resource
                ));
                assert_eq!(store.trace_receipt(identity)?, Some(before.clone()));
                assert_eq!(store.meta()?, revision);
            }
            assert_eq!(
                store
                    .raw
                    .lock()
                    .map_err(|_| "raw poisoned")?
                    .budget
                    .trace_reserve,
                TRACE_RESERVE
            );
            let batch = TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![],
                terminal: Some(trace_terminal(0, 0)),
            };
            let receipt = store.append_trace(identity, &batch, 103)?;
            assert_eq!((receipt.last_sequence, receipt.output_bytes), (0, 0));
            assert_eq!(receipt.terminal, batch.terminal);
            assert_eq!(store.append_trace(identity, &batch, 104)?, receipt);
            assert_eq!(
                store
                    .raw
                    .lock()
                    .map_err(|_| "raw poisoned")?
                    .budget
                    .trace_reserve,
                0
            );
            AnalysisStore::validate_state(store.reader()?.get()?, &root)?;
            drop(store);

            let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
            assert_eq!(store.trace_receipt(identity)?, Some(receipt.clone()));
            assert_eq!(store.append_trace(identity, &batch, 105)?, receipt);
            let output = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
            assert!(output.frames.is_empty());
            assert_eq!(output.terminal, batch.terminal);
            assert_eq!(
                store
                    .raw
                    .lock()
                    .map_err(|_| "raw poisoned")?
                    .budget
                    .trace_reserve,
                0
            );
            AnalysisStore::validate_state(store.reader()?.get()?, &root)?;
        }
        Ok(())
    }

    #[test]
    fn analysis_store_logical_limits() -> TestResult {
        for global in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let limits = StorageLimitsV1 {
                tenant_max_bytes: Some(346),
                logical_max_bytes: Some(if global { 346 } else { 8 * 1024 * 1024 * 1024 }),
                ..Default::default()
            };
            let store = AnalysisStore::open_with_limits(&root, Default::default(), limits)?;
            assert_eq!(store.commit_context(&context(1, 1))?, 1);
            let before = store.meta()?;
            let rejected = store.commit_context(&context(if global { 2 } else { 1 }, 2));
            assert!(matches!(
                rejected,
                Err(crate::Error::StorageCapacity { .. })
            ));
            assert_eq!(store.meta()?, before);
            assert_eq!(store.commit_context(&context(1, 1))?, 1);
            if !global {
                assert_eq!(store.commit_context(&context(2, 1))?, 2);
            }
            drop(store);
            let store = AnalysisStore::open_with_limits(root, Default::default(), limits)?;
            assert_eq!(
                store.context_version(&context(1, 1).key)?,
                Some(context(1, 1))
            );
            assert!(store.context_version(&context(1, 2).key)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn analysis_batch_charges() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
        };
        let mut cursor = 1;
        let mut previous = None;
        let mut previous_bytes = 0;
        for count in [1, 3, crate::MAX_EVIDENCE_BATCH_RECORDS] {
            let mut frames = Vec::new();
            let mut frame_ends = Vec::new();
            for index in 0..count {
                frames.extend(std::iter::repeat_n(1, index % 3 + 1));
                frame_ends.push(frames.len());
            }
            let batch = ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor + count as u64 - 1,
                intake_utc_ns: 1,
                framed_records: frames.into(),
                frame_ends,
            };
            store.accept_validated_batch(identity.clone(), batch.clone())?;
            store.accept_validated_batch(identity.clone(), batch)?;
            let physical =
                std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?.len();
            let mut writer = store.writer()?;
            let transaction = writer.get_mut()?.transaction()?;
            let usage = AnalysisStore::logical_usage(&transaction, identity.tenant_id)?;
            assert_eq!(usage.0, usage.1);
            assert_eq!((usage.2, usage.3), (0, 0));
            if let Some(prior) = previous {
                assert_eq!(usage.0 - prior, physical - previous_bytes);
            }
            previous_bytes = physical;
            assert!(transaction.prepare("SELECT * FROM batch_ranges").is_err());
            previous = Some(usage.0);
            cursor += count as u64;
        }
        drop(store);
        let store = AnalysisStore::open(root)?;
        let mut writer = store.writer()?;
        let transaction = writer.get_mut()?.transaction()?;
        assert_eq!(
            Some(AnalysisStore::logical_usage(&transaction, identity.tenant_id)?.0),
            previous
        );
        Ok(())
    }

    #[test]
    fn analysis_store_witness_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let mut store = AnalysisStore::open(&root)?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".repeat(128),
            ..crate::analysis::tests::identity()
        };
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let key_bytes = identity.key().len() as u64;
        let epoch_bytes = identity.epoch_key().len() as u64;
        let json_bytes = serde_json::to_vec(&identity)?.len() as u64;
        let file_bytes =
            std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?.len();
        assert_eq!((key_bytes, epoch_bytes), (195, 170));
        let raw_bytes = file_bytes + 768 + 2 * json_bytes + 2 * key_bytes + epoch_bytes;
        assert_eq!(
            AnalysisStore::logical_usage(store.writer()?.get()?, identity.tenant_id)?.0,
            raw_bytes
        );
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        assert_eq!(
            store.writer()?.get()?.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({})",
                    AnalysisStore::usage_projection()
                ),
                [],
                |row| row.get::<_, u64>(0),
            )?,
            raw_bytes + 256 + scope.processor_id.len() as u64 + key_bytes
        );
        let context = context(1, 1);
        let context_revision = store.commit_context(&context)?;
        let input = AnalysisResultCommitV1 {
            context_revision,
            body: vec![1],
            created_utc_ns: 2,
            witnesses: vec![AnalysisWitnessV1 {
                identity: identity.into(),
                cursor: 1,
                expires_utc_ns: 100,
            }],
            context_refs: vec![AnalysisContextRefV1 {
                commit_revision: context_revision,
                key: context.key,
            }],
            ..crate::analysis::tests::result(scope, "r".into())
        };
        let current_bytes = {
            let mut writer = store.writer()?;
            let transaction = writer.get_mut()?.transaction()?;
            AnalysisStore::logical_usage(&transaction, input.scope.identity.tenant_id)?.1
        };
        store.storage.tenant_max_bytes = Some(current_bytes);
        let before = store.meta()?;
        assert!(matches!(
            store.accept_validated_batch(
                input.scope.identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 2,
                    last_cursor: 2,
                    intake_utc_ns: 2,
                    framed_records: b"frame".to_vec().into(),
                    frame_ends: vec![5],
                }
            ),
            Err(crate::Error::StorageCapacity {
                resource: "tenant logical bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        let request_bytes = input.request_meta()?.len() as u64;
        let result_bytes = 776 + request_bytes + key_bytes + input.result_id.len() as u64;
        store.storage.tenant_max_bytes = Some(current_bytes + result_bytes - 1);
        assert!(matches!(
            store.commit_result(&input),
            Err(crate::Error::StorageCapacity {
                resource: "tenant logical bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        store.storage.tenant_max_bytes = Some(current_bytes + result_bytes);
        let witness_bytes = file_bytes + 260;
        store.storage.witness_max_bytes = Some(witness_bytes - 1);
        let before = store.meta()?;
        assert!(matches!(
            store.commit_result(&input),
            Err(crate::Error::StorageCapacity {
                resource: "tenant witness bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.read_result([1; 16], "r")?.is_none());
        store.storage.witness_max_bytes = Some(witness_bytes);
        let receipt = store.commit_result(&input)?;
        {
            let reader = store.reader()?;
            let stored_bytes: u64 = reader.get()?.query_row(
                "SELECT octet_length(request_meta) FROM analysis_results WHERE result_id = ?",
                params![input.result_id],
                |row| row.get(0),
            )?;
            assert_eq!(stored_bytes, request_bytes);
            let charged: u64 = reader.get()?.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({}) WHERE tenant_id = ?",
                    AnalysisStore::usage_projection()
                ),
                params![input.scope.identity.tenant_id.as_slice()],
                |row| row.get(0),
            )?;
            assert_eq!(charged, current_bytes + result_bytes);
            AnalysisStore::validate_state(reader.get()?, &store.root)?;
            let plan: String = reader.get()?.query_row(
                &format!("EXPLAIN {}", AnalysisStore::WITNESS_USAGE),
                params![[1_u8; 16].as_slice(), 2_u64, [1_u8; 16].as_slice()],
                |row| row.get(1),
            )?;
            assert!(
                !plan.contains("DELIM_JOIN"),
                "witness quota correlates each retained row:\n{plan}"
            );
        }
        assert_eq!(store.commit_result(&input)?, receipt);
        assert_eq!(
            store.writer()?.get()?.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({})",
                    AnalysisStore::usage_projection()
                ),
                [],
                |row| row.get::<_, u64>(0),
            )?,
            current_bytes + result_bytes
        );
        let mut second = input;
        second.expected_cursor = 1;
        second.result_id = "s".into();
        assert!(matches!(
            store.commit_result(&second),
            Err(crate::Error::StorageCapacity {
                resource: "tenant logical bytes",
                ..
            })
        ));
        store.storage.tenant_max_bytes = StorageLimitsV1::default().tenant_max_bytes;
        store.commit_result(&second)?;
        assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
        {
            let reader = store.reader()?;
            for (tenant, now, expected) in [(1_u8, 2_u64, witness_bytes), (1, 100, 260), (2, 2, 0)]
            {
                let bytes: u64 = reader.get()?.query_row(
                    AnalysisStore::WITNESS_USAGE,
                    params![[tenant; 16].as_slice(), now, [tenant; 16].as_slice()],
                    |row| row.get(0),
                )?;
                assert_eq!(bytes, expected);
                let usage = store.witness_usage([tenant; 16], now)?;
                assert_eq!(usage.charged_bytes, expected);
                assert_eq!(usage.context_bytes, if tenant == 1 { 260 } else { 0 });
                assert_eq!(
                    usage.referenced_bytes,
                    if tenant == 1 && now < 100 { 5 } else { 0 }
                );
                assert_eq!(
                    usage.segment_bytes + usage.context_bytes,
                    usage.charged_bytes
                );
                assert_eq!(
                    usage.referenced_bytes + usage.extra_segment_bytes,
                    usage.segment_bytes
                );
            }
        }
        for (tenant, now, expected) in [(1_u8, 2_u64, witness_bytes), (1, 100, 260), (2, 2, 0)] {
            for limit in [expected.saturating_sub(1), expected] {
                store.storage.witness_max_bytes = Some(limit);
                let mut writer = store.writer()?;
                let transaction = writer.get_mut()?.transaction()?;
                let checked = store.check_witnesses(&transaction, [tenant; 16], now);
                if limit < expected {
                    assert!(matches!(
                        checked,
                        Err(crate::Error::StorageCapacity {
                            resource: "tenant witness bytes",
                            ..
                        })
                    ));
                } else {
                    checked?;
                }
            }
        }
        store.storage.witness_max_bytes = Some(witness_bytes);
        let before_bytes = store.writer()?.get()?.query_row(
            &format!(
                "SELECT logical_bytes FROM ({})",
                AnalysisStore::usage_projection()
            ),
            [],
            |row| row.get::<_, u64>(0),
        )?;
        assert_eq!(
            before_bytes,
            current_bytes + result_bytes + 776 + second.request_meta()?.len() as u64 + key_bytes
        );
        store.storage.tenant_max_bytes = Some(1);
        let retention = crate::EvidenceRetentionOwner::new(&store);
        assert_eq!(
            retention.retain(&second.scope.identity, 3)?.removed_records,
            0
        );
        assert_eq!(
            retention
                .retain(&second.scope.identity, 101)?
                .removed_records,
            1
        );
        assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
        let retained_bytes = before_bytes + (256 + key_bytes) + 256
            - 2 * (257 + key_bytes)
            - (file_bytes + 256 + json_bytes + key_bytes);
        assert_eq!(
            store.writer()?.get()?.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({})",
                    AnalysisStore::usage_projection()
                ),
                [],
                |row| row.get::<_, u64>(0),
            )?,
            retained_bytes
        );
        AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            store.writer()?.get()?.query_row(
                &format!(
                    "SELECT logical_bytes FROM ({})",
                    AnalysisStore::usage_projection()
                ),
                [],
                |row| row.get::<_, u64>(0),
            )?,
            retained_bytes
        );
        AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
        Ok(())
    }

    #[test]
    fn analysis_witness_segment_cost() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = crate::RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 32 * 1024 * 1024,
        };
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        let identity = EvidenceIntakeIdentityV1 {
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
        };
        for group in 0..4 {
            store.accept_validated_batch(
                identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: group * 1024 + 1,
                    last_cursor: (group + 1) * 1024,
                    intake_utc_ns: 1,
                    framed_records: vec![7; 4 * 1024 * 1024].into(),
                    frame_ends: (1..=1024).map(|index| index * 4096 - index % 2).collect(),
                },
            )?;
        }
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let mut input = AnalysisResultCommitV1 {
            consumed_cursor: 4096,
            body: vec![1],
            created_utc_ns: 2,
            witnesses: [1, 2, 3073, 4096]
                .into_iter()
                .map(|cursor| AnalysisWitnessV1 {
                    identity: identity.clone().into(),
                    cursor,
                    expires_utc_ns: 100,
                })
                .collect(),
            ..crate::analysis::tests::result(scope, "first".into())
        };
        store.commit_result(&input)?;
        let segment_bytes = std::fs::read_dir(root.join("segments"))?
            .try_fold(0_u64, |bytes, entry| {
                Ok::<_, std::io::Error>(bytes + entry?.metadata()?.len())
            })?;
        assert!(segment_bytes > 16 * 1024 * 1024);
        let before = store.meta()?;
        let usage = store.witness_usage(identity.tenant_id, 3)?;
        assert_eq!(usage.read_revision, before.commit_revision);
        assert_eq!(usage.referenced_bytes, 16 * 1024);
        assert_eq!(usage.segment_bytes, segment_bytes);
        assert_eq!(usage.extra_segment_bytes, segment_bytes - 16 * 1024);
        assert_eq!(usage.charged_bytes, segment_bytes);
        assert_eq!(usage.context_bytes, 0);
        assert_eq!(store.meta()?, before);
        assert_eq!(store.witness_usage([9; 16], 3)?.charged_bytes, 0);
        assert!(store.witness_usage([0; 16], 3).is_err());
        assert!(store.witness_usage(identity.tenant_id, 0).is_err());
        input.result_id = "second".into();
        input.expected_cursor = 4096;
        input
            .witnesses
            .retain(|witness| matches!(witness.cursor, 1 | 4096));
        for witness in &mut input.witnesses {
            witness.expires_utc_ns = 200;
        }
        store.commit_result(&input)?;
        let duplicate = store.witness_usage(identity.tenant_id, 3)?;
        assert_eq!(duplicate.referenced_bytes, usage.referenced_bytes);
        assert_eq!(duplicate.charged_bytes, usage.charged_bytes);
        let expired = store.witness_usage(identity.tenant_id, 100)?;
        assert_eq!(expired.referenced_bytes, 8192);
        assert_eq!(expired.segment_bytes, segment_bytes);
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        assert_eq!(store.witness_usage(identity.tenant_id, 100)?, expired);
        let owner = crate::EvidenceRetentionOwner::new(&store);
        assert_eq!(owner.retain(&identity, 100)?.removed_records, 0);
        let cleared = owner.retain(&identity, 201)?;
        assert_eq!(cleared.removed_records, 4096);
        assert_eq!(cleared.retained_bytes, 0);
        assert_eq!(cleared.retained_floor, 4096);
        assert_eq!(owner.retain(&identity, 201)?.removed_records, 0);
        assert_eq!(
            store.witness_usage(identity.tenant_id, 201)?.charged_bytes,
            0
        );
        assert!(store.maintenance.try_write().is_ok());
        AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
        Ok(())
    }

    #[test]
    fn analysis_store_revision_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            StorageLimitsV1 {
                retained_revisions: Some(4096),
                tenant_revisions: Some(1024),
                ..Default::default()
            },
        )?;
        let mut writer = store.writer()?;
        let transaction = writer.get_mut()?.transaction()?;
        // Only relation counts are under test. The fixture transaction is not committed.
        for tenant in 1_u8..=4 {
            transaction.execute(
                "INSERT INTO context_versions SELECT ?, 'p', 'e'::BLOB, 'l'::BLOB, i,
                 1, NULL, 'tenant', 'b'::BLOB, 1 FROM range(1, 1025) t(i)",
                params![[tenant; 16].as_slice()],
            )?;
            store.check_logical(&transaction, [tenant; 16], false)?;
        }
        transaction.execute(
            "INSERT INTO context_versions VALUES (?, 'p', 'e'::BLOB, 'l'::BLOB, 1025,
             1, NULL, 'tenant', 'b'::BLOB, 1)",
            params![[4_u8; 16].as_slice()],
        )?;
        assert!(matches!(
            store.check_logical(&transaction, [4; 16], false),
            Err(crate::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            })
        ));
        assert!(matches!(
            store.check_logical(&transaction, [5; 16], false),
            Err(crate::Error::StorageCapacity {
                resource: "global retained revisions",
                ..
            })
        ));
        transaction.rollback()?;
        drop(writer);
        assert_eq!(store.meta()?.commit_revision, 0);
        Ok(())
    }

    #[test]
    fn raw_admission_uses_current_usage() -> TestResult {
        for finite in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let identity = crate::analysis::tests::identity();
            let mut store = AnalysisStore::open_with_limits(
                &root,
                Default::default(),
                StorageLimitsV1 {
                    tenant_max_bytes: finite.then_some(1024 * 1024),
                    ..Default::default()
                },
            )?;
            let batch = |cursor| ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                framed_records: vec![7; 100].into(),
                frame_ends: vec![100],
            };
            let mut first_end = 0;
            let mut accepted_bytes = 0;
            for cursor in 1..=2 {
                store.accept_validated_batch(identity.clone(), batch(cursor))?;
                assert_eq!(*store.revision.borrow(), cursor);
                assert!(store.raw_pending.load(std::sync::atomic::Ordering::Acquire));
                assert!(!store.raw_dirty.load(std::sync::atomic::Ordering::Acquire));
                if cursor == 1 {
                    first_end =
                        std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?
                            .len();
                }
            }
            {
                let guard = store.writer.lock().map_err(|_| "writer poisoned")?;
                let writer = guard.as_ref().ok_or("writer closed")?;
                let projected = AnalysisStore::read_meta_from(writer, &root)?.commit_revision;
                assert_eq!(projected, if finite { 1 } else { 0 });
                let usage = AnalysisStore::logical_usage(writer, identity.tenant_id)?.1;
                if finite {
                    assert!(usage > 0);
                    let end =
                        std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?
                            .len();
                    accepted_bytes = usage + end - first_end;
                } else {
                    assert_eq!(usage, 0);
                }
            }
            let path = super::super::segments::SegmentRange::path(&root, 1);
            let end = std::fs::metadata(&path)?.len();
            if finite {
                store.storage.tenant_max_bytes = Some(accepted_bytes);
                assert!(matches!(
                    store.accept_validated_batch(identity.clone(), batch(3)),
                    Err(crate::Error::StorageCapacity {
                        resource: "tenant logical bytes",
                        ..
                    })
                ));
                assert_eq!(std::fs::metadata(&path)?.len(), end);
                assert_eq!(*store.revision.borrow(), 2);
                assert!(store.write_ready.load(std::sync::atomic::Ordering::Acquire));
                let guard = store.writer.lock().map_err(|_| "writer poisoned")?;
                let writer = guard.as_ref().ok_or("writer closed")?;
                assert_eq!(
                    AnalysisStore::logical_usage(writer, identity.tenant_id)?.1,
                    accepted_bytes
                );
                assert_eq!(
                    AnalysisStore::read_meta_from(writer, &root)?.commit_revision,
                    2
                );
            } else {
                store.accept_validated_batch(identity.clone(), batch(3))?;
                let guard = store.writer.lock().map_err(|_| "writer poisoned")?;
                let writer = guard.as_ref().ok_or("writer closed")?;
                assert_eq!(
                    AnalysisStore::read_meta_from(writer, &root)?.commit_revision,
                    0
                );
                assert_eq!(*store.revision.borrow(), 3);
            }
            drop(store);
            let store = AnalysisStore::open(&root)?;
            assert_eq!(
                store.read_page(&identity, 1)?.records.len(),
                if finite { 2 } else { 3 }
            );
            AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
        }
        Ok(())
    }

    #[test]
    fn raw_projection_keeps_terminal_reserves() -> TestResult {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(
            &root,
            Default::default(),
            StorageLimitsV1 {
                logical_max_bytes: Some(1024 * 1024),
                witness_max_bytes: Some(1024 * 1024),
                ..Default::default()
            },
        )?;
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        store.accept_trace(&intent)?;
        let frame = |sequence, byte| TraceFrameV1 {
            execution_id: identity.execution_id,
            sequence,
            kind: TraceFrameKindV1::Data,
            bytes: vec![byte],
        };
        store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![frame(1, 7)],
                terminal: None,
            },
            101,
        )?;
        {
            let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
            assert_eq!(
                (raw.budget.trace_reserve, raw.budget.trace_slots),
                (TRACE_RESERVE, 1)
            );
        }
        let terminal = trace_terminal(2, 2);
        let receipt = store.append_trace(
            identity,
            &TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![frame(2, 8)],
                terminal: Some(terminal.clone()),
            },
            102,
        )?;
        {
            let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
            assert_eq!((raw.budget.trace_reserve, raw.budget.trace_slots), (0, 0));
        }
        assert_eq!((receipt.last_sequence, receipt.output_bytes), (2, 2));
        let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.frames, vec![frame(1, 7), frame(2, 8)]);
        assert_eq!(page.terminal, Some(terminal));
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.trace_receipt(identity)?, Some(receipt));
        assert_eq!(
            store
                .read_trace(identity, 1, &AnalysisReadControl::default())?
                .frames,
            vec![frame(1, 7), frame(2, 8)]
        );
        Ok(())
    }

    #[test]
    fn usage_tracks_transactions() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.commit_context(&context(1, 1))?;
        let mut writer = store.writer()?;
        let before = AnalysisStore::logical_usage(writer.get()?, [1; 16])?;
        assert_eq!(before, (260, 260, 1, 1));
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(
            "INSERT INTO context_versions SELECT ?, owner_id, entity_key, lifetime_key,
                owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body,
                commit_revision FROM context_versions",
            params![[2u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::logical_usage(&transaction, [2; 16])?,
            (520, 260, 2, 1)
        );
        transaction.execute(
            "DELETE FROM context_versions WHERE tenant_id = ?",
            params![[1u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::logical_usage(&transaction, [1; 16])?,
            (260, 0, 1, 0)
        );
        transaction.rollback()?;
        assert_eq!(
            AnalysisStore::logical_usage(writer.get()?, [1; 16])?,
            before
        );
        AnalysisStore::validate_state(writer.get()?, &root)?;
        drop(writer);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            AnalysisStore::logical_usage(store.writer()?.get()?, [1; 16])?,
            before
        );
        Ok(())
    }
}
