use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use super::{AnalysisReadControl, AnalysisStore};
use crate::{AnalysisDatabaseSnafu, Result};

pub(super) const TRACE_RESERVE: u64 = 16 * 1024;
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
        let (reserved, slots) = Self::terminal_reserve(transaction)?;
        self.storage
            .check_append(self.storage_with_reserve(0, slots)?, reserved)
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
            COALESCE((SELECT SUM(octet_length(c.body) + octet_length(encode(c.owner_id))
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

    pub(super) fn revision_usage(connection: &Connection, tenant: [u8; 16]) -> Result<(u64, u64)> {
        connection
            .query_row(
                "SELECT GREATEST(
                    (SELECT count(*)::UBIGINT FROM coverage),
                    (SELECT count(*)::UBIGINT FROM context_versions),
                    (SELECT count(*)::UBIGINT FROM analysis_results)),
                    GREATEST(
                    (SELECT count(*)::UBIGINT FROM coverage WHERE tenant_id = ?),
                    (SELECT count(*)::UBIGINT FROM context_versions WHERE tenant_id = ?),
                    (SELECT count(*)::UBIGINT FROM analysis_results WHERE tenant_id = ?))",
                params![tenant.as_slice(), tenant.as_slice(), tenant.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count retained revisions",
            })
    }

    pub(super) fn check_revision_limits(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
    ) -> Result<()> {
        if self.storage.retained_revisions.is_none() && self.storage.tenant_revisions.is_none() {
            return Ok(());
        }
        let (total, scoped) = Self::revision_usage(transaction, tenant)?;
        self.storage.check_revisions(total, scoped)
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
    fn analysis_store_witness_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = super::super::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        };
        let mut store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
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
        let file_bytes =
            std::fs::metadata(super::super::segments::SegmentRange::path(&root, 1))?.len();
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        let context = context(1, 1);
        let context_bytes = (context.body.len()
            + context.key.owner_id.len()
            + context.key.entity_key.len()
            + context.key.lifetime_key.len()) as u64;
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
        let witness_bytes = file_bytes + context_bytes;
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
        assert_eq!(store.commit_result(&input)?, receipt);
        let mut second = input;
        second.expected_cursor = 1;
        second.result_id = "s".into();
        store.commit_result(&second)?;
        assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
        {
            let reader = store.reader()?;
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
        for (tenant, now, expected) in [
            (1_u8, 2_u64, witness_bytes),
            (1, 100, context_bytes),
            (2, 2, 0),
        ] {
            let usage = store.witness_usage([tenant; 16], now)?;
            assert_eq!(usage.charged_bytes, expected);
            assert_eq!(
                usage.context_bytes,
                if tenant == 1 { context_bytes } else { 0 }
            );
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
        AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
        drop(store);
        let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
        assert_eq!(store.read_result([1; 16], "s")?, Some(vec![1]));
        AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
        Ok(())
    }

    #[test]
    fn analysis_witness_segment_cost() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: Some(32 * 1024 * 1024),
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
            store.check_revision_limits(&transaction, [tenant; 16])?;
        }
        transaction.execute(
            "INSERT INTO context_versions VALUES (?, 'p', 'e'::BLOB, 'l'::BLOB, 1025,
             1, NULL, 'tenant', 'b'::BLOB, 1)",
            params![[4_u8; 16].as_slice()],
        )?;
        assert!(matches!(
            store.check_revision_limits(&transaction, [4; 16]),
            Err(crate::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            })
        ));
        assert!(matches!(
            store.check_revision_limits(&transaction, [5; 16]),
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
    fn raw_projection_keeps_terminal_reserves() -> TestResult {
        use super::super::raw::tests::{trace_intent, trace_terminal};
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open_with_limits(
            &root,
            Default::default(),
            StorageLimitsV1 {
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
        let before = AnalysisStore::revision_usage(writer.get()?, [1; 16])?;
        assert_eq!(before, (1, 1));
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(
            "INSERT INTO context_versions SELECT ?, owner_id, entity_key, lifetime_key,
                owner_revision, valid_from_utc_ns, valid_until_utc_ns, sensitivity, body,
                commit_revision FROM context_versions",
            params![[2u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::revision_usage(&transaction, [2; 16])?,
            (2, 1)
        );
        transaction.execute(
            "DELETE FROM context_versions WHERE tenant_id = ?",
            params![[1u8; 16].as_slice()],
        )?;
        assert_eq!(
            AnalysisStore::revision_usage(&transaction, [1; 16])?,
            (1, 0)
        );
        transaction.rollback()?;
        assert_eq!(
            AnalysisStore::revision_usage(writer.get()?, [1; 16])?,
            before
        );
        AnalysisStore::validate_state(writer.get()?, &root)?;
        drop(writer);
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            AnalysisStore::revision_usage(store.writer()?.get()?, [1; 16])?,
            before
        );
        Ok(())
    }
}
