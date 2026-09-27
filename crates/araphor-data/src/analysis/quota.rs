use duckdb::{params, Transaction};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result, StorageCapacitySnafu};

const TENANT_REVISIONS: u64 = 1_024;
const GLOBAL_REVISIONS: u64 = 4_096;

impl AnalysisStore {
    const WITNESS_USAGE: &'static str = "SELECT (
        COALESCE((SELECT SUM(256 + octet_length(e.framed_record)) FROM events e
            SEMI JOIN (
                SELECT tenant_id, stream_key, durable_cursor FROM evidence_refs
                WHERE tenant_id = ? AND expires_utc_ns > ?
            ) r USING (tenant_id, stream_key, durable_cursor)), 0)
        + COALESCE((SELECT SUM(256 + octet_length(c.body) + octet_length(encode(c.owner_id))
            + octet_length(c.entity_key) + octet_length(c.lifetime_key)) FROM context_versions c
            SEMI JOIN (
                SELECT tenant_id, owner_id, entity_key, lifetime_key, owner_revision
                FROM context_refs WHERE tenant_id = ?
            ) r USING (tenant_id, owner_id, entity_key, lifetime_key, owner_revision)), 0)
    )::UBIGINT";

    fn logical_usage(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
    ) -> Result<(u64, u64, u64, u64)> {
        // ponytail: scan native columns per write or retention pass. Use transactional counters if load tests exceed the intake budget.
        transaction
            .query_row(
                "WITH charges AS (
                    SELECT tenant_id, 'events' AS family, false AS limited,
                        256 + octet_length(framed_record) AS bytes FROM events
                    UNION ALL SELECT tenant_id, 'coverage', true,
                        256 + octet_length(report) FROM coverage
                    UNION ALL SELECT tenant_id, 'receipts', false,
                        256 + octet_length(encode(identity_json)) FROM source_receipts
                    UNION ALL SELECT tenant_id, 'bindings', false, 256 FROM source_bindings
                    UNION ALL SELECT tenant_id, 'context', true,
                        256 + octet_length(encode(owner_id)) + octet_length(entity_key)
                        + octet_length(lifetime_key) + octet_length(body) FROM context_versions
                    UNION ALL SELECT tenant_id, 'progress', false,
                        256 + octet_length(encode(processor_id)) + octet_length(encode(retirement_id))
                        + octet_length(encode(retirement_reason)) FROM processor_progress
                    UNION ALL SELECT tenant_id, 'witnesses', false,
                        256 + octet_length(encode(ref_id)) FROM evidence_refs
                    UNION ALL SELECT tenant_id, 'context_refs', false,
                        256 + octet_length(encode(ref_id)) + octet_length(encode(owner_id))
                        + octet_length(entity_key) + octet_length(lifetime_key) FROM context_refs
                    UNION ALL SELECT tenant_id, 'results', true,
                        256 + octet_length(encode(result_id)) + octet_length(encode(processor_id))
                        + octet_length(body) FROM analysis_results
                    UNION ALL SELECT tenant_id, 'processor_gaps', false,
                        256 + octet_length(encode(processor_id)) FROM processor_gaps
                    UNION ALL SELECT tenant_id, 'recovery_gaps', false, 256 FROM recovery_gaps
                    UNION ALL SELECT tenant_id, 'expired_ranges', false, 256 FROM expired_ranges
                ), families AS (
                    SELECT family, limited, SUM(bytes) AS bytes,
                        SUM(CASE WHEN tenant_id = ? THEN bytes ELSE 0 END) AS scoped,
                        COUNT(*) AS revisions, COUNT(*) FILTER (WHERE tenant_id = ?) AS scoped_count
                    FROM charges GROUP BY family, limited
                )
                SELECT COALESCE(SUM(bytes), 0)::UBIGINT,
                    COALESCE(SUM(scoped), 0)::UBIGINT,
                    COALESCE(MAX(revisions) FILTER (WHERE limited), 0)::UBIGINT,
                    COALESCE(MAX(scoped_count) FILTER (WHERE limited), 0)::UBIGINT FROM families",
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
        let (total, scoped, revisions, tenant_revisions) =
            self.logical_usage(transaction, tenant)?;
        let global_limit = self.storage.logical_max_bytes;
        let tenant_limit = self.storage.tenant_max_bytes;
        let (global_limit, tenant_limit) = if maintenance {
            (global_limit, tenant_limit)
        } else {
            (
                global_limit - global_limit / 4,
                tenant_limit - tenant_limit / 4,
            )
        };
        let resource = if scoped > tenant_limit {
            Some("tenant logical bytes")
        } else if total > global_limit {
            Some("global logical bytes")
        } else if tenant_revisions > TENANT_REVISIONS {
            Some("tenant retained revisions")
        } else if revisions > GLOBAL_REVISIONS {
            Some("global retained revisions")
        } else {
            None
        };
        match resource {
            Some(resource) => StorageCapacitySnafu { resource }.fail(),
            None => Ok(()),
        }
    }

    pub(super) fn logical_pressure(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
    ) -> Result<bool> {
        let (total, scoped, _, _) = self.logical_usage(transaction, tenant)?;
        let global_limit = self.storage.logical_max_bytes - self.storage.logical_max_bytes / 4;
        let tenant_limit = self.storage.tenant_max_bytes - self.storage.tenant_max_bytes / 4;
        Ok(total >= global_limit - global_limit / 10 || scoped >= tenant_limit - tenant_limit / 10)
    }

    pub(super) fn check_witnesses(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        now: u64,
    ) -> Result<()> {
        let bytes: u64 = transaction
            .query_row(
                Self::WITNESS_USAGE,
                params![tenant.as_slice(), now, tenant.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check exact witness quota",
            })?;
        if bytes > self.storage.witness_max_bytes {
            return StorageCapacitySnafu {
                resource: "tenant witness bytes",
            }
            .fail();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
        AnalysisResultCommitV1, AnalysisWitnessV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
        ProcessorClassV1, ProcessorScopeV1, StorageLimitsV1, ValidatedEvidenceBatchV1,
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
    fn analysis_store_logical_limits() -> TestResult {
        for global in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let limits = StorageLimitsV1 {
                tenant_max_bytes: 346,
                logical_max_bytes: if global { 346 } else { 8 * 1024 * 1024 * 1024 },
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
    fn analysis_store_witness_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let mut store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "n".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
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
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        let context = context(1, 1);
        let context_revision = store.commit_context(&context)?;
        let input = AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision,
            result_id: "r".into(),
            body: vec![1],
            created_utc_ns: 2,
            witnesses: vec![AnalysisWitnessV1 {
                identity,
                cursor: 1,
                expires_utc_ns: 100,
            }],
            context_refs: vec![AnalysisContextRefV1 {
                content_sha256: context.content_digest()?,
                key: context.key,
            }],
        };
        let current_bytes = 1290 + serde_json::to_vec(&input.scope.identity)?.len() as u64;
        store.storage.tenant_max_bytes = current_bytes + 776;
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
        store.storage.witness_max_bytes = 520;
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
        store.storage.witness_max_bytes = 521;
        let receipt = store.commit_result(&input)?;
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
        assert_eq!(store.commit_result(&input)?, receipt);
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
            for (tenant, now, expected) in [(1_u8, 2_u64, 521_u64), (1, 100, 260), (2, 2, 0)] {
                let bytes: u64 = reader.get()?.query_row(
                    AnalysisStore::WITNESS_USAGE,
                    params![[tenant; 16].as_slice(), now, [tenant; 16].as_slice()],
                    |row| row.get(0),
                )?;
                assert_eq!(bytes, expected);
            }
        }
        store.storage.tenant_max_bytes = 1;
        let retention = crate::EvidenceRetentionOwner::new(&store, Default::default())?;
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
        Ok(())
    }

    #[test]
    fn analysis_store_revision_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut writer = store.writer()?;
        let transaction = writer.get_mut()?.transaction()?;
        // Only relation counts are under test. The fixture transaction is not committed.
        for tenant in 1_u8..=4 {
            transaction.execute(
                "INSERT INTO context_versions SELECT ?, 'p', 'e'::BLOB, 'l'::BLOB, i,
                 1, NULL, 'tenant', 'b'::BLOB, 'digest'::BLOB, 1 FROM range(1, 1025) t(i)",
                params![[tenant; 16].as_slice()],
            )?;
            store.check_logical(&transaction, [tenant; 16], false)?;
        }
        transaction.execute(
            "INSERT INTO context_versions VALUES (?, 'p', 'e'::BLOB, 'l'::BLOB, 1025,
             1, NULL, 'tenant', 'b'::BLOB, 'digest'::BLOB, 1)",
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
}
