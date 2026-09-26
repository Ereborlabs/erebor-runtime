use duckdb::{params, OptionalExt as _};
use serde::Serialize;
use snafu::ResultExt as _;

use super::{
    source_key, valid_source_identity, AnalysisGapV1, AnalysisStore, ProcessorClassV1,
    ProcessorScopeV1, StorageUsageV1, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StorageHealthV1 {
    pub retention_healthy: bool,
    pub intake_capacity: bool,
    pub maintenance_capacity: bool,
    pub usage: StorageUsageV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisResultCommitV1, EvidenceRetentionOwner, RetentionLimitsV1, ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn scope() -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: "required".into(),
            method_version: 1,
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "n".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        }
    }

    #[test]
    fn analysis_store_processor_health() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let mut store = AnalysisStore::open(&root)?;
        let required = scope();
        assert!(store.processor_health(&required)?.is_none());
        store.register_processor(&required, ProcessorClassV1::Required, 1)?;
        assert_eq!(
            store
                .processor_health(&required)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::AwaitingSource
        );
        store.accept_validated_batch(
            required.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        let health = store.processor_health(&required)?.ok_or("health absent")?;
        assert_eq!(health.state, ProcessorStateV1::Lagging);
        assert_eq!(health.cursor_lag, 1);
        assert!(!health.incomplete);
        assert!(store.storage_health()?.retention_healthy);
        assert_eq!(health.read_revision, store.meta()?.commit_revision);
        let mut foreign = required.clone();
        foreign.identity.tenant_id = [9; 16];
        assert!(store.processor_health(&foreign)?.is_none());
        let mut optional = required.clone();
        optional.processor_id = "optional".into();
        store.register_processor(&optional, ProcessorClassV1::Optional, 1)?;
        store.commit_result(&AnalysisResultCommitV1 {
            scope: required.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "r".into(),
            body: vec![1],
            created_utc_ns: 2,
            witnesses: vec![],
            context_refs: vec![],
        })?;
        assert_eq!(
            store
                .processor_health(&required)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::Current
        );
        EvidenceRetentionOwner::new(
            &store,
            RetentionLimitsV1 {
                raw_max_age_ns: 1,
                raw_max_bytes: 100,
            },
        )?
        .retain(&required.identity, 3)?;
        assert!(matches!(
            store
                .processor_health(&optional)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::ExpiredInput(AnalysisGapV1 {
                first_cursor: 1,
                last_cursor: 1,
                ..
            })
        ));
        store.resume_optional(&optional)?;
        let health = store.processor_health(&optional)?.ok_or("health absent")?;
        assert_eq!(health.state, ProcessorStateV1::Current);
        assert!(health.incomplete);
        assert_eq!(health.consumed_cursor, 0);
        assert_eq!(health.resume_floor, 1);
        store.record_recovery_floor(&required.identity, 3)?;
        let gap = store.recovery_gaps(&required.identity, 0)?;
        assert_eq!(gap.len(), 1);
        assert_eq!((gap[0].first_cursor, gap[0].last_cursor), (2, 3));
        assert_eq!(
            store
                .processor_health(&required)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::RecoveryLoss(gap[0])
        );
        assert_eq!(
            store
                .source_receipt(&required.identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            1
        );
        store.storage.policy_reserve_bytes = u64::MAX / 4;
        let capacity = store.storage_health()?;
        assert!(capacity.retention_healthy);
        assert!(!capacity.intake_capacity && !capacity.maintenance_capacity);
        store.storage = Default::default();
        store
            .retention_healthy
            .store(false, std::sync::atomic::Ordering::Release);
        let capacity = store.storage_health()?;
        assert!(!capacity.retention_healthy);
        assert!(capacity.intake_capacity && capacity.maintenance_capacity);
        drop(store);
        let reopened = AnalysisStore::open(root)?;
        assert_eq!(reopened.recovery_gaps(&required.identity, 0)?, gap);
        assert_eq!(
            reopened
                .processor_health(&required)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::RecoveryLoss(gap[0])
        );
        Ok(())
    }

    #[test]
    fn analysis_store_recovery_pages() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = scope().identity;
        for cursor in 1..=257 {
            store.record_recovery_floor(&identity, cursor)?;
        }
        let first = store.recovery_gaps(&identity, 0)?;
        assert_eq!(first.len(), 256);
        assert_eq!(first[0].first_cursor, 1);
        assert_eq!(first[255].last_cursor, 256);
        let second = store.recovery_gaps(&identity, 256)?;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].first_cursor, 257);
        assert!(store.recovery_gaps(&identity, u64::MAX)?.is_empty());
        let mut foreign = identity.clone();
        foreign.tenant_id = [2; 16];
        assert!(store.recovery_gaps(&foreign, 0)?.is_empty());
        foreign.tenant_id = [0; 16];
        assert!(store.recovery_gaps(&foreign, 0).is_err());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ProcessorStateV1 {
    AwaitingSource,
    Current,
    Lagging,
    ExpiredInput(AnalysisGapV1),
    RecoveryLoss(AnalysisGapV1),
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessorHealthV1 {
    pub class: ProcessorClassV1,
    pub state: ProcessorStateV1,
    pub accepted_cursor: u64,
    pub consumed_cursor: u64,
    pub resume_floor: u64,
    pub cursor_lag: u64,
    pub incomplete: bool,
    pub read_revision: u64,
}

impl AnalysisStore {
    pub fn storage_health(&self) -> Result<StorageHealthV1> {
        self.meta()?;
        let usage = self.storage_usage()?;
        Ok(StorageHealthV1 {
            retention_healthy: self.retention_healthy(),
            intake_capacity: self.storage.check(usage, false).is_ok(),
            maintenance_capacity: self.storage.check(usage, true).is_ok(),
            usage,
        })
    }

    pub fn recovery_gaps(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        after_cursor: u64,
    ) -> Result<Vec<AnalysisGapV1>> {
        if !valid_source_identity(identity) {
            return self.reject("the recovery gap source identity is invalid");
        }
        let reader = self.reader()?;
        let mut statement = reader
            .prepare(
                "SELECT first_cursor, last_cursor, commit_revision FROM recovery_gaps
             WHERE tenant_id = ? AND stream_key = ? AND last_cursor > ?
             ORDER BY first_cursor LIMIT ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare source recovery gaps",
            })?;
        statement
            .query_map(
                params![
                    identity.tenant_id.as_slice(),
                    source_key(identity).as_slice(),
                    after_cursor,
                    MAX_ANALYSIS_PAGE_RECORDS as u32
                ],
                |row| {
                    Ok(AnalysisGapV1 {
                        first_cursor: row.get(0)?,
                        last_cursor: row.get(1)?,
                        commit_revision: row.get(2)?,
                    })
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read source recovery gaps",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode source recovery gaps",
            })
    }

    pub fn processor_health(&self, scope: &ProcessorScopeV1) -> Result<Option<ProcessorHealthV1>> {
        if !scope.valid() {
            return self.reject("the processor health scope is invalid");
        }
        let key = source_key(&scope.identity);
        let tenant = scope.identity.tenant_id.as_slice();
        let mut reader = self.reader()?;
        let snapshot = reader.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin processor health snapshot",
        })?;
        let progress: Option<(String, u64, u64, bool)> = snapshot
            .query_row(
                "SELECT class, consumed_cursor, resume_floor, retired FROM processor_progress
             WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![
                    scope.processor_id,
                    scope.method_version,
                    tenant,
                    key.as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read processor health",
            })?;
        let Some((class, consumed_cursor, resume_floor, retired)) = progress else {
            return Ok(None);
        };
        let class = ProcessorClassV1::try_from(class.as_str())
            .map_err(|_| self.state_error("the processor class is invalid"))?;
        let receipt = Self::read_receipt_from(&snapshot, &self.root, &scope.identity, &key)?;
        let accepted_cursor = receipt
            .as_ref()
            .map_or(0, |receipt| receipt.contiguous_cursor);
        let effective = consumed_cursor.max(resume_floor);
        let cursor_lag = accepted_cursor
            .checked_sub(effective)
            .ok_or_else(|| self.state_error("processor progress exceeds its receipt"))?;
        let gap: Option<(AnalysisGapV1, bool)> = snapshot
            .query_row(
                "SELECT first_cursor, last_cursor, commit_revision, recovery FROM (
                SELECT first_cursor, last_cursor, commit_revision, true AS recovery
                FROM recovery_gaps WHERE tenant_id = ? AND stream_key = ?
                UNION ALL SELECT first_cursor, last_cursor, commit_revision, false AS recovery
                FROM expired_ranges WHERE tenant_id = ? AND stream_key = ?
             ) WHERE last_cursor > ? ORDER BY recovery DESC, first_cursor LIMIT 1",
                params![tenant, key.as_slice(), tenant, key.as_slice(), effective],
                |row| {
                    Ok((
                        AnalysisGapV1 {
                            first_cursor: row.get(0)?,
                            last_cursor: row.get(1)?,
                            commit_revision: row.get(2)?,
                        },
                        row.get(3)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read processor missing input",
            })?;
        let recorded_gap: bool = snapshot
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM processor_gaps WHERE processor_id = ?
                AND method_version = ? AND tenant_id = ? AND stream_key = ?)
             OR EXISTS (SELECT 1 FROM recovery_gaps WHERE tenant_id = ? AND stream_key = ?)",
                params![
                    scope.processor_id,
                    scope.method_version,
                    tenant,
                    key.as_slice(),
                    tenant,
                    key.as_slice()
                ],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read processor coverage health",
            })?;
        let state = if retired {
            ProcessorStateV1::Retired
        } else if let Some((gap, recovery)) = gap {
            if recovery {
                ProcessorStateV1::RecoveryLoss(gap)
            } else {
                ProcessorStateV1::ExpiredInput(gap)
            }
        } else if receipt.is_none() {
            ProcessorStateV1::AwaitingSource
        } else if cursor_lag > 0 {
            ProcessorStateV1::Lagging
        } else {
            ProcessorStateV1::Current
        };
        Ok(Some(ProcessorHealthV1 {
            class,
            state,
            accepted_cursor,
            consumed_cursor,
            resume_floor,
            cursor_lag,
            incomplete: recorded_gap || gap.is_some(),
            read_revision: Self::read_meta_from(&snapshot, &self.root.join("analysis.duckdb"))?
                .commit_revision,
        }))
    }
}
