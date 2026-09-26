use duckdb::{params, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{source_key, AnalysisStore, ProcessorScopeV1};
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, Result};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorRetirementV1 {
    pub scope: ProcessorScopeV1,
    pub change_id: String,
    pub reason: String,
    pub expected_cursor: u64,
    pub cutoff_cursor: u64,
}

impl ProcessorRetirementV1 {
    pub fn valid(&self) -> bool {
        self.scope.valid()
            && !self.change_id.is_empty()
            && self.change_id.len() <= 128
            && self
                .change_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            && !self.reason.trim().is_empty()
            && self.reason.len() <= 512
            && !self.reason.chars().any(char::is_control)
            && self.expected_cursor <= self.cutoff_cursor
    }
}

impl AnalysisStore {
    /// Control must authorize the exact request before it calls this method.
    pub fn retire_required(&self, input: &ProcessorRetirementV1) -> Result<u64> {
        if !input.valid() {
            return self.reject("the processor retirement request is invalid");
        }
        let scope = &input.scope;
        let key = source_key(&scope.identity);
        let tenant = scope.identity.tenant_id.as_slice();
        let mut writer = self.maintenance_writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin required processor retirement",
            })?;
        let progress: Option<(String, u64, bool, String, String, u64, u64)> = transaction
            .query_row(
                "SELECT class, consumed_cursor, retired, retirement_id, retirement_reason,
                    retirement_cursor, retirement_revision FROM processor_progress
                 WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
                params![scope.processor_id, scope.method_version, tenant, key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu { operation: "read retirement progress" })?;
        let Some((class, consumed, retired, change_id, reason, cutoff, prior)) = progress else {
            return AnalysisConflictSnafu.fail();
        };
        if class != "required" || consumed != input.expected_cursor {
            return AnalysisConflictSnafu.fail();
        }
        if retired {
            if change_id != input.change_id
                || reason != input.reason
                || cutoff != input.cutoff_cursor
            {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(prior);
        }
        let accepted = Self::read_receipt_from(&transaction, &self.root, &scope.identity, &key)?
            .map_or(0, |receipt| receipt.contiguous_cursor);
        if input.cutoff_cursor != accepted {
            return AnalysisConflictSnafu.fail();
        }
        let revision = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?
            .commit_revision
            .checked_add(1)
            .ok_or_else(|| self.state_error("the analysis commit revision is exhausted"))?;
        if consumed < accepted {
            transaction
                .execute(
                    "INSERT INTO processor_gaps VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        scope.processor_id,
                        scope.method_version,
                        tenant,
                        key.as_slice(),
                        consumed + 1,
                        accepted,
                        revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "record retired missing input",
                })?;
        }
        transaction.execute(
            "UPDATE processor_progress SET retired = true, retirement_id = ?, retirement_reason = ?,
                retirement_cursor = ?, retirement_revision = ?
             WHERE processor_id = ? AND method_version = ? AND tenant_id = ? AND stream_key = ?",
            params![input.change_id, input.reason, accepted, revision,
                scope.processor_id, scope.method_version, tenant, key.as_slice()],
        ).context(AnalysisDatabaseSnafu { operation: "retire required processor" })?;
        self.check_logical(&transaction, scope.identity.tenant_id, true)?;
        let relations: &[&str] = if consumed < accepted {
            &["processor_progress", "processor_gaps"]
        } else {
            &["processor_progress"]
        };
        Self::record_revision(&transaction, revision, relations)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit processor retirement",
        })?;
        self.revision.send_replace(revision);
        Ok(revision)
    }

    pub fn processor_retirement(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<(ProcessorRetirementV1, u64)>> {
        if !scope.valid() {
            return self.reject("the processor retirement scope is invalid");
        }
        self.reader()?.get()?.query_row(
            "SELECT retirement_id, retirement_reason, consumed_cursor, retirement_cursor, retirement_revision
             FROM processor_progress WHERE processor_id = ? AND method_version = ?
                AND tenant_id = ? AND stream_key = ? AND retired = true",
            params![scope.processor_id, scope.method_version, scope.identity.tenant_id.as_slice(), source_key(&scope.identity).as_slice()],
            |row| Ok((ProcessorRetirementV1 {
                scope: scope.clone(), change_id: row.get(0)?, reason: row.get(1)?,
                expected_cursor: row.get(2)?, cutoff_cursor: row.get(3)?,
            }, row.get(4)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read processor retirement" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceIntakeIdentityV1,
        EvidenceRetentionOwner, ProcessorClassV1, ProcessorStateV1, RetentionLimitsV1,
        ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn request() -> ProcessorRetirementV1 {
        ProcessorRetirementV1 {
            scope: ProcessorScopeV1 {
                processor_id: "detector".into(),
                method_version: 1,
                identity: EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "n".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 1,
                    source_id: [3; 16],
                    source_epoch: 1,
                },
            },
            change_id: "change-1".into(),
            reason: "Retire this detector version.".into(),
            expected_cursor: 1,
            cutoff_cursor: 3,
        }
    }

    #[test]
    fn analysis_store_required_retirement() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let mut store = AnalysisStore::open(&root)?;
        let input = request();
        store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
        store.accept_validated_batch(
            input.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 3,
                intake_utc_ns: 1,
                framed_records: vec![1, 2, 3].into(),
                frame_ends: vec![1, 2, 3],
            },
        )?;
        let result = AnalysisResultCommitV1 {
            scope: input.scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "finding".into(),
            body: vec![1],
            created_utc_ns: 2,
            context_refs: vec![],
            witnesses: vec![AnalysisWitnessV1 {
                identity: input.scope.identity.clone(),
                cursor: 1,
                expires_utc_ns: 100,
            }],
        };
        let result_receipt = store.commit_result(&result)?;
        let before = store.meta()?;
        let revisions = store.subscribe_revision();
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 100,
        };
        assert_eq!(
            EvidenceRetentionOwner::new(&store, limits)?
                .retain(&input.scope.identity, 10)?
                .removed_records,
            0
        );
        let mut changed = input.clone();
        changed.cutoff_cursor = 2;
        assert!(store.retire_required(&changed).is_err());
        changed = input.clone();
        changed.expected_cursor = 0;
        assert!(store.retire_required(&changed).is_err());
        changed = input.clone();
        changed.scope.identity.tenant_id = [9; 16];
        assert!(store.retire_required(&changed).is_err());
        let storage = store.storage;
        store.storage.tenant_max_bytes = 1;
        assert!(store.retire_required(&input).is_err());
        store.storage = storage;
        assert_eq!(store.meta()?, before);
        assert!(!revisions.has_changed()?);
        assert!(store.processor_retirement(&input.scope)?.is_none());
        assert_eq!(
            EvidenceRetentionOwner::new(&store, limits)?
                .retain(&input.scope.identity, 10)?
                .removed_records,
            0
        );
        let revision = store.retire_required(&input)?;
        let health = store
            .processor_health(&input.scope)?
            .ok_or("health absent")?;
        assert_eq!(health.state, ProcessorStateV1::Retired);
        assert!(health.incomplete);
        assert_eq!(health.consumed_cursor, 1);
        assert_eq!(health.resume_floor, 0);
        assert_eq!(
            store.processor_retirement(&input.scope)?,
            Some((input.clone(), revision))
        );
        assert!(store.processor_retirement(&changed.scope)?.is_none());
        assert_eq!(store.commit_result(&result)?, result_receipt);
        assert!(store
            .register_processor(&input.scope, ProcessorClassV1::Required, 1)
            .is_err());
        assert_eq!(
            EvidenceRetentionOwner::new(&store, limits)?
                .retain(&input.scope.identity, 10)?
                .removed_records,
            2
        );
        let page = store.read_page(&input.scope.identity, 1)?;
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].cursor, 1);
        assert_eq!(page.next_cursor, Some(2));
        assert!(matches!(
            store.read_page(&input.scope.identity, 2),
            Err(crate::Error::RetainedRangeExpired {
                first_cursor: 2,
                last_cursor: 3,
                ..
            })
        ));
        store.accept_validated_batch(
            input.scope.identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 4,
                last_cursor: 4,
                intake_utc_ns: 10,
                framed_records: vec![4].into(),
                frame_ends: vec![1],
            },
        )?;
        let before = store.meta()?;
        assert_eq!(store.retire_required(&input)?, revision);
        assert_eq!(store.meta()?, before);
        changed = input.clone();
        changed.reason = "Different change".into();
        assert!(store.retire_required(&changed).is_err());
        let mut next = result.clone();
        next.result_id = "late-finding".into();
        next.expected_cursor = 1;
        next.consumed_cursor = 4;
        assert!(store.commit_result(&next).is_err());
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(
            reopened.processor_retirement(&input.scope)?,
            Some((input.clone(), revision))
        );
        assert_eq!(reopened.retire_required(&input)?, revision);
        let mut replacement = input.scope.clone();
        replacement.method_version = 2;
        reopened.register_processor(&replacement, ProcessorClassV1::Required, 4)?;
        assert!(reopened.processor_retirement(&replacement)?.is_none());
        Ok(())
    }

    #[test]
    fn analysis_store_retirement_recovery() -> TestResult {
        for fault in [
            "UPDATE processor_progress SET retirement_cursor = 9",
            "DELETE FROM processor_gaps",
            "UPDATE processor_progress SET retired = false",
        ] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let store = AnalysisStore::open(&root)?;
            let mut input = request();
            input.expected_cursor = 0;
            input.cutoff_cursor = 1;
            store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
            store.accept_validated_batch(
                input.scope.identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 1,
                    framed_records: vec![1].into(),
                    frame_ends: vec![1],
                },
            )?;
            store.retire_required(&input)?;
            store.writer()?.get()?.execute_batch(fault)?;
            drop(store);
            assert!(AnalysisStore::open(&root).is_err(), "{fault}");
        }
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut input = request();
        input.expected_cursor = 0;
        input.cutoff_cursor = 0;
        store.register_processor(&input.scope, ProcessorClassV1::Optional, 1)?;
        assert!(store.retire_required(&input).is_err());
        input.scope.method_version = 2;
        store.register_processor(&input.scope, ProcessorClassV1::Required, 1)?;
        store.retire_required(&input)?;
        assert!(
            !store
                .processor_health(&input.scope)?
                .ok_or("health absent")?
                .incomplete
        );
        Ok(())
    }
}
