use serde::Serialize;

use super::{AnalysisGapV1, ProcessorClassV1, StorageUsageV1};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StorageHealthV1 {
    pub write_ready: bool,
    pub retention_healthy: bool,
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
                node_id: "n".into(),
                ..crate::analysis::tests::identity()
            },
        }
    }

    #[test]
    fn analysis_store_processor_health() -> TestResult {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: Some(100),
        };
        let mut store = AnalysisStore::open_with_retention(&root, limits)?;
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
            body: vec![1],
            created_utc_ns: 2,
            ..crate::analysis::tests::result(required.clone(), "r".into())
        })?;
        assert_eq!(
            store
                .processor_health(&required)?
                .ok_or("health absent")?
                .state,
            ProcessorStateV1::Current
        );
        EvidenceRetentionOwner::new(&store).retain(&required.identity, 3)?;
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
        let capacity = store.storage_health()?;
        assert!(capacity.retention_healthy);
        store
            .retention_healthy
            .store(false, std::sync::atomic::Ordering::Release);
        let capacity = store.storage_health()?;
        assert!(!capacity.retention_healthy);
        drop(store);
        let reopened = AnalysisStore::open_with_retention(root, limits)?;
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
    ProcessingFailed,
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
