use std::path::Path;

use snafu::ResultExt as _;
use uuid::Uuid;

use crate::{EvidenceIntakeIdentityV1, Result};

mod backup;
mod capacity;

mod context;
mod coverage;
#[cfg(any(test, feature = "test-fixtures"))]
mod crash;
mod definitions;
mod dependencies;
mod extraction;
mod graph;

mod health;
mod inputs;
mod managed;

pub mod native;
mod notification;
mod packages;
mod progress;
mod quota;
mod raw;

mod raw_segments;
mod read;
mod retention;
mod retirement;

mod segment_file;
mod segments;
#[cfg(any(test, feature = "test-fixtures"))]
mod test_support;
#[cfg(any(test, feature = "test-fixtures"))]
pub use test_support::RawIndexFixture;
mod trace;

pub use backup::{
    AnalysisBackupFileV1, AnalysisBackupManifestV1, AnalysisBackupSegmentV1,
    AnalysisRecoveryStatusV1,
};
pub use capacity::StorageUsageV1;
pub use context::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};
pub use coverage::{CoverageChanges, CoverageRecord, CoverageReportRef};
pub use extraction::{
    AnalysisAppendRead, AnalysisExtractLimits, AnalysisExtractionV1, AnalysisPositionPageV1,
    AnalysisReadModeV1, AnalysisReferenceOriginV1, AnalysisReferenceV1, AnalysisSelectionV1,
    AnalysisSourceSnapshotV1, AnalysisTableRead, AnalysisTableRequests, Selection,
};
pub use graph::{GraphManifest, GraphSourceSummary};

pub use health::{ProcessorHealthV1, ProcessorStateV1, StorageHealthV1};
pub use inputs::InputSubscription;
pub use managed::*;
pub use native::EvidenceRetentionOwner;
pub use native::{
    ActivationSubscription, ManagedCommit, ManagedGraphJournal, ManagedGraphTransaction,
    ManagedLease, ManagedReturn, NativeStore as AnalysisStore, PreparedManagedCommit,
};
pub use notification::{NotificationLookup, PreparedNotificationBatch};
pub use packages::*;
pub use progress::{
    AnalysisContextRefV1, AnalysisGapV1, AnalysisProcessorResultV1, AnalysisResultCommitV1,
    AnalysisResultReceiptV1, AnalysisWitnessV1, ProcessorClassV1, ProcessorScopeV1,
};
pub use progress::{
    DiscoveryProducer, PreparedProfile, ProfileCommit, MAX_RESULT_BYTES, MAX_RESULT_REFS,
};
pub use quota::WitnessUsageV1;
pub use raw::{AnalysisStreamIdentityV1, TraceOutputPageV1, TraceOutputReceiptV1};
pub use read::AnalysisReadControl;
#[cfg(any(test, feature = "test-fixtures"))]
pub use retention::RetentionResultV1;
pub use retention::{RetentionLimitsV1, RetentionStepV1};
pub use retirement::ProcessorRetirementV1;
pub use segment_file::{SegmentFile, EVIDENCE_SEGMENT_BYTES};
pub use trace::{TraceBindingV1, TraceIntentPageV1, TraceIntentV1, TraceStateV1};

pub const ANALYSIS_SCHEMA_VERSION: i64 = 41;
pub const MAX_ANALYSIS_PAGE_RECORDS: usize = 256;
pub const MAX_ANALYSIS_PAGE_BYTES: usize = 1024 * 1024;

#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AnalysisCommitStage {
    BeforeRotation,
    BeforeAppend,
    AfterSync,
    AfterTraceFreeze,
    BeforeResultCommit,
    BeforeRetentionCommit,
    BeforeContextCommit,
    AfterMetadataSync,
}

#[cfg(any(test, feature = "test-fixtures"))]
struct CommitHook {
    stage: AnalysisCommitStage,
    callback: Box<dyn FnOnce() -> Result<()> + Send>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AnalysisStoreMetaV1 {
    pub store_uuid: Uuid,
    pub schema_version: u32,
    pub recovery_epoch: u64,
    pub commit_revision: u64,
}

pub use araphor_analysis_builtins::discovery::StorePositionV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisRecordV1 {
    pub cursor: u64,
    pub framed_record: Vec<u8>,
    pub position: StorePositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisReadPageV1 {
    pub first_cursor: u64,
    pub records: Vec<AnalysisRecordV1>,
    pub encoded_bytes: usize,
    pub next_cursor: Option<u64>,
    pub read_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AnalysisSourceReceiptV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub contiguous_cursor: u64,
    pub coverage_revision: u64,
    pub retained_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisSourceStatusV1 {
    pub receipt: AnalysisSourceReceiptV1,
    pub retained_event_count: u64,
    pub latest_coverage_report: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedEvidenceBatchV1 {
    pub cpu_id: u32,
    pub first_cursor: u64,
    pub last_cursor: u64,
    /// Positive UTC time at durable intake.
    pub intake_utc_ns: u64,
    pub framed_records: prost::bytes::Bytes,
    pub frame_ends: Vec<usize>,
}

impl ValidatedEvidenceBatchV1 {
    pub(super) fn validate_identity(
        &self,
        identity: &EvidenceIntakeIdentityV1,
        root: &Path,
    ) -> Result<()> {
        if !identity.valid()
            || self.first_cursor == 0
            || self.frame_ends.is_empty()
            || self.frame_ends.last().copied() != Some(self.framed_records.len())
            || self
                .frame_ends
                .iter()
                .scan(0, |prior, end| {
                    let increasing = *end > *prior;
                    *prior = *end;
                    Some(increasing)
                })
                .any(|increasing| !increasing)
            || self
                .first_cursor
                .checked_add(self.frame_ends.len() as u64 - 1)
                != Some(self.last_cursor)
        {
            return crate::Error::reject_path(
                root,
                "the validated evidence identity or bounds are invalid",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedCoverageV1 {
    pub identity: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub revision: u64,
    pub encoded_report: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStoreOutcomeV1 {
    Accepted,
    Pending,
    AlreadyAcceptedExpired,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use crate::EVIDENCE_BATCH_RECORDS;

    pub(in crate::analysis) fn assert_no_execution(store: &AnalysisStore) -> Result<()> {
        let counts = store.read_snapshot(|reader| {
            reader
                .query_row(
                    "SELECT (SELECT count(*) FROM managed_instances),
                            (SELECT count(*) FROM managed_versions),
                            (SELECT count(*) FROM managed_calls),
                            (SELECT count(*) FROM managed_attempts),
                            (SELECT count(*) FROM managed_edges),
                            (SELECT count(*) FROM analysis_results)",
                    [],
                    |row| {
                        (0..6)
                            .map(|index| row.get::<usize, u64>(index))
                            .collect::<duckdb::Result<Vec<_>>>()
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read admission effects",
                })
        })?;
        assert_eq!(counts, vec![0; 6]);
        assert!(!store.discovery_enabled());
        Ok(())
    }

    pub(crate) fn identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".to_owned(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
    }

    pub(crate) fn result(scope: ProcessorScopeV1, result_id: String) -> AnalysisResultCommitV1 {
        AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id,
            body: b"finding".to_vec(),
            created_utc_ns: 100,
            witnesses: Vec::new(),
            context_refs: Vec::new(),
        }
    }

    pub(in crate::analysis) fn batch(
        first_cursor: u64,
        records: &[&[u8]],
    ) -> ValidatedEvidenceBatchV1 {
        let mut framed_records = Vec::new();
        let mut frame_ends = Vec::new();
        for record in records {
            framed_records.extend_from_slice(record);
            frame_ends.push(framed_records.len());
        }
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor,
            last_cursor: first_cursor + records.len() as u64 - 1,
            intake_utc_ns: 1_000_000_000,
            framed_records: framed_records.into(),
            frame_ends,
        }
    }

    fn coverage(
        identity: &EvidenceIntakeIdentityV1,
        revision: u64,
        bytes: &[u8],
    ) -> ValidatedCoverageV1 {
        ValidatedCoverageV1 {
            identity: identity.clone(),
            cpu_id: 0,
            revision,
            encoded_report: bytes.to_vec(),
        }
    }

    #[test]
    fn analysis_store_reopen_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let initial = store.meta()?;
        assert_eq!(i64::from(initial.schema_version), ANALYSIS_SCHEMA_VERSION);
        assert_eq!(initial.commit_revision, 0);
        assert!(AnalysisStore::open(&root).is_err());
        {
            let mut writer_guard = store.writer()?;
            let writer = writer_guard.get_mut()?;
            let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
                operation: "begin rollback proof",
            })?;
            transaction
                .execute("UPDATE store_meta SET commit_revision = 1", [])
                .context(AnalysisDatabaseSnafu {
                    operation: "write rollback proof",
                })?;
        }
        assert_eq!(store.meta()?, initial);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.meta()?, initial);
        let writer_guard = reopened.writer()?;
        let writer = writer_guard.get()?;
        let version: String = writer
            .query_row("SELECT version()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read engine version",
            })?;
        assert_eq!(version, "v1.5.5");
        assert!(writer
            .execute_batch("COPY (SELECT 1) TO '/tmp/araphor-analysis-forbidden.csv'")
            .is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_schema_permissions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("schema");
        let store = AnalysisStore::open(&root)?;
        let before = store.meta()?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?, before);
        {
            let writer_guard = store.writer()?;
            writer_guard
                .get()?
                .execute("UPDATE store_meta SET schema_version = 0", [])?;
        }
        drop(store);
        let bytes = fs::read(root.join("analysis.duckdb"))?;
        assert!(matches!(
            AnalysisStore::open(&root),
            Err(crate::Error::AnalysisState { .. })
        ));
        assert_eq!(fs::read(root.join("analysis.duckdb"))?, bytes);
        let root = directory.path().join("nonprivate");
        let store = AnalysisStore::open(&root)?;
        drop(store);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        assert!(AnalysisStore::open(&root).is_err());
        assert!(AnalysisStore::open("relative-analysis").is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_batch_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let first = b"first".as_slice();
        let second = b"second".as_slice();
        let third = b"third".as_slice();

        let pending = batch(2, &[second]);
        assert_eq!(
            store.accept_validated_batch(identity.clone(), pending.clone())?,
            EvidenceStoreOutcomeV1::Pending
        );
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            0
        );
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &[first]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(store.meta()?.commit_revision, 2);
        {
            let writer_guard = store.writer()?;
            let writer = writer_guard.get()?;
            let changed: u64 = writer.query_row(
                "SELECT COUNT(*) FROM relation_revisions WHERE last_changed_revision = 2",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(changed, 2);
            assert!(writer.prepare("SELECT * FROM events").is_err());
        }
        assert_eq!(
            store.read_page(&identity, 2)?.records[0].position,
            StorePositionV1 {
                commit_revision: 1,
                ordinal: 0
            }
        );
        assert_eq!(
            store.accept_validated_batch(identity.clone(), pending)?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, 2);

        assert!(store
            .accept_validated_batch(identity.clone(), batch(2, &[b"changed"]))
            .is_err());
        assert_eq!(store.meta()?.commit_revision, 2);

        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(4, &[third]))?,
            EvidenceStoreOutcomeV1::Pending
        );
        assert!(store
            .accept_validated_batch(identity.clone(), batch(3, &[third, b"changed"]))
            .is_err());
        assert_eq!(store.meta()?.commit_revision, 3);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            3
        );
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(
            reopened
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        assert_eq!(
            reopened.accept_validated_batch(identity.clone(), batch(3, &[third]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            reopened
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            4
        );
        let mut relabeled = identity.clone();
        relabeled.label_epoch += 1;
        assert!(reopened
            .accept_validated_batch(relabeled, batch(1, &[b"first"]))
            .is_err());
        let mut rebooted = identity.clone();
        rebooted.node_boot_id = [9; 16];
        assert!(reopened
            .accept_validated_batch(rebooted, batch(1, &[first]))
            .is_err());
        let mut changed_cpu = batch(5, &[first]);
        changed_cpu.cpu_id = 1;
        assert!(reopened
            .accept_validated_batch(identity.clone(), changed_cpu)
            .is_err());
        reopened.accept_validated_batch(identity.clone(), batch(5, &[first, second, third]))?;
        assert_eq!(
            reopened
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            7
        );
        assert_eq!(
            reopened
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .index
                .ranges
                .keys()
                .filter(|(key, _)| key == &identity.key())
                .count(),
            5
        );

        let revision = reopened.meta()?.commit_revision;
        reopened.accept_validated_coverage(coverage(&identity, 1, b"coverage"))?;
        assert_eq!(*reopened.subscribe_revision().borrow(), revision + 1);
        reopened.recover()?;
        reopened.accept_validated_batch(identity.clone(), batch(8, &[first]))?;
        assert_eq!(reopened.meta()?.commit_revision, revision + 2);
        assert_eq!(*reopened.subscribe_revision().borrow(), revision + 2);
        assert_eq!(
            reopened.read_page(&identity, 8)?.records[0]
                .position
                .commit_revision,
            revision + 2
        );
        let reader = reopened.reader()?;
        let changes: Vec<(String, u64)> = reader
            .get()?
            .prepare("SELECT relation_name, last_changed_revision FROM relation_revisions ORDER BY relation_name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<duckdb::Result<_>>()?;
        assert_eq!(
            changes,
            vec![
                ("coverage".into(), revision + 1),
                ("events".into(), revision + 2),
                ("source_bindings".into(), 1),
                ("source_receipts".into(), revision + 2),
            ]
        );
        Ok(())
    }

    #[test]
    fn analysis_store_bulk_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let maximum = EVIDENCE_BATCH_RECORDS + 1;
        store.accept_validated_batch(identity.clone(), batch(maximum as u64, &[b"frame"]))?;
        let before = store.meta()?;
        let mut changes = store.subscribe_revision();
        let _revision = *changes.borrow_and_update();
        let mut records = vec![b"frame".as_slice(); maximum];
        records[maximum - 1] = b"conflict";
        assert!(store
            .accept_validated_batch(identity.clone(), batch(1, &records))
            .is_err());
        assert_eq!(store.meta()?, before);
        assert!(!changes.has_changed()?);
        assert_eq!(
            store
                .source_status(&identity)?
                .ok_or("source absent")?
                .retained_event_count,
            1
        );
        records[maximum - 1] = b"frame";
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
        let revision = store.meta()?.commit_revision;
        store.accept_validated_batch(identity.clone(), batch(1, &records))?;
        assert_eq!(store.meta()?.commit_revision, revision);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        let status = reopened.source_status(&identity)?.ok_or("source absent")?;
        assert_eq!(status.retained_event_count, maximum as u64);
        assert_eq!(status.receipt.contiguous_cursor, maximum as u64);
        Ok(())
    }

    #[test]
    fn analysis_store_bounded_read() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let identity = identity();
        let mut changed = store.subscribe_revision();
        assert_eq!(*changed.borrow_and_update(), 0);
        let records = vec![b"one".as_slice(); 2 * MAX_ANALYSIS_PAGE_RECORDS + 1];
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert!(changed.has_changed()?);
        assert_eq!(*changed.borrow_and_update(), 1);
        let page = store.read_page(&identity, 1)?;
        assert_eq!(page.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(page.encoded_bytes, 3 * MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(page.next_cursor, Some(257));
        assert_eq!(page.read_revision, 1);
        assert_eq!(page.records[0].position.commit_revision, 1);
        assert_eq!(page.records[0].position.ordinal, 0);
        assert_eq!(page.records[255].position.ordinal, 255);
        let middle = store.read_page(&identity, 257)?;
        assert_eq!(middle.records.len(), MAX_ANALYSIS_PAGE_RECORDS);
        assert_eq!(middle.records[0].cursor, 257);
        assert_eq!(middle.records[255].cursor, 512);
        assert_eq!(middle.next_cursor, Some(513));
        let last = store.read_page(&identity, 513)?;
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.next_cursor, None);
        let empty = store.read_page(&identity, 514)?;
        assert!(empty.records.is_empty());
        assert_eq!(empty.next_cursor, None);
        assert!(store.read_page(&identity, 0).is_err());
        assert!(store.read_page(&identity, 515).is_err());
        let mut foreign = identity.clone();
        foreign.tenant_id = [4; 16];
        assert!(store.read_page(&foreign, 1).is_err());
        assert_eq!(
            store.accept_validated_batch(identity.clone(), batch(1, &records))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert!(!changed.has_changed()?);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(*reopened.subscribe_revision().borrow(), 1);
        assert_eq!(reopened.read_page(&identity, 257)?, middle);
        assert_eq!(reopened.read_page(&identity, 513)?, last);
        let mut large = identity.clone();
        large.source_epoch = 2;
        let frame = vec![42; MAX_ANALYSIS_PAGE_BYTES / 8];
        let frames = vec![frame.as_slice(); 9];
        reopened.accept_validated_batch(large.clone(), batch(1, &frames))?;
        let page = reopened.read_page(&large, 1)?;
        assert_eq!(page.records.len(), 8);
        assert_eq!(page.encoded_bytes, MAX_ANALYSIS_PAGE_BYTES);
        assert_eq!(page.next_cursor, Some(9));
        assert_eq!(
            reopened.read_page(&large, 9)?.records[0].framed_record,
            frame
        );
        {
            let writer = reopened.writer()?;
            writer.get()?.execute(
                "DELETE FROM segments WHERE stream_key = ?",
                params![identity.key().as_slice()],
            )?;
        }
        assert_eq!(
            reopened.read_page(&identity, 1)?.records.len(),
            MAX_ANALYSIS_PAGE_RECORDS
        );
        assert!(reopened.recover().is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_coverage_receipt() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        let mut identity = identity();
        identity.node_id = "n".repeat(128);
        assert_eq!(store.source_status(&identity)?, None);
        let accepted = coverage(&identity, 1, b"coverage-1");
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);
        assert_eq!(
            store
                .writer()?
                .get()?
                .query_row("SELECT count(*) FROM coverage", [], |row| row
                    .get::<_, u64>(0))?,
            1
        );
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        assert_eq!(receipt.contiguous_cursor, 0);
        assert_eq!(receipt.coverage_revision, 1);
        let status = store.source_status(&identity)?.ok_or("status absent")?;
        assert_eq!(status.receipt, receipt);
        assert_eq!(status.retained_event_count, 0);
        assert_eq!(status.latest_coverage_report, Some(b"coverage-1".to_vec()));
        assert_eq!(store.accept_validated_coverage(accepted.clone())?, 1);
        assert_eq!(store.meta()?.commit_revision, 1);
        assert_eq!(
            store
                .writer()?
                .get()?
                .query_row("SELECT count(*) FROM coverage", [], |row| row
                    .get::<_, u64>(0))?,
            1
        );

        let conflicting = coverage(&identity, 1, b"changed");
        assert!(store.accept_validated_coverage(conflicting).is_err());
        assert_eq!(store.meta()?.commit_revision, 1);

        let newer = coverage(&identity, 3, b"coverage-3");
        assert_eq!(store.accept_validated_coverage(newer)?, 3);
        assert_eq!(store.meta()?.commit_revision, 2);
        let stale = coverage(&identity, 2, b"coverage-2");
        assert!(store.accept_validated_coverage(stale).is_err());
        assert_eq!(store.meta()?.commit_revision, 2);
        assert_eq!(
            store
                .writer()?
                .get()?
                .query_row("SELECT count(*) FROM coverage", [], |row| row
                    .get::<_, u64>(0))?,
            2
        );
        AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(reopened.meta()?.commit_revision, 2);
        let receipt = reopened
            .source_receipt(&identity)?
            .ok_or("receipt absent")?;
        assert_eq!(receipt.coverage_revision, 3);
        assert_eq!(receipt.contiguous_cursor, 0);
        let status = reopened.source_status(&identity)?.ok_or("status absent")?;
        assert_eq!(status.receipt, receipt);
        assert_eq!(status.latest_coverage_report, Some(b"coverage-3".to_vec()));
        {
            let writer_guard = reopened.writer()?;
            let writer = writer_guard.get()?;
            assert_eq!(
                writer.query_row("SELECT count(*) FROM coverage", [], |row| row
                    .get::<_, u64>(0))?,
                2
            );
            AnalysisStore::validate_state(writer, &root)?;
            let changed: u64 = writer.query_row(
                "SELECT COUNT(*) FROM relation_revisions WHERE last_changed_revision = 2",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(changed, 2);
            writer.execute(
                "UPDATE coverage SET report = ? WHERE revision = 3",
                params![Vec::<u8>::new()],
            )?;
        }
        assert!(reopened.source_status(&identity).is_err());
        Ok(())
    }

    #[test]
    fn analysis_store_limit_edges() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut source = identity();
        source.node_id = "n".repeat(crate::MAX_NODE_ID_BYTES);
        let mut max_batch = ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: EVIDENCE_BATCH_RECORDS as u64,
            intake_utc_ns: 1_000_000_000,
            framed_records: vec![1; EVIDENCE_BATCH_RECORDS].into(),
            frame_ends: (1..=EVIDENCE_BATCH_RECORDS).collect(),
        };
        store.validate_batch(&source, &max_batch)?;
        max_batch.last_cursor += 1;
        max_batch.framed_records = vec![1; EVIDENCE_BATCH_RECORDS + 1].into();
        max_batch.frame_ends.push(EVIDENCE_BATCH_RECORDS + 1);
        store.validate_batch(&source, &max_batch)?;
        source.node_id.push('n');
        assert!(store
            .validate_batch(&source, &batch(1, &[b"first"]))
            .is_err());
        source.node_id.pop();

        let pending = EVIDENCE_BATCH_RECORDS as u64 + 2;
        assert_eq!(
            store.accept_validated_batch(source.clone(), batch(pending, &[b"gap"]))?,
            EvidenceStoreOutcomeV1::Pending
        );
        let revision = store.meta()?.commit_revision;
        let root = store.root.clone();
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, revision);
        assert_eq!(
            store.accept_validated_batch(
                source.clone(),
                batch(1, &vec![b"frame".as_slice(); pending as usize - 1])
            )?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(
            store
                .source_receipt(&source)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            pending
        );
        let report = vec![1; 4 * 1_024 * 1_024 + 1];
        store.accept_validated_coverage(coverage(&source, 1, &report))?;
        assert_eq!(
            store
                .source_status(&source)?
                .ok_or("source absent")?
                .latest_coverage_report,
            Some(report)
        );
        Ok(())
    }

    #[test]
    fn analysis_store_crash_replay() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let identity = identity();
        if let Some(root) = std::env::var_os("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT") {
            let store = AnalysisStore::open(PathBuf::from(root))?;
            assert_eq!(
                store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
                EvidenceStoreOutcomeV1::Accepted
            );
            std::process::exit(73);
        }

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let status = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("analysis::tests::analysis_store_crash_replay")
            .env("ARAPHOR_ANALYSIS_CRASH_PROOF_ROOT", &root)
            .status()?;
        assert_eq!(status.code(), Some(73));
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, 1);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent after crash")?
                .contiguous_cursor,
            1
        );
        assert_eq!(
            store.accept_validated_batch(identity, batch(1, &[b"first"]))?,
            EvidenceStoreOutcomeV1::Accepted
        );
        assert_eq!(store.meta()?.commit_revision, 1);
        Ok(())
    }
}
