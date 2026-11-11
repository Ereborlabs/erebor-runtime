use std::path::Path;

use uuid::Uuid;

use crate::{EvidenceIntakeIdentityV1, Result};

mod backup;
mod capacity;

mod context;
mod coverage;
#[cfg(any(test, feature = "test-fixtures"))]
mod crash;
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
pub use native::RawIndexFixture;
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
}
