//! Durable data owners shared by embedded and remote Araphor deployments.

use serde::{Deserialize, Serialize};

mod analysis;
mod canonical;
mod digest;
mod discovery;
mod error;
mod evidence;
mod graph;
mod notification;
mod query;
mod trace;
mod workload;

pub use canonical::encode_value;
pub use digest::DiscoveryDigestV1;
pub use discovery::*;
pub(crate) use error::*;
pub use error::{Error, Result};
pub use evidence::{
    CoverageCounters, CoverageInterval, CoverageReport, EvidenceDecisionContext,
    EvidenceExactFileObject, EvidenceRecord, EvidenceRecords, EvidenceTemporalCoverage,
    MAX_EVIDENCE_RECORD_BYTES,
};
pub use graph::*;
pub use notification::*;
pub use query::{
    Column, GraphAnalysisInputsV1, QueryAuthorization, QueryBinding, QueryCheckpoint, QueryClock,
    QueryColumn, QueryCoverage, QueryCoverageRows, QueryCoverageState, QueryErrorCode, QueryFrame,
    QueryGrant, QueryHealth, QueryLimits, QueryMetadata, QueryOperation, QueryOwner, QueryPayload,
    QueryPlan, QueryResult, QuerySql, QueryStream, QueryTemplate, QueryTerminalReason,
    SystemQueryClock, QUERY_CHECKPOINT_BYTES, QUERY_SCHEMA_VERSION,
};
pub use trace::{
    TraceBatchV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceMeasurementV1, TraceRecipeManifestV1, TraceRecipeV1, TraceSourceV1, TraceTerminalReasonV1,
    TraceTerminalV1, MAX_TRACE_FRAME_BYTES, MAX_TRACE_OUTPUT_BYTES, MAX_TRACE_SOURCE_BYTES,
    MAX_TRACE_TARGETS,
};
pub use workload::{ContainerKindV1, KubernetesWorkloadIdentityV1, WorkloadTargetFactV1};

pub use analysis::{
    AnalysisBackupManifestV1, AnalysisBackupSegmentV1, AnalysisContextKeyV1, AnalysisContextRefV1,
    AnalysisContextVersionV1, AnalysisExtractionV1, AnalysisGapV1, AnalysisInputPageV1,
    AnalysisInputV1, AnalysisPositionPageV1, AnalysisProcessorResultV1, AnalysisReadControl,
    AnalysisReadPageV1, AnalysisRecordV1, AnalysisRecoveryStatusV1, AnalysisRelationV1,
    AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisSelectionV1, AnalysisSourceReceiptV1,
    AnalysisSourceSnapshotV1, AnalysisSourceStatusV1, AnalysisStore, AnalysisStoreMetaV1,
    AnalysisStreamIdentityV1, AnalysisWitnessV1, ContextSensitivityV1, EvidenceRetentionOwner,
    EvidenceStoreOutcomeV1, ProcessorClassV1, ProcessorHealthV1, ProcessorRetirementV1,
    ProcessorScopeV1, ProcessorStateV1, RetentionLimitsV1, RetentionResultV1, RetentionSweepV1,
    SegmentFile, Selection, StorageHealthV1, StorageLimitsV1, StorageUsageV1, StorePositionV1,
    TraceBindingV1, TraceIntentPageV1, TraceIntentV1, TraceOutputPageV1, TraceOutputReceiptV1,
    TraceStateV1, ValidatedCoverageV1, ValidatedEvidenceBatchV1, WitnessUsageV1,
    ANALYSIS_DUCKDB_BINDING_VERSION, ANALYSIS_SQLPARSER_VERSION, MAX_EVIDENCE_SEGMENT_BYTES,
};

pub const MAX_EVIDENCE_BATCH_RECORDS: usize = 4_096;
pub const MAX_EVIDENCE_GRPC_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_PENDING_EVIDENCE_RECORDS: u64 = 4_096;
pub const MAX_NODE_ID_BYTES: usize = 128;

#[must_use]
pub fn node_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NODE_ID_BYTES
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_whitespace)
        && !value.contains(['/', '\\', '\0'])
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
/// Separates retained input by authenticated source and source epoch.
pub struct EvidenceIntakeIdentityV1 {
    pub tenant_id: [u8; 16],
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub label_epoch: u64,
    pub source_id: [u8; 16],
    pub source_epoch: u64,
}

#[cfg(any(test, feature = "test-fixtures"))]
pub use analysis::AnalysisCommitStage;
