//! Durable data owners shared by embedded and remote Araphor deployments.

pub mod analysis;
mod canonical;
mod digest;
mod discovery;
mod error;
mod evidence;
mod graph;
mod notification;
mod package;
mod trace;
mod workload;

pub use canonical::encode_value;
pub use digest::{DiscoveryDigestV1, InputRevision};
pub use discovery::*;
pub(crate) use error::*;
pub use error::{
    AnalysisContractSnafu, DiscoveryConflictSnafu, DiscoveryEncodingSnafu, DiscoveryInvalidSnafu,
    EvidenceDecodeSnafu, GraphEncodingSnafu, GraphInvalidSnafu, NotificationEncodingSnafu,
    NotificationSnafu, PackageEncodingSnafu, PackageSnafu, RetainedRangeExpiredSnafu,
};
pub use error::{Error, Result};
pub use evidence::{
    BindingLifecycleV1, CompiledOperationV1, CoverageCounters, CoverageInterval, CoverageReport,
    EffectFamilyV1, EntryKindV1, EvidenceDecisionCatalogV1, EvidenceDecisionContext,
    EvidenceDigestV1, EvidenceExactFileObject, EvidenceFileObjectV1, EvidenceIdV1,
    EvidenceModelError, EvidenceModelResult, EvidenceRecord, EvidenceRecords,
    EvidenceTemporalCoverage, KernelEffectEvidenceV1, ObservationEnvelopeV1, StaticDecisionKeyV1,
    MAX_EVIDENCE_DECISION_CONTEXT_BYTES, MAX_EVIDENCE_RECORD_BYTES,
};
pub use graph::*;
pub use notification::*;
pub use package::*;
pub use trace::{
    TraceBatchV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceMeasurementV1, TraceRecipeManifestV1, TraceRecipeV1, TraceSourceV1, TraceTerminalReasonV1,
    TraceTerminalV1, MAX_TRACE_FRAME_BYTES, MAX_TRACE_OUTPUT_BYTES, MAX_TRACE_SOURCE_BYTES,
    MAX_TRACE_TARGETS,
};
pub use workload::{
    ContainerKindV1, KubernetesWorkloadIdentityV1, TargetContextV1, WorkloadTargetFactV1,
};

#[cfg(any(test, feature = "test-fixtures"))]
pub use analysis::RetentionResultV1;
pub use analysis::{
    AnalysisBackupManifestV1, AnalysisBackupSegmentV1, AnalysisContextKeyV1, AnalysisContextRefV1,
    AnalysisContextVersionV1, AnalysisExtractLimits, AnalysisExtractionV1, AnalysisGapV1,
    AnalysisInputTables, AnalysisPositionPageV1, AnalysisProcessorResultV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisReadPageV1, AnalysisRecordV1, AnalysisRecoveryStatusV1,
    AnalysisReferenceOriginV1, AnalysisReferenceV1, AnalysisResultCommitV1,
    AnalysisResultReceiptV1, AnalysisSelectionV1, AnalysisSourceReceiptV1,
    AnalysisSourceSnapshotV1, AnalysisSourceStatusV1, AnalysisStore, AnalysisStoreMetaV1,
    AnalysisStreamIdentityV1, AnalysisTableRead, AnalysisTableRequests, AnalysisWitnessV1,
    ContextSensitivityV1, EvidenceRetentionOwner, EvidenceStoreOutcomeV1, ProcessorClassV1,
    ProcessorHealthV1, ProcessorRetirementV1, ProcessorScopeV1, ProcessorStateV1,
    RetentionLimitsV1, RetentionStepV1, SegmentFile, Selection, StorageHealthV1, StorageLimitsV1,
    StorageUsageV1, StorePositionV1, TraceBindingV1, TraceIntentPageV1, TraceIntentV1,
    TraceOutputPageV1, TraceOutputReceiptV1, TraceStateV1, ValidatedCoverageV1,
    ValidatedEvidenceBatchV1, WitnessUsageV1, ANALYSIS_DUCKDB_BINDING_VERSION,
    ANALYSIS_SQLPARSER_VERSION, MAX_EVIDENCE_SEGMENT_BYTES,
};

pub const MAX_EVIDENCE_BATCH_RECORDS: usize = 4_096;
pub const MAX_EVIDENCE_GRPC_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_PENDING_EVIDENCE_RECORDS: u64 = 4_096;
pub use araphor_analysis_builtins::discovery::{
    node_id_is_valid, EvidenceIntakeIdentityV1, MAX_NODE_ID_BYTES,
};

#[cfg(any(test, feature = "test-fixtures"))]
pub use analysis::AnalysisCommitStage;

pub use analysis::{
    ManagedAttempt, ManagedCall, ManagedCapture, ManagedCommit, ManagedFrontier, ManagedInstance,
    ManagedManifest, ManagedPage, ManagedPrior, ManagedRead, ManagedReceipt, ManagedRequest,
    ManagedResult, ManagedReturn, ManagedSelected, ManagedSpec,
};
