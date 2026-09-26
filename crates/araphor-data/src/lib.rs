//! Durable data owners shared by embedded and remote Araphor deployments.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};

mod analysis;

pub use analysis::{
    AnalysisBackupManifestV1, AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1,
    AnalysisProcessorGapV1, AnalysisReadPageV1, AnalysisRecordV1, AnalysisRecoveryStatusV1,
    AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisSourceReceiptV1,
    AnalysisSourceStatusV1, AnalysisStore, AnalysisStoreMetaV1, AnalysisWitnessV1,
    ContextSensitivityV1, EvidenceRetentionOwner, EvidenceStoreOutcomeV1, LegacySourceImportV1,
    ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1, RetentionResultV1, StorePositionV1,
    ValidatedCoverageV1, ValidatedEvidenceBatchV1, ANALYSIS_DUCKDB_BINDING_VERSION,
    ANALYSIS_SQLPARSER_VERSION,
};

pub const MAX_EVIDENCE_BATCH_RECORDS: usize = 4_096;
pub const MAX_EVIDENCE_GRPC_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES: usize = 128 * 1_024 * 1_024;
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

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Analysis database operation {operation} failed: {source}"))]
    AnalysisDatabase {
        operation: &'static str,
        source: duckdb::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis store `{}` is invalid: {reason}", path.display()))]
    AnalysisState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis evidence range {first_cursor}..={last_cursor} has expired"))]
    RetainedRangeExpired {
        first_cursor: u64,
        last_cursor: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis progress or immutable result conflicts with committed state"))]
    AnalysisConflict {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis JSON `{}` failed: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
