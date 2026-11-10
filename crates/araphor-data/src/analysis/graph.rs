use super::{AnalysisResultCommitV1, AnalysisContextVersionV1, AnalysisContextRefV1};

pub use araphor_analysis_types::GraphManifest;

pub struct GraphSourceSummary {
    pub manifest: GraphManifest,
    pub restricted_count: Option<u64>,
    pub expired: bool,
}

pub struct GraphCommit {
    pub input_proof: Option<std::sync::Arc<crate::InputProof>>,
    pub request: AnalysisResultCommitV1,
    pub metadata: GraphManifest,
    pub contexts: Vec<AnalysisContextVersionV1>,
    /// Global proof refs. Exclude fact refs and record proof refs.
    pub proofs: Vec<AnalysisContextRefV1>,
    /// Upstream proof refs for each changed source record.
    pub record_proofs: Vec<(crate::DiscoveryRecordIdV1, AnalysisContextRefV1)>,
    pub sources: Vec<(String, u64)>,
    /// Source records absent from the after set.
    pub removed: Vec<crate::DiscoveryRecordIdV1>,
    pub advance: bool,
    pub expire: bool,
}

