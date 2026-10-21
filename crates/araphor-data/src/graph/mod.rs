mod contract;
mod input;
mod model;
mod proof;
mod traversal;

pub use model::*;
pub use proof::*;
pub use traversal::*;

pub const GRAPH_PROCESSOR: &str = "graph-findings";
pub const GRAPH_SCHEMA_VERSION: u32 = 1;
pub const GRAPH_WINDOW_RECORDS: u64 = u64::MAX;
pub const GRAPH_WINDOW_BYTES: usize = usize::MAX;
pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

impl GraphSnapshotV1 {
    pub fn package_key(
        source: &crate::EvidenceIntakeIdentityV1,
        result_id: &str,
    ) -> crate::AnalysisContextKeyV1 {
        crate::AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "graph-packages-v1".into(),
            entity_key: result_id.as_bytes().to_vec(),
            lifetime_key: source.key(),
            owner_revision: GRAPH_SCHEMA_VERSION as u64,
        }
    }
}
