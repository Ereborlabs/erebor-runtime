pub use araphor_analysis_types::GraphManifest;

pub struct GraphSourceSummary {
    pub manifest: GraphManifest,
    pub restricted_count: Option<u64>,
    pub expired: bool,
}
