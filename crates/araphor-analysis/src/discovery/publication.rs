use araphor_data::{
    AnalysisContextRefV1, AnalysisGapV1, DiscoverySnapshotRowV1, EvidenceIntakeIdentityV1,
};
use serde::Deserialize;

mod managed;

#[derive(Deserialize)]
pub(super) struct Publication {
    source: EvidenceIntakeIdentityV1,
    current_result_id: Option<String>,
    result_commit_revision: Option<u64>,
    #[serde(default)]
    repair: bool,
    #[serde(default)]
    notice_only: bool,
    #[serde(default)]
    notice_facts_revision: u64,
    #[serde(default)]
    notice_coverage_revision: u64,
    expected_cursor: u64,
    consumed_cursor: u64,
    processor_present: bool,
    retired: Option<bool>,
    coverage_revision: u64,
    interval_id: Option<String>,
    profile_revision: Option<u64>,
    facts_revision: Option<u64>,
    created_utc_ns: Option<u64>,
    updated_utc_ns: Option<u64>,
    sealed: Option<bool>,
    input_bytes: Option<u64>,
    incomplete: Option<bool>,
    gaps: Option<Vec<AnalysisGapV1>>,
    context_refs: Option<Vec<AnalysisContextRefV1>>,
    snapshot: DiscoverySnapshotRowV1,
}
