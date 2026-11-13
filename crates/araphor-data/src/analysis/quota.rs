pub(super) const TRACE_RESERVE: u64 = 16 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WitnessUsageV1 {
    pub read_revision: u64,
    pub referenced_bytes: u64,
    pub evidence_bytes: u64,
    pub extra_evidence_bytes: u64,
    pub segment_bytes: u64,
    pub extra_segment_bytes: u64,
    pub context_bytes: u64,
    pub charged_bytes: u64,
}
