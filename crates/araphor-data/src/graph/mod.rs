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
pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

impl GraphSnapshotV1 {
    pub fn retained_input_expired(&self) -> bool {
        self.missing_ranges
            .contains(&(self.first_cursor, self.last_cursor))
            && self.findings.iter().all(|finding| {
                finding
                    .limits
                    .iter()
                    .any(|limit| limit == "RETAINED_INPUT_EXPIRED")
            })
    }
}
