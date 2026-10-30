pub(crate) mod contract;
mod input;
mod model;
mod proof;
mod revision;
mod traversal;

pub use model::*;
pub use proof::*;
pub use traversal::*;

pub const GRAPH_PROCESSOR: &str = "graph-findings";
pub const GRAPH_SCHEMA_VERSION: u32 = 1;
pub use araphor_analysis_builtins::graph::{GRAPH_WINDOW_NS, GRAPH_WITNESS_TTL_NS};

impl GraphSnapshotV1 {
    pub fn encode_native(&self) -> crate::Result<Vec<u8>> {
        use snafu::ResultExt as _;
        rmp_serde::to_vec_named(self).context(crate::GraphNativeEncodingSnafu)
    }

    pub fn decode_native(bytes: &[u8]) -> crate::Result<Self> {
        use serde::Deserialize as _;
        use snafu::ResultExt as _;

        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = Self::deserialize(&mut decoder).context(crate::GraphNativeDecodingSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return crate::GraphInvalidSnafu {
                field: "graph snapshot trailing bytes",
            }
            .fail();
        }
        value.validate()?;
        Ok(value)
    }

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
