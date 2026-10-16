use serde::{Deserialize, Serialize};

mod context;
mod derive;
mod model;
mod profile;

pub use context::*;
pub use model::*;
pub use profile::{DiscoveryProfileV1, DiscoveryReplayV1};

pub const DISCOVERY_PROCESSOR: &str = "discovery";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfigV1 {
    pub interval_records: usize,
    pub input_bytes: usize,
    pub atom_limit: usize,
    pub sources_per_pass: usize,
    pub seal_interval_ns: u64,
    pub witness_age_ns: u64,
}

impl Default for DiscoveryConfigV1 {
    fn default() -> Self {
        Self {
            interval_records: MAX_DISCOVERY_RECORDS,
            input_bytes: DISCOVERY_INPUT_BYTES,
            atom_limit: MAX_DISCOVERY_ATOMS,
            sources_per_pass: 16,
            seal_interval_ns: 300_000_000_000,
            witness_age_ns: 7 * 24 * 60 * 60 * 1_000_000_000,
        }
    }
}

impl DiscoveryConfigV1 {
    pub fn valid(&self) -> bool {
        (1..=MAX_DISCOVERY_RECORDS).contains(&self.interval_records)
            && (1..=DISCOVERY_INPUT_BYTES).contains(&self.input_bytes)
            && (1..=MAX_DISCOVERY_ATOMS).contains(&self.atom_limit)
            && (1..=256).contains(&self.sources_per_pass)
            && self.seal_interval_ns > 0
            && self.witness_age_ns > 0
            && self.witness_age_ns <= 7 * 24 * 60 * 60 * 1_000_000_000
    }
}
