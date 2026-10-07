use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::{AnalysisStore, Result};

mod context;
mod derive;
mod live;
mod model;
mod replay;

pub use context::*;
pub use live::DiscoveryProfileV1;
pub use model::*;
pub use replay::DiscoveryReplayV1;

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

pub trait DiscoveryContextProvider: Send + Sync {
    fn context(&self, record: &DiscoveryRecordV1) -> Result<DiscoveryContextJoinV1>;

    fn revision(&self, _source: &crate::EvidenceIntakeIdentityV1) -> Result<u64> {
        Ok(0)
    }
}

pub struct DiscoveryOwner {
    store: Arc<AnalysisStore>,
    provider: Arc<dyn DiscoveryContextProvider>,
    config: DiscoveryConfigV1,
    operation: Mutex<Option<crate::EvidenceIntakeIdentityV1>>,
}

impl DiscoveryOwner {
    pub fn new(
        store: Arc<AnalysisStore>,
        provider: Arc<dyn DiscoveryContextProvider>,
        config: DiscoveryConfigV1,
    ) -> Result<Self> {
        model::require(config.valid(), "configuration")?;
        store
            .discovery_owners
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(Self {
            store,
            provider,
            config,
            operation: Mutex::new(None),
        })
    }
}

impl Drop for DiscoveryOwner {
    fn drop(&mut self) {
        self.store
            .discovery_owners
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
