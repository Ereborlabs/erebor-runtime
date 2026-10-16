use std::sync::{Arc, Mutex};

use araphor_data::*;

use crate::{InstalledAnalysis, Result};

mod context;
mod installed;
mod live;
mod model;
mod replay;
mod sdk;
#[cfg(test)]
pub(crate) mod tests;

pub trait DiscoveryContextProvider: Send + Sync {
    fn context(&self, record: &DiscoveryRecordV1) -> araphor_data::Result<DiscoveryContextJoinV1>;

    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> araphor_data::Result<u64> {
        Ok(0)
    }
}

pub struct DiscoveryOwner {
    store: Arc<AnalysisStore>,
    execution: InstalledAnalysis,
    provider: Arc<dyn DiscoveryContextProvider>,
    config: DiscoveryConfigV1,
    operation: Mutex<Option<EvidenceIntakeIdentityV1>>,
}

impl DiscoveryOwner {
    pub fn new(
        store: Arc<AnalysisStore>,
        provider: Arc<dyn DiscoveryContextProvider>,
        config: DiscoveryConfigV1,
        execution: InstalledAnalysis,
    ) -> Result<Self> {
        model::require(config.valid(), "configuration")?;
        store.register_discovery_owner();
        Ok(Self {
            store,
            execution,
            provider,
            config,
            operation: Mutex::new(None),
        })
    }
}

impl Drop for DiscoveryOwner {
    fn drop(&mut self) {
        self.store.release_discovery_owner();
    }
}
