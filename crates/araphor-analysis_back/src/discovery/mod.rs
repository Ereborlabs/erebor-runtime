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

    /// Return None only when context changes already produce a Data notice.
    fn changes(&self) -> araphor_data::Result<Option<tokio::sync::watch::Receiver<u64>>> {
        Ok(None)
    }

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
        provider: Arc<dyn DiscoveryContextProvider>,
        config: DiscoveryConfigV1,
        mut execution: InstalledAnalysis,
    ) -> Result<Self> {
        model::require(config.valid(), "configuration")?;
        let store = Arc::clone(execution.owner.query.store());
        store.register_discovery_owner();
        execution.memory = execution.owner.query.memory().scope();
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
