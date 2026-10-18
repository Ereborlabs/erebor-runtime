use std::sync::{Arc, Mutex};

use araphor_data::*;

use crate::{InstalledAnalysis, Result};

mod chunks;
mod commit;
mod contract;
mod coverage;
mod derive;
mod expiry;
mod input;
mod installed;
mod live;
mod read;
#[cfg(test)]
pub(crate) mod tests;
mod window;

pub trait GraphContextProvider: Send + Sync {
    fn facts(
        &self,
        record: &DiscoveryRecordV1,
    ) -> araphor_data::Result<Vec<AnalysisContextVersionV1>>;

    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> araphor_data::Result<u64> {
        Ok(0)
    }
}

pub struct GraphAndFindingOwner {
    store: Arc<AnalysisStore>,
    execution: InstalledAnalysis,
    provider: Arc<dyn GraphContextProvider>,
    operation: Mutex<(Option<EvidenceIntakeIdentityV1>, Option<InstalledAnalysis>)>,
}

impl GraphAndFindingOwner {
    pub fn new(
        store: Arc<AnalysisStore>,
        provider: Arc<dyn GraphContextProvider>,
        execution: InstalledAnalysis,
    ) -> Result<Self> {
        store.enable_graph_owner()?;
        let owner = Self {
            store,
            execution,
            provider,
            operation: Mutex::new((None, None)),
        };
        let mut tenant = None;
        loop {
            let tenants = owner.store.tenant_page(tenant)?;
            if tenants.is_empty() {
                break;
            }
            tenant = tenants.last().copied();
            for tenant in tenants {
                let mut after = None;
                loop {
                    let sources = owner.store.source_page(tenant, after.as_ref())?;
                    if sources.is_empty() {
                        break;
                    }
                    after = sources.last().cloned();
                    for source in sources {
                        owner.store.register_graph(&source)?;
                    }
                }
            }
        }
        Ok(owner)
    }
}

impl Drop for GraphAndFindingOwner {
    fn drop(&mut self) {
        self.store.release_graph_owner();
    }
}
