use std::sync::{Arc, Mutex};

use crate::{AnalysisContextVersionV1, AnalysisStore, DiscoveryRecordV1, Result};

mod chunks;
mod commit;
mod coverage;
mod derive;
mod expiry;
mod input;
mod live;
mod model;
mod proof;
mod read;
#[cfg(test)]
pub(crate) mod tests;
mod window;

pub use model::*;
pub use proof::*;

pub const GRAPH_PROCESSOR: &str = "graph-findings";
pub const GRAPH_SCHEMA_VERSION: u32 = 1;
pub const GRAPH_WINDOW_RECORDS: u64 = 256;
pub const GRAPH_WINDOW_BYTES: usize = crate::analysis::NATIVE_MEMORY_BYTES / 16;
pub const GRAPH_WINDOW_NS: u64 = 300_000_000_000;
pub const GRAPH_WITNESS_TTL_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

pub trait GraphContextProvider: Send + Sync {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>>;

    fn revision(&self, _source: &crate::EvidenceIntakeIdentityV1) -> Result<u64> {
        Ok(0)
    }
}

pub struct GraphAndFindingOwner {
    store: Arc<AnalysisStore>,
    provider: Arc<dyn GraphContextProvider>,
    operation: Mutex<Option<crate::EvidenceIntakeIdentityV1>>,
}

impl GraphAndFindingOwner {
    pub fn new(store: Arc<AnalysisStore>, provider: Arc<dyn GraphContextProvider>) -> Result<Self> {
        store.enable_graph_owner()?;
        let owner = Self {
            store,
            provider,
            operation: Mutex::new(None),
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
        self.store
            .graph_owner
            .store(false, std::sync::atomic::Ordering::Release);
    }
}
