use std::sync::Arc;

use crate::{AnalysisStore, QueryOwner};

mod admission;
mod bundle;
mod evaluation;
mod fixtures;
mod freshness;
mod inputs;
mod inspect;
mod lifecycle;
mod model;
mod output;
mod owner;
mod removal;
mod status;
mod supervision;
mod wire;

pub use bundle::*;
pub use model::*;
pub use wire::*;

pub struct AnalysisPackageOwner {
    store: Arc<AnalysisStore>,
    query: Arc<QueryOwner>,
    authority: Arc<dyn PackageAuthorization>,
    operations: Arc<tokio::sync::Semaphore>,
    lifecycle: std::sync::Mutex<()>,
}

#[cfg(test)]
mod tests;
