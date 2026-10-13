use std::sync::Arc;

use crate::{AnalysisStore, QueryOwner};

mod admission;
mod bundle;
mod evaluation;
mod execution;
mod fixtures;
mod freshness;
mod inputs;
mod inspect;
mod installed;
mod lifecycle;
mod model;
pub mod native;
mod output;
mod owner;
mod removal;
mod required;
mod status;
mod supervision;
pub(super) mod wasm;
mod wire;

pub use bundle::*;
pub use installed::{InstalledAnalysis, InstalledEvaluation, InstalledRefV1};
pub use model::*;
pub use wire::*;

pub struct AnalysisPackageOwner {
    store: Arc<AnalysisStore>,
    query: Arc<QueryOwner>,
    authority: Arc<dyn PackageAuthorization>,
    operations: Arc<tokio::sync::Semaphore>,
    lifecycle: Arc<std::sync::Mutex<()>>,
    wasm: wasm::WasmExecution,
    native: native::NativeExecution,
}

#[cfg(test)]
pub(crate) mod tests;
