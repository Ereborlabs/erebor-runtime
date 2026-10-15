use std::sync::Arc;

use crate::{AnalysisStore, QueryOwner};

mod admission;
mod bundle;
mod evaluation;
mod execution;
mod fixtures;
mod freshness;
mod inspect;
mod installed;
mod lifecycle;
mod model;
pub mod native;
mod oci;
mod output;
mod owner;
mod removal;
mod required;
mod status;
pub(crate) mod storage;
mod supervision;
pub(super) mod wasm;

pub use bundle::*;
pub(crate) use evaluation::ResultContext;
pub use fixtures::PackageFixtureV1;
pub use installed::{InstalledAnalysis, InstalledEvaluation, InstalledRefV1};
pub use model::*;
pub(crate) use owner::InstalledContext;

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
