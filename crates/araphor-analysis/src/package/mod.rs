use std::sync::Arc;

use crate::{AnalysisStore, Engine};

mod evaluation;
mod execution;
mod fixtures;
mod freshness;
mod inspect;
mod installed;
mod lifecycle;
pub mod native;
mod output;
mod owner;
mod removal;
mod required;
mod status;
mod supervision;
pub(super) mod wasm;

pub(crate) use araphor_data::{
    InstalledRefV1, PackageActionV1, PackageArtifactIdentityV1, PackageArtifactV1,
    PackageAuthorization, PackageBundleRef, PackageBundleV1, PackageErrorCodeV1,
    PackageExportStatusV1, PackageFixtureV1, PackageGrantV1, PackageImplementationV1,
    PackageReadinessV1, PackageReceiptV1, PackageRefV1, PackageRequestV1, PackageResponseV1,
    PackageTestResultV1,
};
pub use installed::{InstalledAnalysis, InstalledEvaluation};
#[cfg(test)]
pub(crate) use owner::InstalledContext;

pub struct AnalysisPackageOwner {
    store: Arc<AnalysisStore>,
    pub(crate) query: Arc<Engine>,
    authority: Arc<dyn PackageAuthorization>,
    operations: Arc<tokio::sync::Semaphore>,
    lifecycle: Arc<std::sync::Mutex<()>>,
    wasm: wasm::WasmExecution,
    pub(crate) limits: crate::AnalysisLimits,
}

#[cfg(test)]
pub(crate) mod tests;
