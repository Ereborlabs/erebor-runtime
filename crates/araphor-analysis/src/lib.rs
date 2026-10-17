use araphor_data::analysis;
use araphor_data::*;
pub(crate) use araphor_data::{
    DiscoveryConflictSnafu, DiscoveryEncodingSnafu, DiscoveryInvalidSnafu, EvidenceDecodeSnafu,
    GraphEncodingSnafu, GraphInvalidSnafu, NotificationSnafu, RetainedRangeExpiredSnafu,
};
use araphor_query::execution::Engine;
#[cfg(test)]
use araphor_query::execution::Limits;

mod discovery;
mod error;
mod graph;
mod limits;
mod model;
mod notification;
mod package;
#[cfg(test)]
mod testing;

pub use discovery::{DiscoveryContextProvider, DiscoveryOwner};
pub(crate) use error::{
    AnalysisBusySnafu, AnalysisContractSnafu, AnalysisExecutionSnafu, IoSnafu, ModelInvalidSnafu,
    ModelLimitSnafu, PackageArrowSnafu, PackageEncodingSnafu, PackageNativeSnafu, PackageWasmSnafu,
};
pub use error::{Error, Result};
pub use graph::{GraphAndFindingOwner, GraphContextProvider};
pub use limits::{AnalysisLimits, WasmLimits};
pub use model::{ModelRun, SqlDatasetOutputV1, SqlModelOutputV1};
pub use notification::NotificationRouter;
pub use package::native::NativeLimits;
pub use package::{AnalysisPackageOwner, InstalledAnalysis, InstalledEvaluation};
