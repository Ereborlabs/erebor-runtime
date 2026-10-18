mod admission;
mod bundle;
mod error;
mod formats;
mod metadata;
pub mod native;
mod oci;

pub use admission::ModelRef;
pub use bundle::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1};
pub(crate) use error::{AnalysisContractSnafu, IoSnafu, PackageEncodingSnafu};
pub use error::{Error, ErrorCode, Result};
pub use formats::{PackageFixtureV1, SqlModelV1, SqlReasonV1};
pub use metadata::{
    PackageArtifactIdentityV1, PackageImageArtifactV1, PackageImageImplementationV1, PackageImageV1,
};
pub use native::{Dependency, LibraryRequirement, Qualification};

#[cfg(test)]
mod tests;
