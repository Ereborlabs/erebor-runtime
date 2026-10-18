mod bundle;
mod formats;
mod model;
mod parameters;
mod provenance;

pub use araphor_package::{
    native, Dependency, LibraryRequirement, ModelRef, PackageArtifactIdentityV1, PackageArtifactV1,
    PackageBundleV1, PackageFixtureV1, PackageImageArtifactV1, PackageImageImplementationV1,
    PackageImageV1, PackageImplementationV1, PackageRefV1, Qualification, SqlModelV1, SqlReasonV1,
};
pub use araphor_package::{Error as PackageImageError, ErrorCode as PackageImageErrorCode};
pub use bundle::*;
pub use formats::*;
pub use model::*;
pub use parameters::decode_parameters;
pub(crate) use provenance::NativePackageContext;

pub fn parameter_values<'a>(
    parameters: Option<&'a serde_json::Value>,
    package: &str,
    export: &str,
) -> Option<&'a serde_json::Value> {
    parameters
        .and_then(|value| value.get(package))
        .and_then(|value| value.get(export))
}

pub fn validate_package_name(value: &str) -> crate::Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(PackageErrorCodeV1::Invalid.error("package operation name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
