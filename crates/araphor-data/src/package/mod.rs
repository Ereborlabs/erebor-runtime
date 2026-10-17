mod admission;
mod bundle;
mod formats;
mod model;
pub mod native;
mod oci;
mod parameters;
mod provenance;

pub use admission::ModelRef;
pub use bundle::*;
pub use formats::*;
pub use model::*;
pub use native::{Dependency, LibraryRequirement, Qualification};
pub use parameters::decode_parameters;

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
