use std::path::Path;

use snafu::{IntoError as _, ResultExt as _};

mod error;
pub use error::{Error, Result};

pub struct ComponentBuilder;

impl ComponentBuilder {
    pub fn package(
        package: &araphor_analysis_sdk::Package,
        core: &Path,
        directory: &Path,
    ) -> Result<()> {
        package.build(directory).context(error::ContractSnafu)?;
        let component = directory.join("detector.wasm");
        Self::build(core, &component)?;
        let artifact = std::fs::read(&component).context(error::IoSnafu { path: &component })?;
        Self::write_manifest(package, artifact, directory)
    }

    pub fn package_component(
        package: &araphor_analysis_sdk::Package,
        artifact: &[u8],
        directory: &Path,
    ) -> Result<()> {
        package.build(directory).context(error::ContractSnafu)?;
        let component = directory.join("detector.wasm");
        std::fs::write(&component, artifact).context(error::IoSnafu { path: component })?;
        Self::write_manifest(package, artifact.to_vec(), directory)
    }

    fn write_manifest(
        package: &araphor_analysis_sdk::Package,
        artifact: Vec<u8>,
        directory: &Path,
    ) -> Result<()> {
        let bundle = Self::manifest(package, artifact);
        let bytes = serde_json::to_vec(&bundle).context(error::EncodingSnafu)?;
        let manifest = directory.join("package.json");
        std::fs::write(&manifest, bytes).context(error::IoSnafu { path: manifest })
    }

    pub fn build(core: &Path, output: &Path) -> Result<()> {
        let bytes = std::fs::read(core).context(error::IoSnafu { path: core })?;
        let bytes = Self::strip(&bytes)?;
        let component = wit_component::ComponentEncoder::default()
            .module(&bytes)
            .context(error::ComponentSnafu)?
            .validate(true)
            .encode()
            .context(error::ComponentSnafu)?;
        std::fs::write(output, component).context(error::IoSnafu { path: output })
    }

    fn manifest(package: &araphor_analysis_sdk::Package, artifact: Vec<u8>) -> serde_json::Value {
        let mut manifest = serde_json::json!({
            "schema_version": 1,
            "root": {"package_id": package.id, "revision": package.revision},
            "artifacts": [{
                "descriptor": package,
                "implementations": [{
                    "target": "wasm",
                    "exports": package.exports.iter().map(|model| &model.name).collect::<Vec<_>>(),
                    "inputs": null,
                    "artifact": artifact,
                }],
                "fixtures": [],
            }],
        });
        manifest.sort_all_objects();
        manifest
    }

    fn strip(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut stripped = bytes.get(..8).unwrap_or_default().to_vec();
        let mut start = 8;
        for payload in wasmparser::Parser::new(0).parse_all(bytes) {
            let payload = payload
                .map_err(anyhow::Error::from)
                .context(error::ComponentSnafu)?;
            if matches!(
                payload,
                wasmparser::Payload::Version {
                    encoding: wasmparser::Encoding::Component,
                    ..
                }
            ) {
                return Err(
                    error::ComponentSnafu.into_error(anyhow::anyhow!("expected core Wasm module"))
                );
            }
            if let Some((_, range)) = payload.as_section() {
                let end = range.end as usize;
                let remove = matches!(&payload, wasmparser::Payload::CustomSection(section)
                    if section.name() == "name" || section.name().starts_with(".debug_"));
                if !remove {
                    stripped.extend_from_slice(&bytes[start..end]);
                }
                start = end;
            }
        }
        Ok(stripped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_keeps_metadata() -> Result<()> {
        let core = b"\0asm\x01\0\0\0\0\x05\x04name\0\x08\x07payload";
        assert_eq!(
            ComponentBuilder::strip(core)?,
            b"\0asm\x01\0\0\0\0\x08\x07payload"
        );
        assert!(ComponentBuilder::strip(b"invalid").is_err());
        assert!(ComponentBuilder::strip(b"\0asm\x0d\0\x01\0").is_err());
        Ok(())
    }

    #[test]
    fn manifest_has_all_exports() {
        use araphor_analysis_sdk::{Model, Package};

        let package = Package::new(
            "example",
            "1",
            vec![
                Model::new("first", Vec::new(), Vec::new()),
                Model::new("second", Vec::new(), Vec::new()),
            ],
        );
        let manifest = ComponentBuilder::manifest(&package, vec![0, 1, 2]);
        assert_eq!(manifest["root"]["package_id"], "example");
        assert_eq!(
            manifest["artifacts"][0]["implementations"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            manifest["artifacts"][0]["implementations"][0]["exports"],
            serde_json::json!(["first", "second"])
        );
        assert_eq!(
            manifest["artifacts"][0]["implementations"][0]["artifact"],
            serde_json::json!([0, 1, 2])
        );
    }
}
