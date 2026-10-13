use std::path::Path;

use snafu::{IntoError as _, ResultExt as _};

mod error;
mod workspace;
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

    pub fn package_native(
        package: &araphor_analysis_sdk::Package,
        native: &[u8],
        qualification: serde_json::Value,
        directory: &Path,
    ) -> Result<()> {
        let mut bundle = serde_json::json!({
            "schema_version": 1,
            "root": {"package_id": package.id, "revision": package.revision},
            "artifacts": [{"descriptor": package, "implementations": [{
                "target": "native", "export": package.exports.first().map(|model| &model.name),
                "artifact": native, "qualification": qualification,
            }], "fixtures": []}],
        });
        let exports = package
            .exports
            .iter()
            .map(|model| &model.name)
            .collect::<Vec<_>>();
        if qualification.get("exports") != Some(&serde_json::json!(exports)) {
            return Err(
                error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Invalid,
                    "native exports",
                )),
            );
        }
        let mut dependencies: Vec<(String, Vec<u8>)> = Vec::new();
        let declared = qualification
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Invalid,
                    "native dependencies",
                ))
            })?;
        for dependency in declared {
            let name = dependency
                .get("name")
                .and_then(serde_json::Value::as_str)
                .filter(|name| {
                    !name.is_empty()
                        && *name != "."
                        && *name != ".."
                        && !name.contains(['/', '\\'])
                        && ![
                            "descriptor.json",
                            "analysis.wit",
                            "analysis.h",
                            "package.json",
                            "detector.wasm",
                        ]
                        .contains(name)
                        && *name != format!("detector{}", std::env::consts::DLL_SUFFIX)
                        && !dependencies.iter().any(|(prior, _)| prior == name)
                })
                .ok_or_else(|| {
                    error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                        araphor_analysis_sdk::ErrorCode::Invalid,
                        "native dependency name",
                    ))
                })?;
            let artifact: Vec<u8> =
                serde_json::from_value(dependency.get("artifact").cloned().unwrap_or_default())
                    .context(error::EncodingSnafu)?;
            dependencies.push((name.to_owned(), artifact));
        }
        bundle.sort_all_objects();
        let bytes = serde_json::to_vec(&bundle).context(error::EncodingSnafu)?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(
                error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Limit,
                    "package bytes",
                )),
            );
        }
        package.build(directory).context(error::ContractSnafu)?;
        let library = directory.join(format!("detector{}", std::env::consts::DLL_SUFFIX));
        std::fs::write(&library, native).context(error::IoSnafu { path: library })?;
        for (name, artifact) in dependencies {
            let path = directory.join(name);
            std::fs::write(&path, artifact).context(error::IoSnafu { path })?;
        }
        let path = directory.join("package.json");
        std::fs::write(&path, bytes).context(error::IoSnafu { path })
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
    #[test]
    fn native_package_declares_target() -> Result<()> {
        use araphor_analysis_sdk::{Model, Package};
        let package = Package::new(
            "example",
            "1",
            vec![Model::new(
                "evaluate",
                Vec::new(),
                vec![araphor_analysis_sdk::Port::new(
                    "data",
                    araphor_analysis_sdk::Schema::empty(),
                )],
            )],
        );
        let directory = std::env::temp_dir().join(format!(
            "araphor-native-builder-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)
                .context(error::IoSnafu {
                    path: std::env::temp_dir(),
                })?
                .as_nanos()
        ));
        let qualification = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"helper.so", "artifact":[7,8], "digest":"test"}]});
        ComponentBuilder::package_native(&package, &[2, 3], qualification, &directory)?;
        let path = directory.join("package.json");
        let bytes = std::fs::read(&path).context(error::IoSnafu { path: &path })?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&bytes).context(error::EncodingSnafu)?;
        let implementations = &manifest["artifacts"][0]["implementations"];
        assert_eq!(implementations.as_array().map(Vec::len), Some(1));
        assert_eq!(implementations[0]["target"], "native");
        assert_eq!(implementations[0]["artifact"], serde_json::json!([2, 3]));
        assert!(!directory.join("detector.wasm").exists());
        let helper = directory.join("helper.so");
        assert_eq!(
            std::fs::read(&helper).context(error::IoSnafu { path: &helper })?,
            [7, 8]
        );
        let invalid = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"../escape", "artifact":[1]}]});
        assert!(ComponentBuilder::package_native(&package, &[1], invalid, &directory).is_err());
        let mismatch = serde_json::json!({"exports":["other"], "dependencies":[]});
        assert!(ComponentBuilder::package_native(&package, &[1], mismatch, &directory).is_err());
        std::fs::remove_dir_all(&directory).context(error::IoSnafu { path: directory })?;
        Ok(())
    }
}
