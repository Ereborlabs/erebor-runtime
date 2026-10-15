use std::path::Path;

use araphor_analysis_sdk::oci;

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
        let artifact = Self::component(core)?;
        Self::package_component(package, &artifact, directory)
    }

    pub fn package_component(
        package: &araphor_analysis_sdk::Package,
        artifact: &[u8],
        directory: &Path,
    ) -> Result<()> {
        package.build(directory).context(error::ContractSnafu)?;
        Self::write_manifest(package, artifact, directory)
    }

    pub fn package_native(
        package: &araphor_analysis_sdk::Package,
        native: &[u8],
        qualification: serde_json::Value,
        dependencies: &[(&str, &[u8])],
        directory: &Path,
    ) -> Result<()> {
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
        let declared = qualification
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Invalid,
                    "native dependencies",
                ))
            })?;
        if declared.len() != dependencies.len() {
            return Err(
                error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Invalid,
                    "native dependency layers",
                )),
            );
        }
        for (index, (dependency, (raw_name, _))) in declared.iter().zip(dependencies).enumerate() {
            dependency
                .get("name")
                .and_then(serde_json::Value::as_str)
                .filter(|name| {
                    !name.is_empty()
                        && *name != "."
                        && *name != ".."
                        && !name.contains(['/', '\\'])
                        && name == raw_name
                        && !dependencies[..index].iter().any(|(prior, _)| prior == name)
                        && dependency
                            .get("artifact")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(Vec::is_empty)
                })
                .ok_or_else(|| {
                    error::ContractSnafu.into_error(araphor_analysis_sdk::Error::contract(
                        araphor_analysis_sdk::ErrorCode::Invalid,
                        "native dependency name",
                    ))
                })?;
        }
        let bundle = serde_json::json!({
            "schema_version": 1,
            "root": {"package_id": package.id, "revision": package.revision},
            "artifacts": [{"descriptor": package, "implementations": [{
                "target": "native", "export": package.exports.first().map(|model| &model.name),
                "artifact": [], "qualification": qualification,
            }], "fixtures": []}],
        });
        let mut layers = vec![oci::Layer {
            media_type: oci::NATIVE_MEDIA_TYPE,
            bytes: native,
        }];
        layers.extend(dependencies.iter().map(|(_, artifact)| oci::Layer {
            media_type: oci::NATIVE_DEPENDENCY_MEDIA_TYPE,
            bytes: artifact,
        }));
        let layout = oci::Layout::new(&bundle, &layers).context(error::ContractSnafu)?;
        package.build(directory).context(error::ContractSnafu)?;
        layout.write(directory).context(error::ContractSnafu)
    }

    fn write_manifest(
        package: &araphor_analysis_sdk::Package,
        artifact: &[u8],
        directory: &Path,
    ) -> Result<()> {
        let bundle = Self::manifest(package);
        let layers = [oci::Layer {
            media_type: oci::WASM_MEDIA_TYPE,
            bytes: artifact,
        }];
        oci::Layout::new(&bundle, &layers)
            .context(error::ContractSnafu)?
            .write(directory)
            .context(error::ContractSnafu)
    }

    pub fn build(core: &Path, output: &Path) -> Result<()> {
        let component = Self::component(core)?;
        std::fs::write(output, component).context(error::IoSnafu { path: output })
    }

    fn component(core: &Path) -> Result<Vec<u8>> {
        let bytes = std::fs::read(core).context(error::IoSnafu { path: core })?;
        let bytes = Self::strip(&bytes)?;
        wit_component::ComponentEncoder::default()
            .module(&bytes)
            .context(error::ComponentSnafu)?
            .validate(true)
            .encode()
            .context(error::ComponentSnafu)
    }

    fn manifest(package: &araphor_analysis_sdk::Package) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "root": {"package_id": package.id, "revision": package.revision},
            "artifacts": [{
                "descriptor": package,
                "implementations": [{
                    "target": "wasm",
                    "exports": package.exports.iter().map(|model| &model.name).collect::<Vec<_>>(),
                    "artifact": [],
                }],
                "fixtures": [],
            }],
        })
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
        let manifest = ComponentBuilder::manifest(&package);
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
            serde_json::json!([])
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
        let qualification = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"helper.so", "artifact":[], "digest":"test"}]});
        ComponentBuilder::package_native(
            &package,
            &[2, 3],
            qualification,
            &[("helper.so", &[7, 8])],
            &directory,
        )?;
        let content = oci::Content::read_files(|name| {
            std::fs::read(directory.join(name)).map_err(|_| {
                araphor_analysis_sdk::Error::contract(
                    araphor_analysis_sdk::ErrorCode::Failed,
                    "builder fixture file",
                )
            })
        })
        .context(error::ContractSnafu)?;
        let manifest: serde_json::Value = content.package().context(error::ContractSnafu)?;
        let implementations = &manifest["artifacts"][0]["implementations"];
        assert_eq!(implementations.as_array().map(Vec::len), Some(1));
        assert_eq!(implementations[0]["target"], "native");
        assert_eq!(implementations[0]["artifact"], serde_json::json!([]));
        assert_eq!(
            implementations[0]["qualification"]["dependencies"][0]["artifact"],
            serde_json::json!([])
        );
        assert_eq!(content.layers.len(), 2);
        assert_eq!(content.layers[0].media_type, oci::NATIVE_MEDIA_TYPE);
        assert_eq!(content.layers[0].bytes, [2, 3]);
        assert_eq!(
            content.layers[1].media_type,
            oci::NATIVE_DEPENDENCY_MEDIA_TYPE
        );
        assert_eq!(content.layers[1].bytes, [7, 8]);
        assert!(directory.join("oci-layout").is_file());
        assert!(!directory.join("package.json").exists());
        assert!(!directory.join("helper.so").exists());
        let invalid = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"../escape", "artifact":[]}]});
        assert!(ComponentBuilder::package_native(
            &package,
            &[1],
            invalid,
            &[("../escape", &[1])],
            &directory
        )
        .is_err());
        let embedded = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"helper.so", "artifact":[7,8], "digest":"test"}]});
        assert!(ComponentBuilder::package_native(
            &package,
            &[1],
            embedded,
            &[("helper.so", &[7, 8])],
            &directory
        )
        .is_err());
        let missing = serde_json::json!({"exports":["evaluate"], "dependencies":[{"name":"helper.so", "artifact":[], "digest":"test"}]});
        assert!(
            ComponentBuilder::package_native(&package, &[1], missing, &[], &directory).is_err()
        );
        let mismatch = serde_json::json!({"exports":["other"], "dependencies":[]});
        assert!(
            ComponentBuilder::package_native(&package, &[1], mismatch, &[], &directory).is_err()
        );
        std::fs::remove_dir_all(&directory).context(error::IoSnafu { path: directory })?;
        Ok(())
    }
}
