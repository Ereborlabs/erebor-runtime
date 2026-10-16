use std::path::Path;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{Result, SqlModelV1};

use super::{PackageErrorCodeV1 as Code, PackageFixtureV1};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRefV1 {
    pub package_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageBundleV1 {
    pub schema_version: u32,
    pub root: PackageRefV1,
    pub artifacts: Vec<PackageArtifactV1>,
}

pub struct PackageBundleRef<'a> {
    value: &'a PackageBundleV1,
    digest: std::borrow::Cow<'a, str>,
}

impl<'a> PackageBundleRef<'a> {
    pub fn new(value: &'a PackageBundleV1) -> Result<Self> {
        Ok(Self {
            value,
            digest: value.digest()?.into(),
        })
    }

    pub fn bundle(&self) -> &PackageBundleV1 {
        self.value
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn retained(value: &'a PackageBundleV1, digest: &'a str) -> Self {
        Self {
            value,
            digest: digest.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactV1 {
    pub descriptor: sdk::Package,
    pub implementations: Vec<PackageImplementationV1>,
    #[serde(default)]
    pub fixtures: Vec<PackageFixtureV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageImplementationV1 {
    Sql {
        export: String,
        program: SqlModelV1,
    },
    Wasm {
        exports: Vec<String>,
        artifact: Vec<u8>,
    },
    Native {
        export: String,
        artifact: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        qualification: Option<super::native::Qualification>,
    },
    Python {
        export: String,
        artifact: Vec<u8>,
    },
}

impl PackageImplementationV1 {
    pub fn exports(&self) -> &[String] {
        match self {
            Self::Wasm { exports, .. } => exports,
            Self::Native {
                qualification: Some(qualification),
                ..
            } => &qualification.exports,
            Self::Sql { export, .. }
            | Self::Native { export, .. }
            | Self::Python { export, .. } => std::slice::from_ref(export),
        }
    }

    pub fn implements(&self, export: &str) -> bool {
        self.exports().iter().any(|name| name == export)
    }

    pub fn target(&self) -> &'static str {
        match self {
            Self::Sql { .. } => "sql",
            Self::Wasm { .. } => "wasm",
            Self::Native { .. } => "native",
            Self::Python { .. } => "python",
        }
    }

    pub fn identity(&self) -> Result<Option<super::PackageArtifactIdentityV1>> {
        let identity = match self {
            Self::Wasm { artifact, .. } => super::PackageArtifactIdentityV1 {
                digest: super::native::Qualification::digest(artifact),
                closure_digest: None,
                platform: None,
            },
            Self::Native {
                artifact,
                qualification: Some(qualification),
                ..
            } => super::PackageArtifactIdentityV1 {
                digest: super::native::Qualification::digest(artifact),
                closure_digest: Some(qualification.closure_digest(artifact)?),
                platform: Some(qualification.target.clone()),
            },
            _ => return Ok(None),
        };
        Ok(Some(identity))
    }
}

impl PackageArtifactV1 {
    pub fn descriptor_bytes(&self) -> Result<Vec<u8>> {
        self.descriptor
            .inspect()
            .map(String::into_bytes)
            .context(crate::AnalysisContractSnafu)
    }

    pub fn implementation(&self, export: &str) -> Result<&PackageImplementationV1> {
        let mut implementations = self
            .implementations
            .iter()
            .filter(|entry| entry.implements(export))
            .filter(|entry| {
                matches!(
                    entry,
                    PackageImplementationV1::Sql { .. }
                        | PackageImplementationV1::Wasm { .. }
                        | PackageImplementationV1::Native {
                            qualification: Some(_),
                            ..
                        }
                )
            });
        let implementation = implementations
            .next()
            .ok_or_else(|| Code::Unsupported.error("model target"))?;
        if implementations.next().is_some() {
            return Err(Code::Invalid.error("plugin execution type"));
        }
        Ok(implementation)
    }

    pub fn prepared(&self, export: &str) -> bool {
        self.descriptor
            .exports
            .iter()
            .any(|model| model.name == export && model.input_mode == sdk::InputMode::Provided)
            && matches!(
                self.implementation(export),
                Ok(PackageImplementationV1::Wasm { .. }
                    | PackageImplementationV1::Native {
                        qualification: Some(_),
                        ..
                    })
            )
    }

    pub fn reference(&self) -> PackageRefV1 {
        PackageRefV1 {
            package_id: self.descriptor.id.clone(),
            revision: self.descriptor.revision.clone(),
        }
    }
}

impl PackageBundleV1 {
    pub fn read(path: &Path) -> Result<Self> {
        super::oci::PackageOci::read(path)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        super::oci::PackageOci::decode(
            sdk::oci::Content::from_bytes(bytes).context(crate::AnalysisContractSnafu)?,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.oci()?.encode().context(crate::AnalysisContractSnafu)
    }

    pub fn write_layout(&self, path: &Path) -> Result<()> {
        self.oci()?
            .write(path)
            .context(crate::AnalysisContractSnafu)
    }

    pub fn check_encoding(&self) -> Result<()> {
        self.oci().map(|_| ())
    }

    pub fn digest(&self) -> Result<String> {
        Ok(self.oci()?.digest())
    }

    fn oci(&self) -> Result<sdk::oci::Layout<'_>> {
        super::oci::PackageOci::layout(self)
    }

    pub fn artifact(&self, reference: &PackageRefV1) -> Result<&PackageArtifactV1> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.reference() == *reference)
            .ok_or_else(|| Code::Missing.error("locked package revision"))
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use crate::package::tests::{bundle, TestResult};

    #[test]
    fn bundle_writer_digest_matches_bytes() -> TestResult {
        let mut sql = bundle("1", "SELECT count FROM source");
        let mut port = sql.artifacts[0].descriptor.exports[0].outputs[0].clone();
        port.name = "source".into();
        sql.artifacts[0].descriptor.exports[0]
            .inputs
            .push(sdk::InputPort {
                port,
                source: sdk::InputSource::Query("SELECT 1::BIGINT UNSIGNED AS count".into()),
            });
        let original = sql.digest()?;
        sql.artifacts[0].descriptor.exports[0].inputs[0].source =
            sdk::InputSource::Query("SELECT 2::BIGINT UNSIGNED AS count".into());
        assert_ne!(sql.digest()?, original);
        let mut component = sql.clone();
        component.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            artifact: (0_u8..=255).cycle().take(16 * 1024 + 1).collect(),
        }];
        for package in [sql, component] {
            let bytes = package.encode()?;
            let content = sdk::oci::Content::from_bytes(&bytes)?;
            use sha2::{Digest as _, Sha256};
            assert_eq!(
                package.digest()?,
                format!("sha256:{:x}", Sha256::digest(&content.manifest))
            );
            package.check_encoding()?;
            assert_eq!(
                PackageBundleV1::from_bytes(&bytes)?.digest()?,
                package.digest()?
            );
        }
        Ok(())
    }

    #[test]
    fn bundle_writer_descriptor_errors() -> TestResult {
        let mut package = bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
        package.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            artifact: Vec::new(),
        }];
        package.artifacts[0].descriptor.id.clear();
        assert!(matches!(
            package.encode(),
            Err(crate::Error::AnalysisContract { .. })
        ));
        assert!(matches!(
            package.digest(),
            Err(crate::Error::AnalysisContract { .. })
        ));
        assert!(matches!(
            package.check_encoding(),
            Err(crate::Error::AnalysisContract { .. })
        ));
        Ok(())
    }
}
