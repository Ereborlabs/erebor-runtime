use std::collections::BTreeMap;
use std::io::{self, Read as _, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{IoSnafu, PackageEncodingSnafu, Result, SqlModelV1};

use super::{PackageErrorCodeV1 as Code, PackageFixtureV1};

pub const MAX_PACKAGE_BYTES: usize = 32 * 1024 * 1024;

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactV1 {
    pub descriptor: sdk::Package,
    pub implementations: Vec<PackageImplementationV1>,
    #[serde(default)]
    pub fixtures: Vec<PackageFixtureV1>,
}

#[derive(Serialize)]
pub(super) struct ArtifactEncoding<'a> {
    pub(super) descriptor: Box<serde_json::value::RawValue>,
    implementations: &'a [PackageImplementationV1],
    fixtures: &'a [PackageFixtureV1],
}

impl ArtifactEncoding<'_> {
    pub(super) fn check_encoding(&self) -> Result<()> {
        let mut writer = super::wire::PackageBuffer::from_writer(
            io::sink(),
            crate::analysis::MAX_PACKAGE_BYTES as u64,
        );
        serde_json::to_writer(&mut writer, self).context(PackageEncodingSnafu)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageImplementationV1 {
    Sql {
        export: String,
        inputs: BTreeMap<String, String>,
        program: SqlModelV1,
    },
    Wasm {
        exports: Vec<String>,
        #[serde(default)]
        inputs: Option<BTreeMap<String, String>>,
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
    pub(crate) fn bindings(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            Self::Sql { inputs, .. } => Some(inputs),
            Self::Wasm { inputs, .. } => inputs.as_ref(),
            Self::Native { qualification, .. } => qualification.as_ref()?.inputs.as_ref(),
            Self::Python { .. } => None,
        }
    }

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

    pub(crate) fn identity(&self) -> Result<Option<super::PackageArtifactIdentityV1>> {
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
    fn has_component(&self) -> bool {
        self.implementations.iter().any(|implementation| {
            matches!(
                implementation,
                PackageImplementationV1::Wasm { .. }
                    | PackageImplementationV1::Native {
                        qualification: Some(_),
                        ..
                    }
            )
        })
    }

    pub(super) fn encoding(&self, canonical: bool) -> Result<ArtifactEncoding<'_>> {
        let descriptor = if canonical || self.has_component() {
            self.descriptor
                .inspect()
                .context(crate::AnalysisContractSnafu)?
        } else {
            serde_json::to_string(&self.descriptor).context(PackageEncodingSnafu)?
        };
        Ok(ArtifactEncoding {
            descriptor: serde_json::value::RawValue::from_string(descriptor)
                .context(PackageEncodingSnafu)?,
            implementations: &self.implementations,
            fixtures: &self.fixtures,
        })
    }

    pub(crate) fn implementation(&self, export: &str) -> Result<&PackageImplementationV1> {
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

    pub(crate) fn prepared(&self, export: &str) -> bool {
        matches!(
            self.implementation(export),
            Ok(PackageImplementationV1::Wasm { inputs: None, .. })
        ) || matches!(
            self.implementation(export),
            Ok(PackageImplementationV1::Native { qualification: Some(qualification), .. })
                if qualification.inputs.is_none()
        )
    }

    pub fn reference(&self) -> PackageRefV1 {
        PackageRefV1 {
            package_id: self.descriptor.id.clone(),
            revision: self.descriptor.revision.clone(),
        }
    }

    pub(crate) fn uses_clock(&self, model: &sdk::Model) -> Result<bool> {
        match self.implementation(&model.name)? {
            PackageImplementationV1::Sql { program, .. } => program.uses_clock(model),
            PackageImplementationV1::Wasm { .. } | PackageImplementationV1::Native { .. } => {
                Ok(true)
            }
            _ => Err(Code::Unsupported.error("model target")),
        }
    }
}

impl PackageBundleV1 {
    pub fn read(path: &Path) -> Result<Self> {
        let path = if path.is_dir() {
            path.join("package.json")
        } else {
            path.to_path_buf()
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)
            .context(IoSnafu { path: &path })?;
        let metadata = file.metadata().context(IoSnafu { path: &path })?;
        if !metadata.is_file() || metadata.len() > MAX_PACKAGE_BYTES as u64 {
            return Err(Code::Limit.error("package file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_PACKAGE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .context(IoSnafu { path })?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(Code::Limit.error("package bytes"));
        }
        let mut bundle: Self = serde_json::from_slice(bytes).context(PackageEncodingSnafu)?;
        bundle.artifacts.sort_by_key(PackageArtifactV1::reference);
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = super::wire::PackageBuffer::new(MAX_PACKAGE_BYTES as u64);
        self.encode_into(&mut bytes)?;
        Ok(bytes.finish())
    }

    pub(super) fn check_encoding(&self) -> Result<()> {
        let mut writer =
            super::wire::PackageBuffer::from_writer(io::sink(), MAX_PACKAGE_BYTES as u64);
        self.encode_into(&mut writer)
    }

    fn encode_into(&self, writer: &mut impl Write) -> Result<()> {
        let canonical = self.artifacts.iter().any(PackageArtifactV1::has_component);
        let mut artifacts: Vec<_> = self.artifacts.iter().collect();
        artifacts.sort_by_key(|artifact| artifact.reference());
        let artifacts = artifacts
            .into_iter()
            .map(|artifact| artifact.encoding(canonical))
            .collect::<Result<Vec<_>>>()?;
        #[derive(Serialize)]
        struct Ordered<'a> {
            schema_version: u32,
            root: &'a PackageRefV1,
            artifacts: Vec<ArtifactEncoding<'a>>,
        }
        serde_json::to_writer(
            writer,
            &Ordered {
                schema_version: self.schema_version,
                root: &self.root,
                artifacts,
            },
        )
        .context(PackageEncodingSnafu)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(b"ARAPHOR-ANALYSIS-PACKAGE-V1\0");
        self.encode_into(&mut super::wire::PackageBuffer::from_writer(
            &mut digest,
            MAX_PACKAGE_BYTES as u64,
        ))?;
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(crate) fn artifact(&self, reference: &PackageRefV1) -> Result<&PackageArtifactV1> {
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
        let sql = bundle("1", "SELECT 1::UBIGINT AS count");
        let mut component = sql.clone();
        component.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            inputs: None,
            artifact: vec![0, 1, 255],
        }];
        for package in [sql, component] {
            let bytes = package.encode()?;
            let mut digest = Sha256::new();
            digest.update(b"ARAPHOR-ANALYSIS-PACKAGE-V1\0");
            digest.update(&bytes);
            assert_eq!(package.digest()?, format!("{:x}", digest.finalize()));
            package.check_encoding()?;
            let mut exact =
                super::super::wire::PackageBuffer::from_writer(io::sink(), bytes.len() as u64);
            package.encode_into(&mut exact)?;
            let mut short =
                super::super::wire::PackageBuffer::from_writer(io::sink(), bytes.len() as u64 - 1);
            let error = package
                .encode_into(&mut short)
                .err()
                .ok_or("over-limit encoding accepted")?;
            assert!(matches!(error, crate::Error::PackageEncoding { source, .. }
                if source.io_error_kind() == Some(io::ErrorKind::FileTooLarge)));
        }
        Ok(())
    }

    #[test]
    fn bundle_writer_descriptor_errors() -> TestResult {
        let mut package = bundle("1", "SELECT 1::UBIGINT AS count");
        package.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            inputs: None,
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
