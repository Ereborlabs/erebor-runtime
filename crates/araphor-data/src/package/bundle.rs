use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{IoSnafu, PackageEncodingSnafu, Result, SqlModelV1};

use super::{PackageErrorCodeV1 as Code, PackageFixtureV1};

pub const MAX_PACKAGE_BYTES: usize = 3 * 1024 * 1024;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactV1 {
    pub descriptor: sdk::Package,
    pub implementations: Vec<PackageImplementationV1>,
    #[serde(default)]
    pub fixtures: Vec<PackageFixtureV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageImplementationV1 {
    Sql {
        export: String,
        inputs: BTreeMap<String, String>,
        program: SqlModelV1,
    },
    Wasm {
        export: String,
        artifact: Vec<u8>,
    },
    Native {
        export: String,
        artifact: Vec<u8>,
    },
    Python {
        export: String,
        artifact: Vec<u8>,
    },
}

impl PackageImplementationV1 {
    pub fn export(&self) -> &str {
        match self {
            Self::Sql { export, .. }
            | Self::Wasm { export, .. }
            | Self::Native { export, .. }
            | Self::Python { export, .. } => export,
        }
    }

    pub fn target(&self) -> &'static str {
        match self {
            Self::Sql { .. } => "sql",
            Self::Wasm { .. } => "wasm",
            Self::Native { .. } => "native",
            Self::Python { .. } => "python",
        }
    }
}

impl PackageArtifactV1 {
    pub fn reference(&self) -> PackageRefV1 {
        PackageRefV1 {
            package_id: self.descriptor.id.clone(),
            revision: self.descriptor.revision.clone(),
        }
    }

    pub(crate) fn sql(&self, export: &str) -> Option<(&BTreeMap<String, String>, &SqlModelV1)> {
        self.implementations
            .iter()
            .find_map(|implementation| match implementation {
                PackageImplementationV1::Sql {
                    export: name,
                    inputs,
                    program,
                } if name == export => Some((inputs, program)),
                _ => None,
            })
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
        let mut artifacts: Vec<_> = self.artifacts.iter().collect();
        artifacts.sort_by_key(|artifact| artifact.reference());
        #[derive(Serialize)]
        struct Ordered<'a> {
            schema_version: u32,
            root: &'a PackageRefV1,
            artifacts: Vec<&'a PackageArtifactV1>,
        }
        let mut bytes = super::wire::PackageBuffer::new(MAX_PACKAGE_BYTES as u64);
        serde_json::to_writer(
            &mut bytes,
            &Ordered {
                schema_version: self.schema_version,
                root: &self.root,
                artifacts,
            },
        )
        .context(PackageEncodingSnafu)?;
        Ok(bytes.finish())
    }

    pub fn digest(&self) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(b"ARAPHOR-ANALYSIS-PACKAGE-V1\0");
        digest.update(self.encode()?);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(crate) fn artifact(&self, reference: &PackageRefV1) -> Result<&PackageArtifactV1> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.reference() == *reference)
            .ok_or_else(|| Code::Missing.error("locked package revision"))
    }
}
