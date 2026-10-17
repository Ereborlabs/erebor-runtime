use serde::{Deserialize, Serialize};

use crate::{AnalysisContextRefV1, AnalysisWitnessV1};

pub const MAX_PACKAGE_METADATA_BYTES: usize = 1024 * 1024;

pub const MAX_PACKAGE_ROWS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageKeyV1 {
    pub tenant_id: [u8; 16],
    pub scope_id: String,
    pub package_id: String,
    pub export: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageRevisionRefV1 {
    pub package_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageRevisionV1 {
    pub tenant_id: [u8; 16],
    pub package_id: String,
    pub revision: String,
    pub descriptor: Vec<u8>,
    pub artifact: Vec<u8>,
    pub dependencies: Vec<PackageRevisionRefV1>,
}

impl PackageRevisionV1 {
    pub fn decode_artifact(&self) -> crate::Result<crate::PackageArtifactV1> {
        use snafu::ResultExt as _;
        let descriptor: araphor_analysis_sdk::Package =
            serde_json::from_slice(&self.descriptor).context(crate::PackageEncodingSnafu)?;
        let artifact = crate::PackageArtifactV1::from_bytes(&self.artifact)?;
        if artifact.descriptor != descriptor {
            return Err(crate::PackageErrorCodeV1::Invalid.error("retained package descriptor"));
        }
        Ok(artifact)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageActivationV1 {
    pub key: PackageKeyV1,
    pub revision: String,
    pub generation: u64,
    pub checkpoint_revision: u64,
    pub result_id: Option<String>,
    pub grant_id: String,
    pub metadata: Vec<u8>,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageResultRefV1 {
    pub result_id: String,
    pub commit_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageResultV1 {
    pub commit: PackageCommitV1,
    pub commit_revision: u64,
    pub stale: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackageCommitV1 {
    pub activation: PackageActivationV1,
    #[serde(rename = "checkpoint_revision")]
    pub expected_checkpoint_revision: u64,
    pub window_id: String,
    pub result_id: String,
    #[serde(skip)]
    pub request: Vec<u8>,
    #[serde(skip)]
    pub metadata: Vec<u8>,
    #[serde(skip)]
    pub datasets: Vec<u8>,
    #[serde(skip)]
    pub checkpoint: Vec<u8>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
    pub created_utc_ns: u64,
}

impl PackageKeyV1 {
    pub(super) fn valid(&self) -> bool {
        [&self.scope_id, &self.package_id, &self.export]
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 256)
    }
}
