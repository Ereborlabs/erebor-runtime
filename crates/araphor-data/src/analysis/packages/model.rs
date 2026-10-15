use serde::{Deserialize, Serialize};

use crate::{AnalysisContextRefV1, AnalysisWitnessV1};

pub(crate) const MAX_PACKAGE_METADATA_BYTES: usize = 1024 * 1024;

pub(crate) const MAX_PACKAGE_ROWS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageKeyV1 {
    pub tenant_id: [u8; 16],
    pub scope_id: String,
    pub package_id: String,
    pub export: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageRevisionRefV1 {
    pub package_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageRevisionV1 {
    pub tenant_id: [u8; 16],
    pub package_id: String,
    pub revision: String,
    pub descriptor: Vec<u8>,
    pub artifact: Vec<u8>,
    pub encoded_bytes: usize,
    pub dependencies: Vec<PackageRevisionRefV1>,
}

impl PackageRevisionV1 {
    pub(crate) fn decode_artifact(&self) -> crate::Result<crate::PackageArtifactV1> {
        use snafu::ResultExt as _;
        let descriptor =
            serde_json::from_slice(&self.descriptor).context(crate::PackageEncodingSnafu)?;
        crate::package::storage::StoredArtifact::decode(
            &self.artifact,
            &descriptor,
            self.encoded_bytes,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageActivationV1 {
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
pub(crate) struct PackageResultRefV1 {
    pub result_id: String,
    pub commit_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageResultV1 {
    pub key: PackageKeyV1,
    pub activation: PackageActivationV1,
    pub window_id: String,
    pub revision: String,
    pub result_id: String,
    pub request: Vec<u8>,
    pub metadata: Vec<u8>,
    pub datasets: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub commit_revision: u64,
    pub stale: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PackageCommitV1 {
    pub activation: PackageActivationV1,
    pub expected_checkpoint_revision: u64,
    pub window_id: String,
    pub result_id: String,
    pub request: Vec<u8>,
    pub metadata: Vec<u8>,
    pub datasets: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
    pub created_utc_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PackageCommitMetadata {
    pub activation: PackageActivationV1,
    pub checkpoint_revision: u64,
    pub window_id: String,
    pub result_id: String,
    pub dependencies: Vec<PackageResultRefV1>,
    pub source_revisions: Vec<(String, u64)>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub context_refs: Vec<AnalysisContextRefV1>,
    pub created_utc_ns: u64,
}

impl From<&PackageCommitV1> for PackageCommitMetadata {
    fn from(input: &PackageCommitV1) -> Self {
        Self {
            activation: input.activation.clone(),
            checkpoint_revision: input.expected_checkpoint_revision,
            window_id: input.window_id.clone(),
            result_id: input.result_id.clone(),
            dependencies: input.dependencies.clone(),
            source_revisions: input.source_revisions.clone(),
            witnesses: input.witnesses.clone(),
            context_refs: input.context_refs.clone(),
            created_utc_ns: input.created_utc_ns,
        }
    }
}

impl PackageKeyV1 {
    pub(super) fn valid(&self) -> bool {
        [&self.scope_id, &self.package_id, &self.export]
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 256)
    }
}
