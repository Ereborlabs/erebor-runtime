use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::Result;

pub(super) use sdk::wire::BoundedBuffer as PackageBuffer;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDatasetV1 {
    pub name: String,
    pub ipc: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInputV1 {
    pub data: PackageDatasetV1,
    pub revision: sdk::Revision,
    pub coverage: sdk::Coverage,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOutputV1 {
    pub datasets: Vec<PackageDatasetV1>,
    pub evidence: Vec<sdk::EvidenceLink>,
    pub reasons: Vec<PackageReasonV1>,
    pub checkpoint: Option<PackageCheckpointV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageReasonV1 {
    pub output: sdk::RowRef,
    pub code: String,
    pub details: PackageDatasetV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCheckpointV1 {
    pub version: u32,
    pub datasets: Vec<PackageDatasetV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFixtureV1 {
    pub name: String,
    pub export: String,
    #[serde(default)]
    pub time_utc_ns: i64,
    #[serde(default)]
    pub seed: Option<u64>,
    pub inputs: Vec<PackageInputV1>,
    pub parameters: Option<serde_json::Value>,
    pub checkpoint: Option<PackageCheckpointV1>,
    pub expected: PackageOutputV1,
}

impl PackageFixtureV1 {
    pub(super) fn evaluation_context(&self, model: &sdk::Model) -> sdk::EvaluationContext {
        sdk::EvaluationContext {
            id: format!("fixture:{}", self.name),
            time_utc_ns: self.time_utc_ns,
            seed: self.seed,
            limits: model.limits,
        }
    }
}

impl PackageDatasetV1 {
    pub fn encode(data: &sdk::Dataset, schema: &sdk::Schema, limits: sdk::Limits) -> Result<Self> {
        let encoded = sdk::wire::Dataset::encode(data, schema, limits)
            .context(crate::AnalysisContractSnafu)?;
        Ok(Self {
            name: encoded.name,
            ipc: encoded.arrow_ipc,
        })
    }

    pub fn decode(&self, schema: &sdk::Schema, limits: sdk::Limits) -> Result<sdk::Dataset> {
        sdk::wire::Dataset::decode_ipc(&self.name, &self.ipc, Some(schema), limits)
            .context(crate::AnalysisContractSnafu)
    }

    pub(super) fn decode_any(&self, limits: sdk::Limits) -> Result<sdk::Dataset> {
        sdk::wire::Dataset::decode_ipc(&self.name, &self.ipc, None, limits)
            .context(crate::AnalysisContractSnafu)
    }
}
