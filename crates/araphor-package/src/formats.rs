use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlModelV1 {
    pub outputs: BTreeMap<String, String>,
    pub checkpoint: BTreeMap<String, String>,
    pub evidence: Option<String>,
    pub reasons: Vec<SqlReasonV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlReasonV1 {
    pub output: String,
    pub code: String,
    pub sql: String,
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
    pub inputs: Vec<sdk::wire::Input>,
    pub parameters: Option<serde_json::Value>,
    pub checkpoint: Option<sdk::wire::Checkpoint>,
    pub expected: sdk::wire::Output,
}

impl PackageFixtureV1 {
    pub fn evaluation_context(&self) -> sdk::EvaluationContext {
        sdk::EvaluationContext {
            id: format!("fixture:{}", self.name),
            time_utc_ns: self.time_utc_ns,
            seed: self.seed,
        }
    }
}
