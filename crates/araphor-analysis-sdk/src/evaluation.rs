use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, Limits, RecordBatch, Result};

#[derive(Clone, Debug)]
pub struct Dataset {
    pub name: String,
    pub batches: Vec<RecordBatch>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWindow {
    pub source: Vec<u8>,
    pub start_utc_ns: i64,
    pub end_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub owner: String,
    pub id: String,
    pub window: Option<SourceWindow>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum CoverageState {
    Complete = 0,
    Gapped = 1,
    Unknown = 2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub state: CoverageState,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Input {
    pub data: Dataset,
    pub revision: Revision,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationContext {
    pub id: String,
    pub time_utc_ns: i64,
    pub seed: Option<u64>,
    pub limits: Limits,
}

#[derive(Clone, Debug)]
pub struct Evaluation {
    pub export: String,
    pub inputs: Vec<Input>,
    pub parameters: Option<RecordBatch>,
    pub context: EvaluationContext,
    pub checkpoint: Option<Checkpoint>,
}

impl Evaluation {
    pub fn input(&self, name: &str) -> Result<&Input> {
        self.inputs
            .iter()
            .find(|input| input.data.name == name)
            .ok_or_else(|| Error::contract(ErrorCode::Incomplete, format!("input {name}")))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RowRef {
    pub dataset: String,
    pub row: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLink {
    pub output: RowRef,
    pub input: RowRef,
}

#[derive(Clone, Debug)]
pub struct ReasonValue {
    pub output: RowRef,
    pub code: String,
    pub details: RecordBatch,
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub version: u32,
    pub datasets: Vec<Dataset>,
}

#[derive(Clone, Debug, Default)]
pub struct Output {
    pub datasets: Vec<Dataset>,
    pub evidence: Vec<EvidenceLink>,
    pub reasons: Vec<ReasonValue>,
    pub checkpoint: Option<Checkpoint>,
}
