use crate::{Coverage, Error, ErrorCode, EvaluationContext, EvidenceLink, Revision, RowRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    pub name: String,
    pub arrow_ipc: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub data: Dataset,
    pub revision: Revision,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub datasets: Vec<Dataset>,
}

#[derive(Clone, Debug)]
pub struct Evaluation {
    pub export_name: String,
    pub inputs: Vec<Input>,
    pub parameters: Option<Vec<u8>>,
    pub context: EvaluationContext,
    pub checkpoint: Option<Checkpoint>,
    pub previous_outputs: Vec<Dataset>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonValue {
    pub output: RowRef,
    pub code: String,
    pub details: Vec<u8>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub datasets: Vec<Dataset>,
    pub evidence: Vec<EvidenceLink>,
    pub reasons: Vec<ReasonValue>,
    pub checkpoint: Option<Checkpoint>,
}

#[derive(Clone, Debug)]
pub struct EvaluationError {
    pub code: ErrorCode,
    pub field: String,
}

impl From<Error> for EvaluationError {
    fn from(error: Error) -> Self {
        let code = error.code();
        let field = match error {
            Error::Contract { field, .. } => field,
            Error::Batch { .. } => "arrow batch".into(),
            Error::Encoding { .. } => "encoding".into(),
            Error::Io { .. } => "io".into(),
        };
        Self { code, field }
    }
}

impl From<EvaluationError> for Error {
    fn from(error: EvaluationError) -> Self {
        Self::contract(error.code, error.field)
    }
}
