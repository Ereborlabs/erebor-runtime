
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};


use super::InputInterest;

use crate::{AnalysisSelectionV1, AnalysisTableRequests};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]

pub(in crate::analysis) struct InputSpec {
    pub selection: AnalysisSelectionV1,
    pub requests: AnalysisTableRequests,
    pub owners: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(in crate::analysis) struct InputCut {
    pub revision: u64,
    pub native: (u64, u64, u64),
    pub raw: Option<(u64, u64, u64)>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(in crate::analysis) struct InputCapture {
    pub owner: u64,
    pub generation: u64,
    pub version: u64,
    pub cut: InputCut,
    pub exhaustive: bool,
}


impl InputInterest {
    pub(in crate::analysis) fn spec(&self) -> InputSpec {
        InputSpec {
            selection: self.original.clone(),
            requests: self.requests.clone(),
            owners: self.owners.clone(),
        }
    }
}
