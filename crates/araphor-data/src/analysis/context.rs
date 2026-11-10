use std::path::Path;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;


use crate :: Result ;

mod batch;
pub(in crate::analysis) use batch::PreparedFact;
mod facts;
mod pages;
mod provenance;
mod reads;
#[cfg(test)]
mod tests;
mod write;

pub(in crate::analysis) use facts::FactRecord;
pub(super) use provenance::VerifiedPackages;

type ContextRow = (Option<u64>, Option<u64>, String, Vec<u8>, u64);

pub use araphor_analysis_builtins::graph::AnalysisContextKeyV1;

pub use araphor_analysis_builtins::graph::ContextSensitivityV1;

pub(in crate::analysis) fn version_key(key: &AnalysisContextKeyV1) -> Result<Vec<u8>> {
    rmp_serde::to_vec(&(
        key.tenant_id,
        &key.owner_id,
        &key.entity_key,
        &key.lifetime_key,
        key.owner_revision,
    ))
    .context(crate::AnalysisKeyEncodeSnafu)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisContextVersionV1 {
    pub key: AnalysisContextKeyV1,
    pub valid_from_utc_ns: Option<u64>,
    pub valid_until_utc_ns: Option<u64>,
    pub sensitivity: ContextSensitivityV1,
    pub body: Vec<u8>,
}

impl AnalysisContextVersionV1 {
    pub fn valid(&self) -> bool {
        self.key.valid()
            && match (self.valid_from_utc_ns, self.valid_until_utc_ns) {
                (None, None) => true,
                (Some(from), until) => from > 0 && until.is_none_or(|end| end > from),
                (None, Some(_)) => false,
            }
            && !self.body.is_empty()
    }
}

impl AnalysisContextVersionV1 {
pub(in crate::analysis) fn decode_row(
        root: &Path,
        key: AnalysisContextKeyV1,
        (from, until, sensitivity, body, revision): ContextRow,
    ) -> Result<(AnalysisContextVersionV1, u64)> {
        let sensitivity = match ContextSensitivityV1::try_from(sensitivity.as_str()) {
            Ok(value) => value,
            Err(()) => {
                return crate::Error::reject_path(root, "the context sensitivity is invalid")
            }
        };
        let result = AnalysisContextVersionV1 {
            key,
            valid_from_utc_ns: from,
            valid_until_utc_ns: until,
            sensitivity,
            body,
        };
        if !result.valid() || revision == 0 {
            return crate::Error::reject_path(root, "the retained context version is invalid");
        }
        Ok((result, revision))
    }
}
