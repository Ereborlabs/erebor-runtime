use serde::{Deserialize, Serialize};

use super::AnalysisStore;
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, Result};

mod pages;
mod provenance;
mod reads;
#[cfg(test)]
mod tests;
mod write;

type ContextRow = (Option<u64>, Option<u64>, String, Vec<u8>, u64);

pub use araphor_analysis_builtins::graph::AnalysisContextKeyV1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContextSensitivityV1 {
    Public,
    Tenant,
    HostRestricted,
}

impl From<ContextSensitivityV1> for &'static str {
    fn from(value: ContextSensitivityV1) -> Self {
        match value {
            ContextSensitivityV1::Public => "public",
            ContextSensitivityV1::Tenant => "tenant",
            ContextSensitivityV1::HostRestricted => "host_restricted",
        }
    }
}

impl TryFrom<&str> for ContextSensitivityV1 {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "public" => Ok(Self::Public),
            "tenant" => Ok(Self::Tenant),
            "host_restricted" => Ok(Self::HostRestricted),
            _ => Err(()),
        }
    }
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
    fn valid(&self) -> bool {
        self.key.valid()
            && match (self.valid_from_utc_ns, self.valid_until_utc_ns) {
                (None, None) => true,
                (Some(from), until) => from > 0 && until.is_none_or(|end| end > from),
                (None, Some(_)) => false,
            }
            && !self.body.is_empty()
    }
}
