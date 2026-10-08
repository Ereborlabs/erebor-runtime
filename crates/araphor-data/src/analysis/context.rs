use serde::{Deserialize, Serialize};

use super::AnalysisStore;
use crate::{AnalysisConflictSnafu, AnalysisDatabaseSnafu, Result};

mod pages;
mod reads;
#[cfg(test)]
mod tests;
mod write;

const MAX_CONTEXT_BYTES: usize = 32 * 1024;
const MAX_CONTEXT_KEY_BYTES: usize = 256;
type ContextRow = (Option<u64>, Option<u64>, String, Vec<u8>, u64);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AnalysisContextKeyV1 {
    pub tenant_id: [u8; 16],
    pub owner_id: String,
    pub entity_key: Vec<u8>,
    pub lifetime_key: Vec<u8>,
    pub owner_revision: u64,
}

impl AnalysisContextKeyV1 {
    pub(crate) fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && !self.owner_id.is_empty()
            && self.owner_id.len() <= 128
            && !self.entity_key.is_empty()
            && self.entity_key.len() <= MAX_CONTEXT_KEY_BYTES
            && !self.lifetime_key.is_empty()
            && self.lifetime_key.len() <= MAX_CONTEXT_KEY_BYTES
    }
}

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
            && self.body.len() <= MAX_CONTEXT_BYTES
    }
}
