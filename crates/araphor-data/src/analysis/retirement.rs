use serde::{Deserialize, Serialize};

use super::ProcessorScopeV1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorRetirementV1 {
    pub scope: ProcessorScopeV1,
    pub change_id: String,
    pub reason: String,
    pub expected_cursor: u64,
    pub cutoff_cursor: u64,
}

impl ProcessorRetirementV1 {
    pub fn valid(&self) -> bool {
        self.scope.valid()
            && !self.change_id.is_empty()
            && self.change_id.len() <= 128
            && self
                .change_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            && !self.reason.trim().is_empty()
            && self.reason.len() <= 512
            && !self.reason.chars().any(char::is_control)
            && self.expected_cursor <= self.cutoff_cursor
    }
}
