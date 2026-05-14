//! Policy evaluation contracts for erebor-runtime.

use erebor_runtime_events::RuntimeEvent;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny {
        reason: String,
    },
    RequireApproval {
        reason: String,
        approval_id: Option<String>,
    },
}

pub trait PolicyEvaluator {
    fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, PolicyError>;
}

#[derive(Clone, Debug, Default)]
pub struct AllowAllPolicy;

impl PolicyEvaluator for AllowAllPolicy {
    fn evaluate(&self, _event: &RuntimeEvent) -> Result<Decision, PolicyError> {
        Ok(Decision::Allow)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("policy source is empty")]
    EmptyPolicy,
    #[error("policy rule `{rule_id}` is invalid: {reason}")]
    InvalidRule { rule_id: String, reason: String },
}
