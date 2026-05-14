use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("policy source is empty")]
    EmptyPolicy,
    #[error("policy syntax is invalid: {reason}")]
    InvalidPolicySyntax { reason: String },
    #[error("policy rule `{rule_id}` is invalid: {reason}")]
    InvalidRule { rule_id: String, reason: String },
    #[error("policy rule `{rule_id}` is duplicated")]
    DuplicateRule { rule_id: String },
}
