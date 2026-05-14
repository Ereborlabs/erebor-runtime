use snafu::Location;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy source is empty")]
    EmptyPolicy { location: Location },
    #[error("policy syntax is invalid: {source}")]
    InvalidPolicySyntax {
        source: serde_json::Error,
        location: Location,
    },
    #[error("policy rule `{rule_id}` is invalid: {reason}")]
    InvalidRule {
        rule_id: String,
        reason: String,
        location: Location,
    },
    #[error("policy rule `{rule_id}` is duplicated")]
    DuplicateRule { rule_id: String, location: Location },
}

impl PolicyError {
    #[track_caller]
    pub fn empty_policy() -> Self {
        Self::EmptyPolicy {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_policy_syntax(source: serde_json::Error) -> Self {
        Self::InvalidPolicySyntax {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_rule(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidRule {
            rule_id: rule_id.into(),
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn duplicate_rule(rule_id: impl Into<String>) -> Self {
        Self::DuplicateRule {
            rule_id: rule_id.into(),
            location: Location::default(),
        }
    }
}
