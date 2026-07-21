use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PolicyError {
    #[snafu(display("policy source is empty"))]
    EmptyPolicy {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("policy syntax is invalid: {source}"))]
    InvalidPolicySyntax {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("policy rule `{rule_id}` is invalid: {reason}"))]
    InvalidRule {
        rule_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("policy rule `{rule_id}` is duplicated"))]
    DuplicateRule {
        rule_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("mandatory policy layer `{layer}` did not cover this effect"))]
    MissingMandatoryCoverage {
        layer: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "policy layers require incompatible mediations: `{first_layer}` and `{second_layer}`"
    ))]
    IncompatibleMediation {
        first_layer: String,
        second_layer: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, PolicyError>;

impl ErrorExt for PolicyError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::EmptyPolicy { .. }
            | Self::InvalidRule { .. }
            | Self::MissingMandatoryCoverage { .. }
            | Self::IncompatibleMediation { .. } => StatusCode::InvalidArguments,
            Self::InvalidPolicySyntax { .. } => StatusCode::InvalidSyntax,
            Self::DuplicateRule { .. } => StatusCode::AlreadyExists,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
