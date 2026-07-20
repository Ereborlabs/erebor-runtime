use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionSpecError {
    #[snafu(display("session specification is invalid at `{field}`: {reason}"))]
    Invalid {
        field: &'static str,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session transition from `{from}` to `{to}` is not allowed"))]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionSpecError {
    fn status_code(&self) -> StatusCode {
        StatusCode::InvalidArguments
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
