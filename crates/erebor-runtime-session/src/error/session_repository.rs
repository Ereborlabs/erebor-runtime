use std::{any::Any, io, path::PathBuf};

use erebor_runtime_core::SessionSpecError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionRepositoryError {
    #[snafu(display("session repository I/O failed while {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session repository record `{}` is invalid: {source}", path.display()))]
    Decode {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` already exists"))]
    AlreadyExists {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` was not found"))]
    NotFound {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session `{session_id}` generation {actual} does not match expected {expected}"
    ))]
    GenerationConflict {
        session_id: String,
        expected: u64,
        actual: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` is retained and cannot be removed"))]
    RetentionHeld {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session repository path `{}` is unsafe: {reason}", path.display()))]
    UnsafePath {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Spec {
        source: SessionSpecError,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionRepositoryError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } => StatusCode::External,
            Self::Decode { .. } | Self::UnsafePath { .. } | Self::Spec { .. } => {
                StatusCode::InvalidArguments
            }
            Self::AlreadyExists { .. } => StatusCode::AlreadyExists,
            Self::NotFound { .. } => StatusCode::NotFound,
            Self::GenerationConflict { .. } => StatusCode::IllegalState,
            Self::RetentionHeld { .. } => StatusCode::PolicyDenied,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::GenerationConflict { .. } => RetryHint::Retryable,
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
