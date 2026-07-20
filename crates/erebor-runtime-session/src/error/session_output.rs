use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionOutputError {
    #[snafu(display("session stream I/O failed while {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session stream record `{}` is invalid: {source}", path.display()))]
    Decode {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session stream integrity check failed for `{}`: {reason}", path.display()))]
    Integrity {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "required session stream `{stream}` reached its admitted {maximum_bytes}-byte limit"
    ))]
    RequiredSinkFull {
        stream: String,
        maximum_bytes: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session stream `{stream}` state lock is poisoned"))]
    StateLock {
        stream: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("input lease `{lease_id}` is not owned by client `{client_id}`"))]
    LeaseNotOwned {
        lease_id: String,
        client_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("interactive input is already leased to another client"))]
    LeaseUnavailable {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("input lease duration must be positive"))]
    InvalidLeaseDuration {
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionOutputError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } => StatusCode::External,
            Self::Decode { .. } | Self::Integrity { .. } | Self::InvalidLeaseDuration { .. } => {
                StatusCode::InvalidArguments
            }
            Self::RequiredSinkFull { .. } => StatusCode::Unavailable,
            Self::StateLock { .. } => StatusCode::Internal,
            Self::LeaseNotOwned { .. } => StatusCode::PermissionDenied,
            Self::LeaseUnavailable { .. } => StatusCode::AlreadyExists,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::LeaseUnavailable { .. } => RetryHint::Retryable,
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
