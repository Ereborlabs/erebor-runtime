use std::{any::Any, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};
use tonic::Code;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum DaemonClientError {
    #[snafu(display("failed to connect to erebord at `{}`: {source}", path.display()))]
    Connect {
        path: PathBuf,
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon client timed out while {operation}"))]
    TimedOut {
        operation: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon gRPC contract failed: {reason}"))]
    Protocol {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon rejected the request: {message}"))]
    Rpc {
        code: Code,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, DaemonClientError>;

impl ErrorExt for DaemonClientError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Connect { .. } | Self::TimedOut { .. } => StatusCode::Unavailable,
            Self::Protocol { .. } => StatusCode::InvalidArguments,
            Self::Rpc { code, .. } => match code {
                Code::Cancelled => StatusCode::Cancelled,
                Code::InvalidArgument | Code::OutOfRange => StatusCode::InvalidArguments,
                Code::DeadlineExceeded => StatusCode::DeadlineExceeded,
                Code::NotFound => StatusCode::NotFound,
                Code::AlreadyExists => StatusCode::AlreadyExists,
                Code::PermissionDenied | Code::Unauthenticated => StatusCode::PermissionDenied,
                Code::FailedPrecondition | Code::Aborted => StatusCode::IllegalState,
                Code::Unimplemented => StatusCode::Unsupported,
                Code::Unavailable | Code::ResourceExhausted => StatusCode::Unavailable,
                Code::Unknown | Code::Internal | Code::DataLoss => StatusCode::Internal,
                Code::Ok => StatusCode::Success,
            },
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Connect { .. } | Self::TimedOut { .. } => RetryHint::Retryable,
            Self::Rpc {
                code: Code::Unavailable | Code::ResourceExhausted,
                ..
            } => RetryHint::Retryable,
            Self::Protocol { .. } | Self::Rpc { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
