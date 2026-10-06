use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};
use tonic::Code;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum AraphorError {
    #[snafu(display("Araphor input is invalid: {field}"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read Araphor file `{}`: {source}", path.display()))]
    Read {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to connect to the Araphor TLS endpoint: {source}"))]
    Connect {
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor RPC failed with {}", source.code()))]
    Rpc {
        #[snafu(source(from(tonic::Status, Box::new)))]
        source: Box<tonic::Status>,
        #[snafu(implicit)]
        location: Location,
    },
}

impl AraphorError {
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Connect { .. })
            || matches!(self, Self::Rpc { source, .. } if matches!(source.code(), Code::Unavailable | Code::Unknown))
    }

    pub fn expired(&self) -> bool {
        matches!(self, Self::Rpc { source, .. } if source.code() == Code::OutOfRange)
    }
}

impl ErrorExt for AraphorError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } => StatusCode::InvalidArguments,
            Self::Read { .. } => StatusCode::External,
            Self::Connect { .. } => StatusCode::Unavailable,
            Self::Rpc { source, .. } => match source.code() {
                Code::InvalidArgument => StatusCode::InvalidArguments,
                Code::PermissionDenied | Code::Unauthenticated => StatusCode::PermissionDenied,
                Code::OutOfRange | Code::DataLoss | Code::FailedPrecondition => {
                    StatusCode::IllegalState
                }
                Code::Cancelled => StatusCode::Cancelled,
                Code::DeadlineExceeded => StatusCode::DeadlineExceeded,
                Code::Unimplemented => StatusCode::Unsupported,
                Code::NotFound => StatusCode::NotFound,
                Code::AlreadyExists | Code::Aborted => StatusCode::AlreadyExists,
                Code::Unavailable | Code::ResourceExhausted => StatusCode::Unavailable,
                Code::Ok => StatusCode::Success,
                Code::Unknown | Code::Internal => StatusCode::Internal,
            },
        }
    }

    fn retry_hint(&self) -> RetryHint {
        if self.retryable() {
            RetryHint::Retryable
        } else {
            RetryHint::NonRetryable
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
