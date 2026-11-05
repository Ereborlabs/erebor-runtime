use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use serde::{Deserialize, Serialize};
use snafu::{IntoError as _, Location, Snafu};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum ErrorCode {
    Invalid = 1,
    Incompatible = 2,
    Unauthorized = 3,
    Incomplete = 4,
    Failed = 5,
    Limit = 6,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Analysis host failed: {source}"))]
    Backend {
        source: BackendError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract {code:?} at {field}"))]
    Contract {
        code: ErrorCode,
        field: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis descriptor encoding failed: {source}"))]
    Encoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis batch is invalid: {source}"))]
    #[snafu(context(false))]
    Batch {
        source: arrow_schema::ArrowError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis file {} failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct BackendError(Box<dyn ErrorExt + Send + Sync>);

impl std::fmt::Display for BackendError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(output)
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl Error {
    pub fn backend(source: impl ErrorExt + Send + Sync + 'static) -> Self {
        BackendSnafu.into_error(BackendError(Box::new(source)))
    }
    #[track_caller]
    pub fn contract(code: ErrorCode, field: impl Into<String>) -> Self {
        ContractSnafu { code, field }.build()
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Backend { source, .. } => match source.0.status_code() {
                StatusCode::PermissionDenied | StatusCode::PolicyDenied => ErrorCode::Unauthorized,
                StatusCode::InvalidArguments | StatusCode::InvalidSyntax => ErrorCode::Invalid,
                StatusCode::Unsupported => ErrorCode::Incompatible,
                StatusCode::Unavailable
                | StatusCode::Cancelled
                | StatusCode::DeadlineExceeded
                | StatusCode::IllegalState => ErrorCode::Incomplete,
                _ => ErrorCode::Failed,
            },
            Self::Contract { code, .. } => *code,
            Self::Batch {
                source: arrow_schema::ArrowError::IoError(_, error),
                ..
            } if error.kind() == std::io::ErrorKind::FileTooLarge => ErrorCode::Limit,
            Self::Batch { .. } => ErrorCode::Invalid,
            Self::Encoding { .. } | Self::Io { .. } => ErrorCode::Failed,
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        if let Self::Backend { source, .. } = self {
            return source.0.status_code();
        }
        match self.code() {
            ErrorCode::Invalid | ErrorCode::Limit => StatusCode::InvalidArguments,
            ErrorCode::Incompatible => StatusCode::Unsupported,
            ErrorCode::Unauthorized => StatusCode::PermissionDenied,
            ErrorCode::Incomplete => StatusCode::Unavailable,
            ErrorCode::Failed => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Backend { source, .. } => source.0.retry_hint(),
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
