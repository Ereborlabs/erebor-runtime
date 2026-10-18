use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Invalid,
    Limit,
    Denied,
    Conflict,
    Missing,
    Unsupported,
    Incomplete,
}

impl ErrorCode {
    pub fn error(self, field: &'static str) -> Error {
        PackageSnafu { code: self, field }.build()
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Package {code:?} rejects {field}"))]
    Package {
        code: ErrorCode,
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package encoding failed: {source}"))]
    PackageEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract failed: {source}"))]
    AnalysisContract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Image file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Package { code, .. } => match code {
                ErrorCode::Invalid | ErrorCode::Limit => StatusCode::InvalidArguments,
                ErrorCode::Denied => StatusCode::PermissionDenied,
                ErrorCode::Conflict => StatusCode::AlreadyExists,
                ErrorCode::Missing => StatusCode::NotFound,
                ErrorCode::Unsupported => StatusCode::Unsupported,
                ErrorCode::Incomplete => StatusCode::Unavailable,
            },
            Self::PackageEncoding { .. } => StatusCode::InvalidArguments,
            Self::AnalysisContract { source, .. } => source.status_code(),
            Self::Io { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::AnalysisContract { source, .. } => source.retry_hint(),
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
