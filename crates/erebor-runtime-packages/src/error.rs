use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PackageError {
    #[snafu(display("invalid package model: {reason}"))]
    InvalidModel {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("canonical encoding failed: {source}"))]
    CanonicalEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, PackageError>;

impl ErrorExt for PackageError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidModel { .. } => StatusCode::InvalidArguments,
            Self::CanonicalEncoding { .. } => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::InvalidModel { .. } | Self::CanonicalEncoding { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
