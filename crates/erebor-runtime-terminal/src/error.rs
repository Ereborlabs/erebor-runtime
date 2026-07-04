use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_policy::PolicyError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to read terminal policy `{}`: {source}", path.display()))]
    ReadPolicy {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    InvalidPolicy {
        source: PolicyError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to parse terminal policy JSON: {source}"))]
    PolicyJson {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("terminal process guard config is invalid: {reason}"))]
    InvalidGuardConfig {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ReadPolicy { .. } => StatusCode::External,
            Self::InvalidPolicy { source, .. } => source.status_code(),
            Self::PolicyJson { .. } => StatusCode::InvalidSyntax,
            Self::InvalidGuardConfig { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::ReadPolicy { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidPolicy { source, .. } => source.retry_hint(),
            Self::PolicyJson { .. } | Self::InvalidGuardConfig { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
