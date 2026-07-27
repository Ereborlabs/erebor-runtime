use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum TelemetryError {
    #[snafu(display("telemetry I/O failed while {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("telemetry record at `{}` could not be encoded: {source}", path.display()))]
    Encode {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("telemetry record at `{}` could not be decoded: {source}", path.display()))]
    Decode {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("telemetry state lock is poisoned"))]
    StateLock {
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, TelemetryError>;

impl ErrorExt for TelemetryError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } => StatusCode::External,
            Self::Encode { .. } | Self::Decode { .. } | Self::StateLock { .. } => {
                StatusCode::Internal
            }
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Encode { .. } | Self::Decode { .. } | Self::StateLock { .. } => {
                RetryHint::NonRetryable
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
