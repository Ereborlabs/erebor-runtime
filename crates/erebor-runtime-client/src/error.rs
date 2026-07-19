use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_ipc::IpcProtocolError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum DaemonClientError {
    #[snafu(display("failed to connect to erebord at `{}`: {source}", path.display()))]
    Connect {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon client I/O failed: {source}"))]
    Io {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon client timed out while {operation}"))]
    TimedOut {
        operation: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon IPC failed: {source}"))]
    Ipc {
        source: IpcProtocolError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon protocol failed: {reason}"))]
    Protocol {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon rejected the request: {message}"))]
    Daemon {
        status_code: u32,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, DaemonClientError>;

impl ErrorExt for DaemonClientError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Connect { .. } | Self::Io { .. } | Self::TimedOut { .. } => {
                StatusCode::Unavailable
            }
            Self::Ipc { source, .. } => source.status_code(),
            Self::Protocol { .. } => StatusCode::InvalidArguments,
            Self::Daemon { status_code, .. } => {
                StatusCode::from_u32(*status_code).unwrap_or(StatusCode::Unknown)
            }
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Connect { source, .. } | Self::Io { source, .. } => {
                RetryHint::from_io_error(source)
            }
            Self::TimedOut { .. } => RetryHint::Retryable,
            Self::Ipc { source, .. } => source.retry_hint(),
            Self::Protocol { .. } | Self::Daemon { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
