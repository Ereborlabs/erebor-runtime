use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

use super::SessionOutputError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionControllerError {
    #[snafu(display("session controller I/O failed while {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session controller protocol failed: {source}"))]
    Protocol {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session controller handoff is invalid: {reason}"))]
    InvalidHandoff {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session controller command `{program}` failed: {reason}"))]
    Command {
        program: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session controller output continuity failed: {source}"))]
    Output {
        source: SessionOutputError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session controller command channel failed"))]
    CommandChannel {
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionControllerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } | Self::Command { .. } | Self::Output { .. } => StatusCode::External,
            Self::Protocol { .. } | Self::InvalidHandoff { .. } => StatusCode::InvalidArguments,
            Self::CommandChannel { .. } => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Output { source, .. } => source.retry_hint(),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
