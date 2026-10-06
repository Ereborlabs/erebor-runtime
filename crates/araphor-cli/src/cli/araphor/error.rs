use std::{any::Any, io};

use erebor_runtime_client::AraphorError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub(crate) enum AraphorCommandError {
    #[snafu(display("Araphor command is invalid: {field}"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor response is invalid: {field}"))]
    Protocol {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read command input: {source}"))]
    Input {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Client {
        source: AraphorError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode command output: {source}"))]
    Encode {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write command output: {source}"))]
    Output {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to start the command runtime: {source}"))]
    Runtime {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("the result is partial or limited"))]
    Partial {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("the stream ended without a final result"))]
    Uncertain {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("the output wait reached its deadline"))]
    OutputDeadline {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("the command was interrupted"))]
    Interrupted {
        #[snafu(implicit)]
        location: Location,
    },
}

pub(super) type Result<T> = std::result::Result<T, AraphorCommandError>;

impl AraphorCommandError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Invalid { .. } => 2,
            Self::Partial { .. } | Self::Uncertain { .. } | Self::OutputDeadline { .. } => 4,
            Self::Output { source, .. } if source.kind() == io::ErrorKind::BrokenPipe => 4,
            Self::Interrupted { .. } => 130,
            Self::Client { source, .. } if source.expired() => 4,
            Self::Client { source, .. } => match source.status_code() {
                StatusCode::InvalidArguments => 2,
                StatusCode::PermissionDenied | StatusCode::PolicyDenied => 3,
                _ => 5,
            },
            _ => 5,
        }
    }
}

impl ErrorExt for AraphorCommandError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } => StatusCode::InvalidArguments,
            Self::Protocol { .. } => StatusCode::IllegalState,
            Self::Input { .. } | Self::Output { .. } => StatusCode::External,
            Self::Client { source, .. } => source.status_code(),
            Self::Encode { .. } | Self::Runtime { .. } => StatusCode::Internal,
            Self::Partial { .. } | Self::Uncertain { .. } => StatusCode::IllegalState,
            Self::OutputDeadline { .. } => StatusCode::DeadlineExceeded,
            Self::Interrupted { .. } => StatusCode::Cancelled,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
