use std::{any::Any, io};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_policy::PolicyError;
use snafu::{Location, Snafu};

use crate::engine::AuditError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RuntimeError {
    #[snafu(display("policy evaluation failed: {source}"))]
    Policy {
        source: PolicyError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context pin session `{pin_session_id}` does not match event session `{event_session_id}`"
    ))]
    ContextSessionMismatch {
        event_session_id: String,
        pin_session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("durable context audit failed: {source}"))]
    DurableAudit {
        source: AuditError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to build async runtime: {source}"))]
    BuildAsyncRuntime {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session surface start plan includes unsupported surface `{surface}`"))]
    UnsupportedSessionSurface {
        surface: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session surface start plan did not include any services"))]
    NoSessionSurfaceServices {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to start session surface `{surface}`: {reason}"))]
    SurfaceStart {
        surface: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session surface `{surface}` exited: {reason}"))]
    SurfaceExited {
        surface: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to launch session runner `{runner}` using `{program}`: {source}"))]
    SessionRunnerLaunch {
        runner: String,
        program: String,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session runner `{runner}` exited unsuccessfully with code {code:?}"))]
    SessionRunnerExit {
        runner: String,
        code: Option<i32>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session runner `{runner}` does not support `{operation}`"))]
    UnsupportedSessionRunnerOperation {
        runner: String,
        operation: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for RuntimeError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Policy { source, .. } => source.status_code(),
            Self::DurableAudit { source, .. } => source.status_code(),
            Self::BuildAsyncRuntime { .. }
            | Self::SurfaceStart { .. }
            | Self::SurfaceExited { .. }
            | Self::SessionRunnerLaunch { .. }
            | Self::SessionRunnerExit { .. } => StatusCode::External,
            Self::UnsupportedSessionSurface { .. }
            | Self::UnsupportedSessionRunnerOperation { .. } => StatusCode::Unsupported,
            Self::NoSessionSurfaceServices { .. } | Self::ContextSessionMismatch { .. } => {
                StatusCode::IllegalState
            }
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Policy { source, .. } => source.retry_hint(),
            Self::DurableAudit { source, .. } => source.retry_hint(),
            Self::BuildAsyncRuntime { source, .. } | Self::SessionRunnerLaunch { source, .. } => {
                RetryHint::from_io_error(source)
            }
            Self::UnsupportedSessionSurface { .. }
            | Self::NoSessionSurfaceServices { .. }
            | Self::SurfaceStart { .. }
            | Self::SurfaceExited { .. }
            | Self::SessionRunnerExit { .. }
            | Self::UnsupportedSessionRunnerOperation { .. }
            | Self::ContextSessionMismatch { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::RuntimeError;

    #[test]
    fn runtime_statuses_cover_external_unsupported_and_illegal_state() {
        let launch = RuntimeError::SessionRunnerLaunch {
            runner: String::from("linux-host"),
            program: String::from("sh"),
            source: io::Error::from(io::ErrorKind::ConnectionRefused),
            location: Location::default(),
        };
        assert_eq!(launch.status_code(), StatusCode::External);
        assert_eq!(launch.retry_hint(), RetryHint::Retryable);

        let unsupported = RuntimeError::UnsupportedSessionRunnerOperation {
            runner: String::from("docker"),
            operation: String::from("adopt"),
            location: Location::default(),
        };
        assert_eq!(unsupported.status_code(), StatusCode::Unsupported);

        let empty = RuntimeError::NoSessionSurfaceServices {
            location: Location::default(),
        };
        assert_eq!(empty.status_code(), StatusCode::IllegalState);
    }
}
