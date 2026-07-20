use std::any::Any;

use erebor_runtime_core::{RuntimeError, SessionRunnerKind};
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

use super::SessionRepositoryError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionSupervisorError {
    #[snafu(display("{source}"))]
    Repository {
        source: SessionRepositoryError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Runner {
        source: RuntimeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runner `{}` is not available on this daemon host", runner.as_str()))]
    RunnerUnavailable {
        runner: SessionRunnerKind,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` has no active runner handle"))]
    ActiveHandleMissing {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` active handle lock is poisoned"))]
    ActiveHandleLock {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runner capabilities changed after session `{session_id}` was admitted"))]
    CapabilityChanged {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionSupervisorError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Repository { source, .. } => source.status_code(),
            Self::Runner { source, .. } => source.status_code(),
            Self::RunnerUnavailable { .. } => StatusCode::Unavailable,
            Self::ActiveHandleMissing { .. }
            | Self::ActiveHandleLock { .. }
            | Self::CapabilityChanged { .. } => StatusCode::IllegalState,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Repository { source, .. } => source.retry_hint(),
            Self::Runner { source, .. } => source.retry_hint(),
            Self::RunnerUnavailable { .. } | Self::ActiveHandleLock { .. } => RetryHint::Retryable,
            Self::ActiveHandleMissing { .. } | Self::CapabilityChanged { .. } => {
                RetryHint::NonRetryable
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
