use std::{any::Any, error::Error, io, path::PathBuf};

use erebor_runtime_core::RuntimeError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

use super::{RuntimeInterceptionBrokerError, SessionOutputError, SessionRepositoryError};

pub type SessionPathResolverError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionManagerError {
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
    #[snafu(display("runner `{runner}` is not available on this daemon host"))]
    RunnerUnavailable {
        runner: String,
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
    #[snafu(display("session runtime I/O failed while {action} `{}`: {source}", path.display()))]
    RuntimeIo {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session runtime guard operation failed: {source}"))]
    RuntimeGuard {
        source: RuntimeInterceptionBrokerError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session output operation failed: {source}"))]
    Output {
        source: SessionOutputError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session path resolution failed for uid {uid} gid {gid} path `{}`: {source}",
        path.display()
    ))]
    PathResolution {
        uid: u32,
        gid: u32,
        path: PathBuf,
        source: SessionPathResolverError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` runtime state is invalid: {reason}"))]
    InvalidRuntime {
        session_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` cannot {operation} from state `{state}`"))]
    InvalidState {
        session_id: String,
        operation: &'static str,
        state: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session `{session_id}` operation is invalid: {reason}"))]
    InvalidOperation {
        session_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session manager {resource} state lock is poisoned"))]
    StateLock {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionManagerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Repository { source, .. } => source.status_code(),
            Self::Runner { source, .. } => source.status_code(),
            Self::RunnerUnavailable { .. } => StatusCode::Unavailable,
            Self::RuntimeIo { .. } | Self::PathResolution { .. } => StatusCode::External,
            Self::RuntimeGuard { source, .. } => source.status_code(),
            Self::Output { source, .. } => source.status_code(),
            Self::InvalidRuntime { .. } | Self::InvalidOperation { .. } => {
                StatusCode::InvalidArguments
            }
            Self::StateLock { .. } => StatusCode::Internal,
            Self::ActiveHandleMissing { .. }
            | Self::ActiveHandleLock { .. }
            | Self::CapabilityChanged { .. }
            | Self::InvalidState { .. } => StatusCode::IllegalState,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Repository { source, .. } => source.retry_hint(),
            Self::Runner { source, .. } => source.retry_hint(),
            Self::RunnerUnavailable { .. } | Self::ActiveHandleLock { .. } => RetryHint::Retryable,
            Self::RuntimeIo { source, .. } => RetryHint::from_io_error(source),
            Self::RuntimeGuard { source, .. } => source.retry_hint(),
            Self::Output { source, .. } => source.retry_hint(),
            Self::PathResolution { .. }
            | Self::InvalidRuntime { .. }
            | Self::StateLock { .. }
            | Self::InvalidState { .. }
            | Self::InvalidOperation { .. } => RetryHint::NonRetryable,
            Self::ActiveHandleMissing { .. } | Self::CapabilityChanged { .. } => {
                RetryHint::NonRetryable
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
