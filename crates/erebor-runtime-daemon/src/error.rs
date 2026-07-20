use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_ipc::IpcProtocolError;
use erebor_runtime_session::{
    RuntimeInterceptionBrokerError, SessionOutputError, SessionSupervisorError,
};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum DaemonError {
    #[snafu(display("daemon I/O failed while {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon configuration `{}` is invalid: {source}", path.display()))]
    InvalidConfig {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon path `{}` is unsafe: {reason}", path.display()))]
    UnsafePath {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("another erebord instance already owns `{}`", path.display()))]
    AlreadyRunning {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon lock at `{}` could not be acquired", path.display()))]
    LockUnavailable {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon socket group `{group}` is not available"))]
    SocketGroupUnavailable {
        group: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon request is not authorized for observed uid {uid}"))]
    Unauthorized {
        uid: u32,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon request is invalid: {reason}"))]
    InvalidRequest {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon idempotency key conflicts with an earlier request"))]
    IdempotencyConflict {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon idempotency store is full at {capacity} pending records"))]
    IdempotencyCapacity {
        capacity: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon state lock is poisoned"))]
    StateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon IPC failed: {source}"))]
    Ipc {
        source: IpcProtocolError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon session operation failed: {source}"))]
    Session {
        #[snafu(source(from(SessionSupervisorError, Box::new)))]
        source: Box<SessionSupervisorError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon session output operation failed: {source}"))]
    SessionOutput {
        source: SessionOutputError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon runtime guard operation failed: {source}"))]
    RuntimeGuard {
        source: RuntimeInterceptionBrokerError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, DaemonError>;

impl ErrorExt for DaemonError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } => StatusCode::External,
            Self::InvalidConfig { .. }
            | Self::UnsafePath { .. }
            | Self::InvalidRequest { .. }
            | Self::IdempotencyConflict { .. } => StatusCode::InvalidArguments,
            Self::AlreadyRunning { .. } => StatusCode::AlreadyExists,
            Self::LockUnavailable { .. }
            | Self::SocketGroupUnavailable { .. }
            | Self::IdempotencyCapacity { .. } => StatusCode::Unavailable,
            Self::Unauthorized { .. } => StatusCode::PermissionDenied,
            Self::StateLock { .. } => StatusCode::Internal,
            Self::Ipc { source, .. } => source.status_code(),
            Self::Session { source, .. } => source.status_code(),
            Self::SessionOutput { source, .. } => source.status_code(),
            Self::RuntimeGuard { source, .. } => source.status_code(),
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Ipc { source, .. } => source.retry_hint(),
            Self::Session { source, .. } => source.retry_hint(),
            Self::SessionOutput { source, .. } => source.retry_hint(),
            Self::RuntimeGuard { source, .. } => source.retry_hint(),
            Self::LockUnavailable { .. } | Self::AlreadyRunning { .. } => RetryHint::Retryable,
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
