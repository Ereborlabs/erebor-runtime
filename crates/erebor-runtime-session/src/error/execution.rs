use std::{any::Any, io, path::PathBuf};

use erebor_runtime_core::{RuntimeConfigError, RuntimeError, SessionRegistryError};
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_filesystem::FilesystemError;
use erebor_runtime_policy::PolicyError;
use erebor_runtime_terminal::TerminalSurfaceError;
use snafu::{Location, Snafu};

use super::RuntimeInterceptionBrokerError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionExecutionError {
    #[snafu(display("{source}"))]
    InvalidConfig {
        source: RuntimeConfigError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read policy `{}`: {source}", path.display()))]
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
    #[snafu(display("{source}"))]
    Runtime {
        source: RuntimeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    TerminalSurface {
        source: TerminalSurfaceError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("guarded session diagnostic failed: {reason}"))]
    DiagnosticFailed {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Linux process guard I/O failed: {source}"))]
    GuardIo {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Linux process guard config is invalid: {reason}"))]
    GuardConfig {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    SessionRegistry {
        source: SessionRegistryError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    FilesystemSurface {
        #[snafu(source(from(FilesystemError, Box::new)))]
        source: Box<FilesystemError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    RuntimeInterceptionBroker {
        source: RuntimeInterceptionBrokerError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read process table `{}`: {source}", path.display()))]
    ReadProcessTable {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("invalid session adoption target: {reason}"))]
    InvalidAdoptTarget {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("no running process matched session adoption pattern `{pattern}`"))]
    AdoptMatchNotFound {
        pattern: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session adoption pattern `{pattern}` matched multiple processes: {}",
        matches.join(", ")
    ))]
    AdoptMatchAmbiguous {
        pattern: String,
        matches: Vec<String>,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionExecutionError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidConfig { source, .. } => source.status_code(),
            Self::ReadPolicy { .. } => StatusCode::External,
            Self::InvalidPolicy { source, .. } => source.status_code(),
            Self::Runtime { source, .. } => source.status_code(),
            Self::TerminalSurface { source, .. } => source.status_code(),
            Self::DiagnosticFailed { .. } => StatusCode::PolicyDenied,
            Self::GuardIo { .. } => StatusCode::External,
            Self::GuardConfig { .. } => StatusCode::InvalidArguments,
            Self::SessionRegistry { source, .. } => source.status_code(),
            Self::FilesystemSurface { source, .. } => source.status_code(),
            Self::RuntimeInterceptionBroker { source, .. } => source.status_code(),
            Self::ReadProcessTable { .. } => StatusCode::External,
            Self::InvalidAdoptTarget { .. } => StatusCode::InvalidArguments,
            Self::AdoptMatchNotFound { .. } => StatusCode::NotFound,
            Self::AdoptMatchAmbiguous { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::InvalidConfig { source, .. } => source.retry_hint(),
            Self::ReadPolicy { source, .. }
            | Self::GuardIo { source, .. }
            | Self::ReadProcessTable { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidPolicy { source, .. } => source.retry_hint(),
            Self::Runtime { source, .. } => source.retry_hint(),
            Self::TerminalSurface { source, .. } => source.retry_hint(),
            Self::SessionRegistry { source, .. } => source.retry_hint(),
            Self::FilesystemSurface { source, .. } => source.retry_hint(),
            Self::RuntimeInterceptionBroker { source, .. } => source.retry_hint(),
            Self::DiagnosticFailed { .. }
            | Self::GuardConfig { .. }
            | Self::InvalidAdoptTarget { .. }
            | Self::AdoptMatchNotFound { .. }
            | Self::AdoptMatchAmbiguous { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{io, path::PathBuf};

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use erebor_runtime_filesystem::FilesystemError;
    use snafu::Location;

    use super::SessionExecutionError;

    #[test]
    fn session_execution_statuses_cover_guard_adoption_and_denials() {
        let guard_io = SessionExecutionError::GuardIo {
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(guard_io.status_code(), StatusCode::External);
        assert_eq!(guard_io.retry_hint(), RetryHint::Retryable);

        let denied = SessionExecutionError::DiagnosticFailed {
            reason: String::from("raw CDP process launch is denied"),
            location: Location::default(),
        };
        assert_eq!(denied.status_code(), StatusCode::PolicyDenied);

        let not_found = SessionExecutionError::AdoptMatchNotFound {
            pattern: String::from("missing-process"),
            location: Location::default(),
        };
        assert_eq!(not_found.status_code(), StatusCode::NotFound);

        let invalid = SessionExecutionError::InvalidAdoptTarget {
            reason: String::from("process match pattern cannot be empty"),
            location: Location::default(),
        };
        assert_eq!(invalid.status_code(), StatusCode::InvalidArguments);

        let process_table = SessionExecutionError::ReadProcessTable {
            path: PathBuf::from("/proc"),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
            location: Location::default(),
        };
        assert_eq!(process_table.status_code(), StatusCode::External);

        let filesystem = SessionExecutionError::FilesystemSurface {
            source: Box::new(FilesystemError::InvalidVolumeId {
                id: String::from("bad/id"),
                reason: String::from("must be a safe path component"),
                location: Location::default(),
            }),
            location: Location::default(),
        };
        assert_eq!(filesystem.status_code(), StatusCode::InvalidArguments);
    }
}
