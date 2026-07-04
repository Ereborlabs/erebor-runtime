use std::{io, path::PathBuf};

use erebor_runtime_core::{RuntimeConfigError, RuntimeError, SessionRegistryError};
use erebor_runtime_policy::PolicyError;
use erebor_runtime_terminal::TerminalSurfaceError;
use snafu::Location;
use thiserror::Error;

use crate::runtime_interception_broker::RuntimeInterceptionBrokerError;

#[derive(Debug, Error)]
pub enum SessionExecutionError {
    #[error("{source}")]
    InvalidConfig {
        source: RuntimeConfigError,
        location: Location,
    },
    #[error("failed to read policy `{}`: {source}", path.display())]
    ReadPolicy {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("{source}")]
    InvalidPolicy {
        source: PolicyError,
        location: Location,
    },
    #[error("{source}")]
    Runtime {
        source: RuntimeError,
        location: Location,
    },
    #[error("{source}")]
    TerminalSurface {
        source: TerminalSurfaceError,
        location: Location,
    },
    #[error("guarded session diagnostic failed: {reason}")]
    DiagnosticFailed { reason: String, location: Location },
    #[error("Linux process guard I/O failed: {source}")]
    GuardIo {
        source: io::Error,
        location: Location,
    },
    #[error("Linux process guard config is invalid: {reason}")]
    GuardConfig { reason: String, location: Location },
    #[error("{source}")]
    SessionRegistry {
        source: SessionRegistryError,
        location: Location,
    },
    #[error("{source}")]
    RuntimeInterceptionBroker {
        source: RuntimeInterceptionBrokerError,
        location: Location,
    },
    #[error("failed to read process table `{}`: {source}", path.display())]
    ReadProcessTable {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("invalid session adoption target: {reason}")]
    InvalidAdoptTarget { reason: String, location: Location },
    #[error("no running process matched session adoption pattern `{pattern}`")]
    AdoptMatchNotFound { pattern: String, location: Location },
    #[error("session adoption pattern `{pattern}` matched multiple processes: {}", matches.join(", "))]
    AdoptMatchAmbiguous {
        pattern: String,
        matches: Vec<String>,
        location: Location,
    },
}

impl SessionExecutionError {
    #[track_caller]
    pub(crate) fn invalid_config(source: RuntimeConfigError) -> Self {
        Self::InvalidConfig {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn invalid_policy(source: PolicyError) -> Self {
        Self::InvalidPolicy {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn runtime(source: RuntimeError) -> Self {
        Self::Runtime {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn terminal_surface(source: TerminalSurfaceError) -> Self {
        Self::TerminalSurface {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn diagnostic_failed(reason: impl Into<String>) -> Self {
        Self::DiagnosticFailed {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn guard_io(source: io::Error) -> Self {
        Self::GuardIo {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn guard_config(reason: impl Into<String>) -> Self {
        Self::GuardConfig {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn session_registry(source: SessionRegistryError) -> Self {
        Self::SessionRegistry {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn runtime_interception_broker(source: RuntimeInterceptionBrokerError) -> Self {
        Self::RuntimeInterceptionBroker {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn invalid_adopt_target(reason: impl Into<String>) -> Self {
        Self::InvalidAdoptTarget {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn adopt_match_not_found(pattern: impl Into<String>) -> Self {
        Self::AdoptMatchNotFound {
            pattern: pattern.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn adopt_match_ambiguous(pattern: impl Into<String>, matches: Vec<String>) -> Self {
        Self::AdoptMatchAmbiguous {
            pattern: pattern.into(),
            matches,
            location: Location::default(),
        }
    }
}
