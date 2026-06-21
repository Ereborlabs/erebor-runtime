use std::{io, path::PathBuf};

use erebor_runtime_core::{RuntimeConfigError, SessionRegistryError};
use snafu::Location;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("failed to open audit log `{}`: {source}", path.display())]
    Open {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to read audit log `{}`: {source}", path.display())]
    Read {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to write audit log `{}`: {source}", path.display())]
    Write {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to serialize audit record for `{}`: {source}", path.display())]
    SerializeRecord {
        path: PathBuf,
        source: serde_json::Error,
        location: Location,
    },
    #[error("invalid audit record in `{}` at line {line}: {source}", path.display())]
    InvalidRecord {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
        location: Location,
    },
}

impl AuditLogError {
    #[track_caller]
    pub fn open(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Open {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn read(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Read {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn write(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Write {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn serialize_record(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::SerializeRecord {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_record(
        path: impl Into<PathBuf>,
        line: usize,
        source: serde_json::Error,
    ) -> Self {
        Self::InvalidRecord {
            path: path.into(),
            line,
            source,
            location: Location::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum EvidenceTraceError {
    #[error("{source}")]
    AuditLog {
        source: AuditLogError,
        location: Location,
    },
    #[error("failed to read `{}`: {source}", path.display())]
    ReadFile {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to write `{}`: {source}", path.display())]
    WriteFile {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("JSON artifact `{}` is invalid: {source}", path.display())]
    InvalidJson {
        path: PathBuf,
        source: serde_json::Error,
        location: Location,
    },
    #[error("audit file does not contain session records")]
    NoSessionRecords { location: Location },
    #[error("audit file does not contain records for session id `{session_id}`")]
    UnknownSession {
        session_id: String,
        location: Location,
    },
}

impl EvidenceTraceError {
    #[track_caller]
    pub(crate) fn audit_log(source: AuditLogError) -> Self {
        Self::AuditLog {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn read_file(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::ReadFile {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn write_file(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::WriteFile {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn invalid_json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::InvalidJson {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn no_session_records() -> Self {
        Self::NoSessionRecords {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn unknown_session(session_id: impl Into<String>) -> Self {
        Self::UnknownSession {
            session_id: session_id.into(),
            location: Location::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SessionReviewError {
    #[error("{source}")]
    AuditLog {
        source: AuditLogError,
        location: Location,
    },
    #[error("audit file does not contain session records")]
    NoSessionRecords { location: Location },
    #[error("audit file does not contain records for session id `{session_id}`")]
    UnknownSession {
        session_id: String,
        location: Location,
    },
    #[error("failed to read `{}`: {source}", path.display())]
    ReadFile {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("runtime config `{}` is invalid: {source}", path.display())]
    InvalidRuntimeConfig {
        path: PathBuf,
        source: RuntimeConfigError,
        location: Location,
    },
    #[error("failed to encode session review JSON output: {source}")]
    EncodeJson {
        source: serde_json::Error,
        location: Location,
    },
    #[error("{source}")]
    SessionRegistry {
        source: SessionRegistryError,
        location: Location,
    },
    #[error("explicit audit review requires --audit, --policy, and --config")]
    IncompleteExplicitReviewPaths { location: Location },
    #[error("session `{session_id}` registry record does not include a copied policy artifact")]
    MissingPolicyArtifact {
        session_id: String,
        location: Location,
    },
    #[error("session `{session_id}` registry record does not include a copied config artifact")]
    MissingConfigArtifact {
        session_id: String,
        location: Location,
    },
}

impl SessionReviewError {
    #[track_caller]
    pub(crate) fn audit_log(source: AuditLogError) -> Self {
        Self::AuditLog {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn no_session_records() -> Self {
        Self::NoSessionRecords {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn unknown_session(session_id: impl Into<String>) -> Self {
        Self::UnknownSession {
            session_id: session_id.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn read_file(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::ReadFile {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn invalid_runtime_config(
        path: impl Into<PathBuf>,
        source: RuntimeConfigError,
    ) -> Self {
        Self::InvalidRuntimeConfig {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn encode_json(source: serde_json::Error) -> Self {
        Self::EncodeJson {
            source,
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
    pub(crate) fn incomplete_explicit_review_paths() -> Self {
        Self::IncompleteExplicitReviewPaths {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn missing_policy_artifact(session_id: impl Into<String>) -> Self {
        Self::MissingPolicyArtifact {
            session_id: session_id.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub(crate) fn missing_config_artifact(session_id: impl Into<String>) -> Self {
        Self::MissingConfigArtifact {
            session_id: session_id.into(),
            location: Location::default(),
        }
    }
}
