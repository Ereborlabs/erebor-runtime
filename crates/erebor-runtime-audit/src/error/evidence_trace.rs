use std::{any::Any, io, path::PathBuf};

use erebor_runtime_core::SessionRegistryError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

use super::AuditLogError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum EvidenceTraceError {
    #[snafu(display("{source}"))]
    AuditLog {
        source: AuditLogError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read `{}`: {source}", path.display()))]
    ReadFile {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write `{}`: {source}", path.display()))]
    WriteFile {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("JSON artifact `{}` is invalid: {source}", path.display()))]
    InvalidJson {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("audit file does not contain session records"))]
    NoSessionRecords {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("audit file does not contain records for session id `{session_id}`"))]
    UnknownSession {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    SessionRegistry {
        source: SessionRegistryError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session `{session_id}` registry record does not include a copied policy artifact"
    ))]
    MissingPolicyArtifact {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session `{session_id}` registry record does not include a copied config artifact"
    ))]
    MissingConfigArtifact {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for EvidenceTraceError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuditLog { source, .. } => source.status_code(),
            Self::ReadFile { .. } | Self::WriteFile { .. } => StatusCode::External,
            Self::InvalidJson { .. } => StatusCode::InvalidSyntax,
            Self::UnknownSession { .. } => StatusCode::NotFound,
            Self::SessionRegistry { source, .. } => source.status_code(),
            Self::NoSessionRecords { .. }
            | Self::MissingPolicyArtifact { .. }
            | Self::MissingConfigArtifact { .. } => StatusCode::IllegalState,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::AuditLog { source, .. } => source.retry_hint(),
            Self::ReadFile { source, .. } | Self::WriteFile { source, .. } => {
                RetryHint::from_io_error(source)
            }
            Self::SessionRegistry { source, .. } => source.retry_hint(),
            Self::InvalidJson { .. }
            | Self::NoSessionRecords { .. }
            | Self::UnknownSession { .. }
            | Self::MissingPolicyArtifact { .. }
            | Self::MissingConfigArtifact { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_error::{ErrorExt, StatusCode};
    use snafu::Location;

    use super::EvidenceTraceError;

    #[test]
    fn evidence_trace_statuses_cover_not_found_and_illegal_state() {
        let missing_session = EvidenceTraceError::UnknownSession {
            session_id: String::from("missing"),
            location: Location::default(),
        };
        assert_eq!(missing_session.status_code(), StatusCode::NotFound);

        let missing_artifact = EvidenceTraceError::MissingPolicyArtifact {
            session_id: String::from("session-1"),
            location: Location::default(),
        };
        assert_eq!(missing_artifact.status_code(), StatusCode::IllegalState);
    }
}
