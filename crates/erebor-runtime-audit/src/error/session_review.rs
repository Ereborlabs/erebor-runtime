use std::{any::Any, io, path::PathBuf};

use erebor_runtime_core::{RuntimeConfigError, SessionRegistryError};
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

use super::AuditLogError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionReviewError {
    #[snafu(display("{source}"))]
    AuditLog {
        source: AuditLogError,
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
    #[snafu(display("failed to read `{}`: {source}", path.display()))]
    ReadFile {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config `{}` is invalid: {source}", path.display()))]
    InvalidRuntimeConfig {
        path: PathBuf,
        source: RuntimeConfigError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode session review JSON output: {source}"))]
    EncodeJson {
        source: serde_json::Error,
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

impl ErrorExt for SessionReviewError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AuditLog { source, .. } => source.status_code(),
            Self::NoSessionRecords { .. }
            | Self::MissingPolicyArtifact { .. }
            | Self::MissingConfigArtifact { .. } => StatusCode::IllegalState,
            Self::UnknownSession { .. } => StatusCode::NotFound,
            Self::ReadFile { .. } => StatusCode::External,
            Self::InvalidRuntimeConfig { source, .. } => source.status_code(),
            Self::EncodeJson { .. } => StatusCode::Unexpected,
            Self::SessionRegistry { source, .. } => source.status_code(),
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::AuditLog { source, .. } => source.retry_hint(),
            Self::ReadFile { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidRuntimeConfig { source, .. } => source.retry_hint(),
            Self::SessionRegistry { source, .. } => source.retry_hint(),
            Self::NoSessionRecords { .. }
            | Self::UnknownSession { .. }
            | Self::EncodeJson { .. }
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

    use super::SessionReviewError;

    #[test]
    fn session_review_statuses_cover_not_found_and_illegal_state() {
        let missing_session = SessionReviewError::UnknownSession {
            session_id: String::from("missing"),
            location: Location::default(),
        };
        assert_eq!(missing_session.status_code(), StatusCode::NotFound);

        let no_records = SessionReviewError::NoSessionRecords {
            location: Location::default(),
        };
        assert_eq!(no_records.status_code(), StatusCode::IllegalState);
    }
}
