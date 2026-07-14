use std::{any::Any, io, path::PathBuf};

use erebor_runtime_context::ContextRepositoryError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum SessionRegistryError {
    #[snafu(display("failed to create session registry directory `{}`: {source}", path.display()))]
    CreateDir {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to copy session artifact from `{}` to `{}`: {source}",
        from.display(),
        to.display()
    ))]
    CopyArtifact {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read session registry record `{}`: {source}", path.display()))]
    ReadRecord {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write session registry record `{}`: {source}", path.display()))]
    WriteRecord {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode session registry record `{}`: {source}", path.display()))]
    EncodeRecord {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to decode session registry record `{}`: {source}", path.display()))]
    DecodeRecord {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session registry `{}` does not contain session `{session_id}`",
        root.display()
    ))]
    UnknownSession {
        root: PathBuf,
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session id `{requested_session_id}` maps to `{}`, which belongs to session `{stored_session_id}`",
        session_dir.display()
    ))]
    SessionDirectoryCollision {
        requested_session_id: String,
        stored_session_id: String,
        session_dir: Box<PathBuf>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session directory `{}` is already occupied and cannot be assigned to session `{session_id}`",
        session_dir.display()
    ))]
    SessionDirectoryOccupied {
        session_id: String,
        session_dir: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session id `{session_id}` does not produce a safe session directory name"))]
    InvalidSessionDirectoryName {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "requested session `{requested_session_id}` does not match the record's session id `{recorded_session_id}` at `{}`",
        record_path.display()
    ))]
    SessionIdMismatch {
        requested_session_id: String,
        recorded_session_id: String,
        record_path: Box<PathBuf>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session record `{}` names directory `{}`, but `{}` is the authorized directory",
        record_path.display(),
        actual_session_dir.display(),
        expected_session_dir.display()
    ))]
    SessionDirectoryMismatch {
        record_path: Box<PathBuf>,
        expected_session_dir: PathBuf,
        actual_session_dir: Box<PathBuf>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session directory `{}` must not be a symbolic link", path.display()))]
    SessionDirectorySymlink {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context artifact metadata for session `{session_id}` has invalid {field} `{actual}`; expected `{expected}`"
    ))]
    InvalidContextArtifactMetadata {
        session_id: String,
        field: &'static str,
        expected: &'static str,
        actual: Box<str>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context artifact path `{}` for session `{session_id}` is invalid: {reason}",
        path.display()
    ))]
    InvalidContextArtifactPath {
        session_id: String,
        path: Box<PathBuf>,
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context artifact for session `{session_id}` is missing at `{}`",
        path.display()
    ))]
    MissingContextArtifact {
        session_id: String,
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context artifact root for session `{session_id}` must not be a symbolic link: `{}`",
        path.display()
    ))]
    ContextArtifactSymlink {
        session_id: String,
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to inspect context artifact path `{}` for session `{session_id}`: {source}",
        path.display()
    ))]
    InspectContextArtifact {
        session_id: String,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to initialize or open context repository for session `{session_id}` at `{}`: {source}",
        path.display()
    ))]
    ContextRepository {
        session_id: String,
        path: PathBuf,
        source: Box<ContextRepositoryError>,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for SessionRegistryError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::CreateDir { .. }
            | Self::CopyArtifact { .. }
            | Self::ReadRecord { .. }
            | Self::WriteRecord { .. } => StatusCode::External,
            Self::EncodeRecord { .. } => StatusCode::Unexpected,
            Self::DecodeRecord { .. } => StatusCode::InvalidSyntax,
            Self::UnknownSession { .. } => StatusCode::NotFound,
            Self::SessionDirectoryCollision { .. } | Self::SessionDirectoryOccupied { .. } => {
                StatusCode::AlreadyExists
            }
            Self::InvalidSessionDirectoryName { .. }
            | Self::SessionIdMismatch { .. }
            | Self::SessionDirectoryMismatch { .. }
            | Self::InvalidContextArtifactMetadata { .. }
            | Self::InvalidContextArtifactPath { .. } => StatusCode::InvalidArguments,
            Self::MissingContextArtifact { .. } => StatusCode::NotFound,
            Self::SessionDirectorySymlink { .. } | Self::ContextArtifactSymlink { .. } => {
                StatusCode::IllegalState
            }
            Self::InspectContextArtifact { .. } => StatusCode::External,
            Self::ContextRepository { source, .. } => source.status_code(),
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::CreateDir { source, .. }
            | Self::CopyArtifact { source, .. }
            | Self::ReadRecord { source, .. }
            | Self::WriteRecord { source, .. } => RetryHint::from_io_error(source),
            Self::InspectContextArtifact { source, .. } => RetryHint::from_io_error(source),
            Self::ContextRepository { source, .. } => source.retry_hint(),
            Self::EncodeRecord { .. }
            | Self::DecodeRecord { .. }
            | Self::UnknownSession { .. }
            | Self::SessionDirectoryCollision { .. }
            | Self::SessionDirectoryOccupied { .. }
            | Self::InvalidSessionDirectoryName { .. }
            | Self::SessionIdMismatch { .. }
            | Self::SessionDirectoryMismatch { .. }
            | Self::SessionDirectorySymlink { .. }
            | Self::InvalidContextArtifactMetadata { .. }
            | Self::InvalidContextArtifactPath { .. }
            | Self::MissingContextArtifact { .. }
            | Self::ContextArtifactSymlink { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::SessionRegistryError;

    #[test]
    fn session_registry_statuses_cover_io_decode_and_not_found() {
        let io_error = SessionRegistryError::ReadRecord {
            path: PathBuf::from("session.json"),
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);

        let not_found = SessionRegistryError::UnknownSession {
            root: PathBuf::from(".erebor/sessions"),
            session_id: String::from("missing"),
            location: Location::default(),
        };
        assert_eq!(not_found.status_code(), StatusCode::NotFound);
    }
}
