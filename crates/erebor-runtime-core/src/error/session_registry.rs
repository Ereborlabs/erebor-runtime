use std::{any::Any, io, path::PathBuf};

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
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::CreateDir { source, .. }
            | Self::CopyArtifact { source, .. }
            | Self::ReadRecord { source, .. }
            | Self::WriteRecord { source, .. } => RetryHint::from_io_error(source),
            Self::EncodeRecord { .. } | Self::DecodeRecord { .. } | Self::UnknownSession { .. } => {
                RetryHint::NonRetryable
            }
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
