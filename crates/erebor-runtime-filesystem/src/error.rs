use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

pub type Result<T> = std::result::Result<T, FilesystemError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum FilesystemError {
    #[snafu(display("filesystem volume id `{id}` is invalid: {reason}"))]
    InvalidVolumeId {
        id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` {field} path `{}` is invalid: {reason}",
        path.display()
    ))]
    InvalidVolumePath {
        volume_id: String,
        field: &'static str,
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to create filesystem storage directory `{}`: {source}", path.display()))]
    CreateStorageDir {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem overlay session view is unsupported on `{platform}`"))]
    UnsupportedOverlayPlatform {
        platform: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem overlay session view requires `{command}` in PATH"))]
    MissingOverlayCommand {
        command: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem volume `{volume_id}` overlay session view is invalid: {reason}"))]
    InvalidOverlaySessionView {
        volume_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to inspect filesystem volume `{volume_id}` {field} path `{}`: {source}",
        path.display()
    ))]
    InspectOverlaySessionPath {
        volume_id: String,
        field: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to create filesystem volume `{volume_id}` overlay session directory `{}`: {source}",
        path.display()
    ))]
    CreateOverlaySessionDir {
        volume_id: String,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write filesystem overlay wrapper `{}`: {source}", path.display()))]
    WriteOverlayWrapper {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to set filesystem overlay wrapper permissions `{}`: {source}",
        path.display()
    ))]
    SetOverlayWrapperPermissions {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to start ostree for repo `{}`: {source}", repo.display()))]
    StartOstree {
        repo: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "ostree init failed for repo `{}` with exit code {:?}: {}",
        repo.display(),
        code,
        stderr
    ))]
    OstreeInitFailed {
        repo: PathBuf,
        code: Option<i32>,
        stderr: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for FilesystemError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidVolumeId { .. }
            | Self::InvalidVolumePath { .. }
            | Self::UnsupportedOverlayPlatform { .. }
            | Self::MissingOverlayCommand { .. }
            | Self::InvalidOverlaySessionView { .. } => StatusCode::InvalidArguments,
            Self::CreateStorageDir { .. }
            | Self::InspectOverlaySessionPath { .. }
            | Self::CreateOverlaySessionDir { .. }
            | Self::WriteOverlayWrapper { .. }
            | Self::SetOverlayWrapperPermissions { .. }
            | Self::StartOstree { .. }
            | Self::OstreeInitFailed { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::CreateStorageDir { source, .. }
            | Self::InspectOverlaySessionPath { source, .. }
            | Self::CreateOverlaySessionDir { source, .. }
            | Self::WriteOverlayWrapper { source, .. }
            | Self::SetOverlayWrapperPermissions { source, .. }
            | Self::StartOstree { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidVolumeId { .. }
            | Self::InvalidVolumePath { .. }
            | Self::UnsupportedOverlayPlatform { .. }
            | Self::MissingOverlayCommand { .. }
            | Self::InvalidOverlaySessionView { .. }
            | Self::OstreeInitFailed { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::FilesystemError;

    #[test]
    fn filesystem_errors_have_status_and_retry_hints() {
        let invalid = FilesystemError::InvalidVolumeId {
            id: String::from("bad/id"),
            reason: String::from("must be a safe path component"),
            location: Location::default(),
        };
        assert_eq!(invalid.status_code(), StatusCode::InvalidArguments);
        assert_eq!(invalid.retry_hint(), RetryHint::NonRetryable);

        let io_error = FilesystemError::CreateStorageDir {
            path: PathBuf::from("/tmp/erebor"),
            source: std::io::Error::from(std::io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);
    }
}
