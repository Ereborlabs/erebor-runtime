use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use serde_json::Error as JsonError;
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
    #[snafu(display("failed to read filesystem layer path `{}`: {source}", path.display()))]
    ReadLayerPath {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to inspect filesystem layer path `{}`: {source}", path.display()))]
    InspectLayerPath {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` cannot normalize layer while pid {pid} fd {fd} has a writer open under `{}`",
        path.display()
    ))]
    ActiveLayerWriter {
        volume_id: String,
        path: PathBuf,
        pid: u32,
        fd: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem volume `{volume_id}` layer is not promotable: {reason}"))]
    UnsupportedLayer {
        volume_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write filesystem layer manifest `{}`: {source}", path.display()))]
    WriteLayerManifest {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode filesystem layer manifest `{}`: {source}", path.display()))]
    EncodeLayerManifest {
        path: PathBuf,
        source: JsonError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem checkpoint id `{checkpoint_id}` is invalid: {reason}"))]
    InvalidCheckpointId {
        checkpoint_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to {action} filesystem checkpoint path `{}`: {source}", path.display()))]
    CheckpointIo {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode filesystem checkpoint manifest `{}`: {source}", path.display()))]
    EncodeCheckpointManifest {
        path: PathBuf,
        source: JsonError,
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
    #[snafu(display(
        "ostree {operation} failed for repo `{}` with exit code {:?}: {}",
        repo.display(),
        code,
        stderr
    ))]
    OstreeCommandFailed {
        repo: PathBuf,
        operation: &'static str,
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
            | Self::InvalidOverlaySessionView { .. }
            | Self::InvalidCheckpointId { .. } => StatusCode::InvalidArguments,
            Self::CreateStorageDir { .. }
            | Self::InspectOverlaySessionPath { .. }
            | Self::CreateOverlaySessionDir { .. }
            | Self::WriteOverlayWrapper { .. }
            | Self::SetOverlayWrapperPermissions { .. }
            | Self::ReadLayerPath { .. }
            | Self::InspectLayerPath { .. }
            | Self::ActiveLayerWriter { .. }
            | Self::WriteLayerManifest { .. }
            | Self::EncodeLayerManifest { .. }
            | Self::CheckpointIo { .. }
            | Self::EncodeCheckpointManifest { .. }
            | Self::StartOstree { .. }
            | Self::OstreeInitFailed { .. }
            | Self::OstreeCommandFailed { .. } => StatusCode::External,
            Self::UnsupportedLayer { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::CreateStorageDir { source, .. }
            | Self::InspectOverlaySessionPath { source, .. }
            | Self::CreateOverlaySessionDir { source, .. }
            | Self::WriteOverlayWrapper { source, .. }
            | Self::SetOverlayWrapperPermissions { source, .. }
            | Self::ReadLayerPath { source, .. }
            | Self::InspectLayerPath { source, .. }
            | Self::WriteLayerManifest { source, .. }
            | Self::CheckpointIo { source, .. }
            | Self::StartOstree { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidVolumeId { .. }
            | Self::InvalidVolumePath { .. }
            | Self::UnsupportedOverlayPlatform { .. }
            | Self::MissingOverlayCommand { .. }
            | Self::InvalidOverlaySessionView { .. }
            | Self::InvalidCheckpointId { .. }
            | Self::ActiveLayerWriter { .. }
            | Self::UnsupportedLayer { .. }
            | Self::EncodeLayerManifest { .. }
            | Self::EncodeCheckpointManifest { .. }
            | Self::OstreeInitFailed { .. }
            | Self::OstreeCommandFailed { .. } => RetryHint::NonRetryable,
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
