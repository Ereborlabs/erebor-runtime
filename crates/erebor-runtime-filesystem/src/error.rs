use std::{io, path::PathBuf};

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
    #[snafu(display("filesystem promotion id `{promotion_id}` is invalid: {reason}"))]
    InvalidPromotionId {
        promotion_id: String,
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
    #[snafu(display("failed to {action} filesystem promotion path `{}`: {source}", path.display()))]
    PromotionIo {
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
    #[snafu(display("failed to encode filesystem promotion manifest `{}`: {source}", path.display()))]
    EncodePromotionManifest {
        path: PathBuf,
        source: JsonError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` preimage `{path}` is {size_bytes} bytes, over limit {limit_bytes}"
    ))]
    PromotionPreimageTooLarge {
        volume_id: String,
        path: String,
        size_bytes: u64,
        limit_bytes: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` preimage backend `{backend}` cannot protect `{path}`: {reason}"
    ))]
    PromotionPreimageBackendUnavailable {
        volume_id: String,
        path: String,
        backend: &'static str,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` preimage artifact `{}` for `{path}` is invalid: {reason}",
        artifact.display()
    ))]
    PromotionPreimageArtifactInvalid {
        volume_id: String,
        path: String,
        artifact: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "filesystem volume `{volume_id}` host path `{path}` drifted before promotion: {reason}"
    ))]
    PromotionHostDrift {
        volume_id: String,
        path: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem promotion `{promotion_id}` is incomplete: {reason}"))]
    IncompletePromotion {
        promotion_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem transaction handle `{handle}` is invalid: {reason}"))]
    InvalidTransactionHandle {
        handle: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem transaction name `{name}` is invalid: {reason}"))]
    InvalidTransactionName {
        name: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to {action} filesystem transaction catalog path `{}`: {source}", path.display()))]
    TransactionCatalogIo {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode filesystem transaction catalog `{}`: {source}", path.display()))]
    EncodeTransactionCatalog {
        path: PathBuf,
        source: JsonError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem retention target `{target}` is invalid: {reason}"))]
    InvalidRetentionTarget {
        target: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem retention target `{target}` is protected: {reason}"))]
    ProtectedRetentionTarget {
        target: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to {action} filesystem retention path `{}`: {source}", path.display()))]
    RetentionIo {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode filesystem retention artifact `{}`: {source}", path.display()))]
    EncodeRetention {
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

mod ext;

#[cfg(test)]
#[path = "error/tests.rs"]
mod tests;
