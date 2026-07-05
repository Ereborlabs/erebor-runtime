//! Filesystem surface domain contracts.

mod config;
mod error;
mod linux_overlay_session;
mod manifest;
mod normalizer;
mod storage;

pub use config::{FilesystemBackendKind, FilesystemVolumeMode};
pub use error::{FilesystemError, Result};
pub use linux_overlay_session::LinuxOverlaySessionView;
pub use manifest::{
    FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerMetadata,
    FilesystemLayerMetadataSidecar, FilesystemLayerOperation, FilesystemLayerUnsupported,
    LAYER_MANIFEST_FILE, LAYER_MANIFEST_KIND,
};
pub use normalizer::normalize_session_layers;
pub use storage::{
    FilesystemOverlayStorage, FilesystemSessionStorage, FilesystemVolumeStorage,
    FilesystemVolumeStorageRequest,
};
