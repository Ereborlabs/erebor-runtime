//! Filesystem surface domain contracts.

mod config;
mod error;
mod linux_overlay_session;
mod storage;

pub use config::{FilesystemBackendKind, FilesystemVolumeMode};
pub use error::{FilesystemError, Result};
pub use linux_overlay_session::LinuxOverlaySessionView;
pub use storage::{
    FilesystemOverlayStorage, FilesystemSessionStorage, FilesystemVolumeStorage,
    FilesystemVolumeStorageRequest,
};
