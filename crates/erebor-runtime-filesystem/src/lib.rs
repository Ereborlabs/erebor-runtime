//! Filesystem surface domain contracts.

mod config;
mod error;
mod storage;

pub use config::{FilesystemBackendKind, FilesystemVolumeMode};
pub use error::{FilesystemError, Result};
pub use storage::{
    FilesystemOverlayStorage, FilesystemSessionStorage, FilesystemVolumeStorage,
    FilesystemVolumeStorageRequest,
};
