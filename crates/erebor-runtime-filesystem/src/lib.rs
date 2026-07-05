//! Filesystem surface domain contracts.

mod checkpoint;
mod config;
mod error;
mod linux_overlay_session;
mod manifest;
mod normalizer;
mod ostree;
mod promotion;
mod storage;

pub use checkpoint::{
    checkpoint_manifest_ref, commit_session_checkpoint, volume_layer_ref,
    FilesystemCheckpointCommit, FilesystemCheckpointManifest, FilesystemCheckpointVolume,
    CHECKPOINT_MANIFEST_FILE, CHECKPOINT_MANIFEST_KIND,
};
pub use config::{FilesystemBackendKind, FilesystemVolumeMode};
pub use error::{FilesystemError, Result};
pub use linux_overlay_session::LinuxOverlaySessionView;
pub use manifest::{
    FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerMetadata,
    FilesystemLayerMetadataSidecar, FilesystemLayerOperation, FilesystemLayerUnsupported,
    LAYER_MANIFEST_FILE, LAYER_MANIFEST_KIND,
};
pub use normalizer::normalize_session_layers;
pub use promotion::{
    promote_session_checkpoint, promotion_manifest_ref, promotion_preimage_ref, rollback_promotion,
    FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
    FilesystemPreimageManifest, FilesystemPromotion, FilesystemPromotionManifest,
    FilesystemPromotionOptions, FilesystemPromotionState, FilesystemPromotionVolume,
    FilesystemRollback, PREIMAGE_MANIFEST_FILE, PREIMAGE_MANIFEST_KIND, PROMOTION_MANIFEST_FILE,
    PROMOTION_MANIFEST_KIND,
};
pub use storage::{
    FilesystemOverlayStorage, FilesystemSessionStorage, FilesystemVolumeStorage,
    FilesystemVolumeStorageRequest,
};
