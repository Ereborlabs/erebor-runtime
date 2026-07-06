//! Filesystem surface domain contracts.

mod checkpoint;
mod config;
mod error;
mod linux_overlay_session;
mod manifest;
mod metadata;
mod normalizer;
mod ostree;
mod overlay;
mod promotion;
mod session_work;
mod storage;

pub use checkpoint::{
    FilesystemCheckpointCommit, FilesystemCheckpointManifest, FilesystemCheckpointVolume,
    CHECKPOINT_MANIFEST_FILE, CHECKPOINT_MANIFEST_KIND,
};
pub use config::{
    FilesystemBackendKind, FilesystemPreimageBackendKind, FilesystemSessionWorkAutocommitBoundary,
    FilesystemVolumeMode,
};
pub use error::{FilesystemError, Result};
pub use linux_overlay_session::LinuxOverlaySessionView;
pub use manifest::{
    FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerMetadata,
    FilesystemLayerMetadataSidecar, FilesystemLayerOperation, FilesystemLayerUnsupported,
    FilesystemOpaqueMarker, FilesystemXattr, LAYER_MANIFEST_FILE, LAYER_MANIFEST_KIND,
};
pub use promotion::{
    FilesystemDirectoryPreimageFile, FilesystemHostMetadata, FilesystemOstreePrune,
    FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
    FilesystemPreimageManifest, FilesystemPromotion, FilesystemPromotionManifest,
    FilesystemPromotionOptions, FilesystemPromotionState, FilesystemPromotionVolume,
    FilesystemRegularPreimage, FilesystemRetainedArtifactStatus, FilesystemRetainedLocalArtifact,
    FilesystemRetainedLocalKind, FilesystemRetainedRef, FilesystemRetainedRefKind,
    FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemRetentionState,
    FilesystemRetentionSubtransaction, FilesystemRetentionTransaction, FilesystemRollback,
    FilesystemSubtransaction, FilesystemSubtransactionState, FilesystemTransaction,
    FilesystemTransactionCatalog, FilesystemTransactionChange, FilesystemTransactionRename,
    FilesystemTransactionRollback, FilesystemTransactionState, FilesystemTransactionTarget,
    PREIMAGE_MANIFEST_FILE, PREIMAGE_MANIFEST_KIND, PROMOTION_MANIFEST_FILE,
    PROMOTION_MANIFEST_KIND,
};
pub use session_work::{
    FilesystemSessionWorkCatalog, FilesystemSessionWorkChange, FilesystemSessionWorkCommit,
    FilesystemSessionWorkCommitRequest, FilesystemSessionWorkCommitSource,
    FilesystemSessionWorkCommitter, FilesystemSessionWorkManifest, FilesystemSessionWorkRename,
    FilesystemSessionWorkRollback, FilesystemSessionWorkSubtransaction,
    FilesystemSessionWorkTarget, FilesystemSessionWorkTransaction,
    FilesystemSessionWorkTransactionState, FilesystemSessionWorkVolume, SESSION_WORK_MANIFEST_FILE,
    SESSION_WORK_MANIFEST_KIND,
};
pub use storage::{
    FilesystemOverlayStorage, FilesystemSessionStorage, FilesystemVolumeStorage,
    FilesystemVolumeStorageRequest,
};
