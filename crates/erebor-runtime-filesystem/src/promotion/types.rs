use std::path::{Path, PathBuf};

use crate::FilesystemPreimageBackendKind;

use super::manifest::FilesystemPromotionVolume;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemPromotionOptions {
    preimage_size_limit_bytes: u64,
    preimage_backend: FilesystemPreimageBackendKind,
}

impl FilesystemPromotionOptions {
    #[must_use]
    pub const fn new(preimage_size_limit_bytes: u64) -> Self {
        Self::from_parts(
            preimage_size_limit_bytes,
            FilesystemPreimageBackendKind::OstreeBytes,
        )
    }

    #[must_use]
    pub const fn from_parts(
        preimage_size_limit_bytes: u64,
        preimage_backend: FilesystemPreimageBackendKind,
    ) -> Self {
        Self {
            preimage_size_limit_bytes,
            preimage_backend,
        }
    }

    #[must_use]
    pub const fn preimage_size_limit_bytes(self) -> u64 {
        self.preimage_size_limit_bytes
    }

    #[must_use]
    pub const fn preimage_backend(self) -> FilesystemPreimageBackendKind {
        self.preimage_backend
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemPromotion {
    promotion_id: String,
    manifest_path: PathBuf,
    volumes: Vec<FilesystemPromotionVolume>,
}

impl FilesystemPromotion {
    pub(super) fn new(
        promotion_id: impl Into<String>,
        manifest_path: PathBuf,
        volumes: Vec<FilesystemPromotionVolume>,
    ) -> Self {
        Self {
            promotion_id: promotion_id.into(),
            manifest_path,
            volumes,
        }
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    #[must_use]
    pub fn volumes(&self) -> &[FilesystemPromotionVolume] {
        &self.volumes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemRollback {
    promotion_id: String,
    restored_volumes: Vec<String>,
}

impl FilesystemRollback {
    pub(super) fn new(promotion_id: impl Into<String>, restored_volumes: Vec<String>) -> Self {
        Self {
            promotion_id: promotion_id.into(),
            restored_volumes,
        }
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn restored_volumes(&self) -> &[String] {
        &self.restored_volumes
    }
}
