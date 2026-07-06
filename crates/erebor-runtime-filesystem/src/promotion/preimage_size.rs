use snafu::ensure;

use crate::{error::PromotionPreimageTooLargeSnafu, FilesystemVolumeStorage, Result};

use super::manifest::FilesystemPreimageManifest;

pub(super) struct PreimageSizeBudget<'a> {
    volume: &'a FilesystemVolumeStorage,
    limit_bytes: u64,
}

impl<'a> PreimageSizeBudget<'a> {
    pub(super) const fn new(volume: &'a FilesystemVolumeStorage, limit_bytes: u64) -> Self {
        Self {
            volume,
            limit_bytes,
        }
    }

    pub(super) fn add_bytes(
        &self,
        path: &str,
        bytes: u64,
        manifest: &mut FilesystemPreimageManifest,
    ) -> Result<()> {
        let next = manifest.total_bytes.saturating_add(bytes);
        ensure!(
            next <= self.limit_bytes,
            PromotionPreimageTooLargeSnafu {
                volume_id: self.volume.id().to_owned(),
                path: path.to_owned(),
                size_bytes: next,
                limit_bytes: self.limit_bytes
            }
        );
        manifest.total_bytes = next;
        Ok(())
    }
}
