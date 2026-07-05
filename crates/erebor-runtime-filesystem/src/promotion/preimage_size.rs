use snafu::ensure;

use crate::{error::PromotionPreimageTooLargeSnafu, FilesystemVolumeStorage, Result};

use super::manifest::FilesystemPreimageManifest;

pub(super) fn add_bytes(
    volume: &FilesystemVolumeStorage,
    path: &str,
    bytes: u64,
    limit_bytes: u64,
    manifest: &mut FilesystemPreimageManifest,
) -> Result<()> {
    let next = manifest.total_bytes.saturating_add(bytes);
    ensure!(
        next <= limit_bytes,
        PromotionPreimageTooLargeSnafu {
            volume_id: volume.id().to_owned(),
            path: path.to_owned(),
            size_bytes: next,
            limit_bytes
        }
    );
    manifest.total_bytes = next;
    Ok(())
}
