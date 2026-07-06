use crate::{error::UnsupportedLayerSnafu, FilesystemLayerManifest, Result};

pub(super) struct PromotionLayerGuard<'a> {
    manifest: &'a FilesystemLayerManifest,
}

impl<'a> PromotionLayerGuard<'a> {
    pub(super) const fn new(manifest: &'a FilesystemLayerManifest) -> Self {
        Self { manifest }
    }

    pub(super) fn ensure_promotable(&self) -> Result<()> {
        if !self.manifest.promotable {
            return UnsupportedLayerSnafu {
                volume_id: self.manifest.volume_id.clone(),
                reason: self
                    .manifest
                    .unsupported
                    .iter()
                    .map(|entry| format!("{}: {}", entry.path, entry.reason))
                    .collect::<Vec<_>>()
                    .join("; "),
            }
            .fail();
        }

        Ok(())
    }
}
