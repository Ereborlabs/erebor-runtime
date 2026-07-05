use crate::{error::UnsupportedLayerSnafu, FilesystemLayerManifest, Result};

pub(super) fn ensure_layer_promotable(manifest: &FilesystemLayerManifest) -> Result<()> {
    if !manifest.promotable {
        return UnsupportedLayerSnafu {
            volume_id: manifest.volume_id.clone(),
            reason: manifest
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
