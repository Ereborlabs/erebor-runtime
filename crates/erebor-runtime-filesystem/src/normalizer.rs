use std::fs;

use snafu::ResultExt;

use crate::{
    error::{EncodeLayerManifestSnafu, UnsupportedLayerSnafu, WriteLayerManifestSnafu},
    manifest::FilesystemLayerManifest,
    FilesystemSessionStorage, FilesystemVolumeStorage, Result,
};

mod entry;
mod opaque;
mod proc;

use entry::FilesystemLayerEntryNormalizer;
use proc::ActiveWriterProbe;

#[cfg(test)]
mod tests;

impl FilesystemSessionStorage {
    pub fn ensure_quiescent(&self) -> Result<()> {
        FilesystemSessionQuiescenceProbe::new(self).ensure_no_active_writers()
    }

    pub fn normalize_layers(&self) -> Result<Vec<FilesystemLayerManifest>> {
        FilesystemSessionLayerNormalizer::new(self).normalize()
    }
}

struct FilesystemSessionQuiescenceProbe<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> FilesystemSessionQuiescenceProbe<'a> {
    const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    fn ensure_no_active_writers(&self) -> Result<()> {
        for volume in self.storage.volumes() {
            ActiveWriterProbe::new(volume).ensure_no_active_writers()?;
        }
        Ok(())
    }
}

struct FilesystemSessionLayerNormalizer<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> FilesystemSessionLayerNormalizer<'a> {
    const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    fn normalize(&self) -> Result<Vec<FilesystemLayerManifest>> {
        self.storage
            .volumes()
            .iter()
            .map(|volume| FilesystemVolumeLayerNormalizer::new(volume).normalize())
            .collect()
    }
}

struct FilesystemVolumeLayerNormalizer<'a> {
    volume: &'a FilesystemVolumeStorage,
}

impl<'a> FilesystemVolumeLayerNormalizer<'a> {
    const fn new(volume: &'a FilesystemVolumeStorage) -> Self {
        Self { volume }
    }

    fn normalize(&self) -> Result<FilesystemLayerManifest> {
        ActiveWriterProbe::new(self.volume).ensure_no_active_writers()?;
        let mut manifest = FilesystemLayerManifest::new(
            self.volume.id(),
            self.volume.overlay().upper_path().display().to_string(),
            self.volume.host_path().display().to_string(),
        );
        FilesystemLayerEntryNormalizer::new(self.volume, &mut manifest)
            .walk_directory(self.volume.overlay().upper_path())?;
        manifest
            .operations
            .sort_by(|left, right| left.path().cmp(right.path()));
        manifest.unsupported.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.reason.cmp(&right.reason))
        });
        self.write_manifest(&manifest)?;

        if manifest.promotable {
            Ok(manifest)
        } else {
            UnsupportedLayerSnafu {
                volume_id: self.volume.id().to_owned(),
                reason: manifest
                    .unsupported
                    .iter()
                    .map(|entry| format!("{}: {}", entry.path, entry.reason))
                    .collect::<Vec<_>>()
                    .join("; "),
            }
            .fail()
        }
    }

    fn write_manifest(&self, manifest: &FilesystemLayerManifest) -> Result<()> {
        let path = self.volume.layer_manifest_path();
        let source = serde_json::to_vec_pretty(manifest)
            .context(EncodeLayerManifestSnafu { path: &path })?;
        fs::write(&path, source).context(WriteLayerManifestSnafu { path })
    }
}
