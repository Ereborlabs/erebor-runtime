use std::{fs, path::Path};

use snafu::ResultExt;

use crate::{
    error::{
        EncodeLayerManifestSnafu, InspectLayerPathSnafu, ReadLayerPathSnafu, UnsupportedLayerSnafu,
        WriteLayerManifestSnafu,
    },
    manifest::FilesystemLayerManifest,
    FilesystemSessionStorage, FilesystemVolumeStorage, Result,
};

mod entry;
mod opaque;
mod proc;

use entry::normalize_entry;

#[cfg(test)]
mod tests;

pub fn normalize_session_layers(
    storage: &FilesystemSessionStorage,
) -> Result<Vec<FilesystemLayerManifest>> {
    storage
        .volumes()
        .iter()
        .map(normalize_volume_layer)
        .collect()
}

fn normalize_volume_layer(volume: &FilesystemVolumeStorage) -> Result<FilesystemLayerManifest> {
    proc::ensure_no_active_writers(volume)?;
    let mut manifest = FilesystemLayerManifest::new(
        volume.id(),
        volume.overlay().upper_path().display().to_string(),
        volume.host_path().display().to_string(),
    );
    walk_upperdir(volume, volume.overlay().upper_path(), &mut manifest)?;
    manifest
        .operations
        .sort_by(|left, right| left.path().cmp(right.path()));
    manifest.unsupported.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.reason.cmp(&right.reason))
    });
    write_manifest(volume, &manifest)?;

    if manifest.promotable {
        Ok(manifest)
    } else {
        UnsupportedLayerSnafu {
            volume_id: volume.id().to_owned(),
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

fn walk_upperdir(
    volume: &FilesystemVolumeStorage,
    directory: &Path,
    manifest: &mut FilesystemLayerManifest,
) -> Result<()> {
    let entries = fs::read_dir(directory).context(ReadLayerPathSnafu { path: directory })?;
    for entry in entries {
        let entry = entry.context(ReadLayerPathSnafu { path: directory })?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).context(InspectLayerPathSnafu { path: &path })?;
        normalize_entry(volume, &path, &metadata, manifest)?;
    }
    Ok(())
}

fn write_manifest(
    volume: &FilesystemVolumeStorage,
    manifest: &FilesystemLayerManifest,
) -> Result<()> {
    let path = volume.layer_manifest_path();
    let source =
        serde_json::to_vec_pretty(manifest).context(EncodeLayerManifestSnafu { path: &path })?;
    fs::write(&path, source).context(WriteLayerManifestSnafu { path })
}
