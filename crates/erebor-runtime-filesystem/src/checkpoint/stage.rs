use std::{
    fs,
    os::unix::fs::symlink,
    path::{Component, Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{CheckpointIoSnafu, EncodeLayerManifestSnafu, UnsupportedLayerSnafu},
    manifest::{
        FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerOperation,
        LAYER_MANIFEST_FILE,
    },
    FilesystemVolumeStorage, Result,
};

const FILES_DIR: &str = "files";

pub(super) fn stage_volume_layer(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    manifest: &FilesystemLayerManifest,
) -> Result<()> {
    reset_stage(stage_root)?;
    write_layer_manifest(stage_root, manifest)?;

    for operation in &manifest.operations {
        match operation {
            FilesystemLayerOperation::Create { path, entry }
            | FilesystemLayerOperation::Replace { path, entry } => {
                stage_entry(stage_root, volume, path, entry)?;
            }
            FilesystemLayerOperation::Delete { .. } => {}
        }
    }
    Ok(())
}

fn reset_stage(stage_root: &Path) -> Result<()> {
    if stage_root.exists() {
        fs::remove_dir_all(stage_root).context(CheckpointIoSnafu {
            action: "remove checkpoint stage",
            path: stage_root,
        })?;
    }
    fs::create_dir_all(stage_root.join(FILES_DIR)).context(CheckpointIoSnafu {
        action: "create checkpoint stage",
        path: stage_root,
    })
}

fn write_layer_manifest(stage_root: &Path, manifest: &FilesystemLayerManifest) -> Result<()> {
    let path = stage_root.join(LAYER_MANIFEST_FILE);
    let source = serde_json::to_vec_pretty(manifest).context(EncodeLayerManifestSnafu {
        path: path.as_path(),
    })?;
    fs::write(&path, source).context(CheckpointIoSnafu {
        action: "write checkpoint layer manifest",
        path: path.as_path(),
    })
}

fn stage_entry(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    path: &str,
    entry: &FilesystemLayerEntry,
) -> Result<()> {
    let target = stage_root.join(FILES_DIR).join(safe_relative(path)?);
    match entry {
        FilesystemLayerEntry::Directory { .. } => {
            fs::create_dir_all(&target).context(CheckpointIoSnafu {
                action: "create checkpoint directory entry",
                path: target.as_path(),
            })?;
        }
        FilesystemLayerEntry::Regular { source, .. } => {
            copy_regular(volume, source, &target)?;
        }
        FilesystemLayerEntry::Symlink { target: source, .. } => {
            write_symlink(source, &target)?;
        }
    }
    Ok(())
}

fn copy_regular(volume: &FilesystemVolumeStorage, source: &str, target: &Path) -> Result<()> {
    let source = volume.overlay().upper_path().join(safe_relative(source)?);
    create_parent(target)?;
    fs::copy(&source, target).context(CheckpointIoSnafu {
        action: "copy checkpoint regular entry",
        path: target,
    })?;
    Ok(())
}

fn write_symlink(source: &str, target: &Path) -> Result<()> {
    create_parent(target)?;
    symlink(source, target).context(CheckpointIoSnafu {
        action: "create checkpoint symlink entry",
        path: target,
    })
}

fn create_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(CheckpointIoSnafu {
            action: "create checkpoint parent directory",
            path: parent,
        })?;
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() {
        return invalid_layer_path(value);
    }
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return invalid_layer_path(value),
        }
    }
    Ok(relative)
}

fn invalid_layer_path(value: &str) -> Result<PathBuf> {
    UnsupportedLayerSnafu {
        volume_id: String::from("<checkpoint>"),
        reason: format!("checkpoint layer path `{value}` is not a safe relative path"),
    }
    .fail()
}
