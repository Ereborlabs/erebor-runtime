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
    metadata, overlay, FilesystemVolumeStorage, Result,
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
            FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                stage_opaque_replace(stage_root, volume, path)?;
            }
            FilesystemLayerOperation::Delete { .. } => {}
        }
    }
    apply_directory_metadata(stage_root, manifest)?;
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
        FilesystemLayerEntry::Regular { source, metadata } => {
            copy_regular(volume, source, &target)?;
            metadata::apply_layer_metadata(&target, metadata)?;
        }
        FilesystemLayerEntry::Symlink {
            target: source,
            metadata,
        } => {
            write_symlink(source, &target)?;
            metadata::apply_layer_metadata(&target, metadata)?;
        }
    }
    Ok(())
}

fn apply_directory_metadata(stage_root: &Path, manifest: &FilesystemLayerManifest) -> Result<()> {
    for operation in manifest.operations.iter().rev() {
        let Some((path, metadata)) = directory_metadata(operation) else {
            continue;
        };
        let target = stage_root.join(FILES_DIR).join(safe_relative(path)?);
        metadata::apply_layer_metadata(&target, metadata)?;
    }
    Ok(())
}

fn directory_metadata(
    operation: &FilesystemLayerOperation,
) -> Option<(&str, &crate::FilesystemLayerMetadata)> {
    match operation {
        FilesystemLayerOperation::Create {
            path,
            entry: FilesystemLayerEntry::Directory { metadata },
        }
        | FilesystemLayerOperation::Replace {
            path,
            entry: FilesystemLayerEntry::Directory { metadata },
        }
        | FilesystemLayerOperation::OpaqueReplace {
            path,
            entry: FilesystemLayerEntry::Directory { metadata },
            ..
        } => Some((path, metadata)),
        _ => None,
    }
}

fn stage_opaque_replace(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    path: &str,
) -> Result<()> {
    let relative = safe_relative(path)?;
    let source = volume.overlay().upper_path().join(&relative);
    let target = stage_root.join(FILES_DIR).join(relative);
    stage_visible_tree(&source, &target)
}

fn stage_visible_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target).context(CheckpointIoSnafu {
        action: "create checkpoint opaque directory",
        path: target,
    })?;
    for entry in fs::read_dir(source).context(CheckpointIoSnafu {
        action: "read checkpoint opaque directory",
        path: source,
    })? {
        let entry = entry.context(CheckpointIoSnafu {
            action: "read checkpoint opaque directory entry",
            path: source,
        })?;
        let source_path = entry.path();
        let file_metadata = fs::symlink_metadata(&source_path).context(CheckpointIoSnafu {
            action: "inspect checkpoint opaque entry",
            path: source_path.as_path(),
        })?;
        if overlay::is_whiteout_entry(&source_path, &file_metadata)? {
            continue;
        }
        let target_path = target.join(entry.file_name());
        if file_metadata.is_dir() {
            stage_visible_tree(&source_path, &target_path)?;
        } else if file_metadata.is_file() {
            fs::copy(&source_path, &target_path).context(CheckpointIoSnafu {
                action: "copy checkpoint opaque regular entry",
                path: source_path.as_path(),
            })?;
            apply_source_metadata(&source_path, &target_path, &file_metadata)?;
        } else if file_metadata.file_type().is_symlink() {
            let link = fs::read_link(&source_path).context(CheckpointIoSnafu {
                action: "read checkpoint opaque symlink entry",
                path: source_path.as_path(),
            })?;
            symlink(link, &target_path).context(CheckpointIoSnafu {
                action: "copy checkpoint opaque symlink entry",
                path: target_path.as_path(),
            })?;
            apply_source_metadata(&source_path, &target_path, &file_metadata)?;
        } else {
            return UnsupportedLayerSnafu {
                volume_id: String::from("<checkpoint>"),
                reason: format!(
                    "opaque replacement `{}` contains a special file",
                    source.display()
                ),
            }
            .fail();
        }
    }
    let directory_metadata = fs::symlink_metadata(source).context(CheckpointIoSnafu {
        action: "inspect checkpoint opaque directory metadata",
        path: source,
    })?;
    apply_source_metadata(source, target, &directory_metadata)
}

fn apply_source_metadata(source: &Path, target: &Path, metadata: &fs::Metadata) -> Result<()> {
    let metadata = metadata::layer_metadata(source, metadata)?;
    metadata::apply_layer_metadata(target, &metadata)
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
