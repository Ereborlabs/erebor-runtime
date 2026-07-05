use std::{fs, os::unix::fs::symlink, path::Path};

use snafu::{ensure, ResultExt};

use crate::{
    error::{PromotionHostDriftSnafu, PromotionIoSnafu, PromotionPreimageTooLargeSnafu},
    manifest::FilesystemLayerOperation,
    metadata, FilesystemLayerManifest, FilesystemVolumeStorage, Result,
};

use super::{
    manifest::{
        FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
        FilesystemPreimageManifest,
    },
    path::{create_parent, safe_relative},
};

const FILES_DIR: &str = "files";

pub(super) fn capture_volume_preimage(
    stage_root: &Path,
    promotion_id: &str,
    volume: &FilesystemVolumeStorage,
    layer: &FilesystemLayerManifest,
    limit_bytes: u64,
) -> Result<FilesystemPreimageManifest> {
    reset_stage(stage_root)?;
    let mut manifest = FilesystemPreimageManifest::new(
        promotion_id,
        volume.id(),
        volume.host_path().display().to_string(),
    );
    for operation in &layer.operations {
        let path = operation_path(operation);
        match operation {
            FilesystemLayerOperation::Create { .. } => {
                capture_absent(volume, path, &mut manifest)?;
            }
            FilesystemLayerOperation::Replace { .. } | FilesystemLayerOperation::Delete { .. } => {
                capture_present(stage_root, volume, path, limit_bytes, &mut manifest)?;
            }
        }
    }
    Ok(manifest)
}

pub(super) fn verify_preimage_matches_host(
    volume: &FilesystemVolumeStorage,
    manifest: &FilesystemPreimageManifest,
) -> Result<()> {
    for entry in &manifest.entries {
        let host_path = volume
            .host_path()
            .join(safe_relative(volume.id(), &entry.path)?);
        match &entry.state {
            FilesystemPreimageEntryState::Absent => match fs::symlink_metadata(&host_path) {
                Ok(_) => PromotionHostDriftSnafu {
                    volume_id: volume.id().to_owned(),
                    path: entry.path.clone(),
                    reason: String::from("expected path to remain absent"),
                }
                .fail()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(source).context(PromotionIoSnafu {
                        action: "inspect absent host preimage path for drift",
                        path: host_path.as_path(),
                    });
                }
            },
            FilesystemPreimageEntryState::Present { .. } => {
                let current = fs::symlink_metadata(&host_path).context(PromotionIoSnafu {
                    action: "inspect host preimage path for drift",
                    path: host_path.as_path(),
                })?;
                let Some(expected) = &entry.metadata else {
                    continue;
                };
                let current = metadata::host_metadata(&host_path, &current)?;
                ensure!(
                    current == *expected,
                    PromotionHostDriftSnafu {
                        volume_id: volume.id().to_owned(),
                        path: entry.path.clone(),
                        reason: String::from("metadata no longer matches captured preimage")
                    }
                );
            }
        }
    }
    Ok(())
}

fn reset_stage(stage_root: &Path) -> Result<()> {
    if stage_root.exists() {
        fs::remove_dir_all(stage_root).context(PromotionIoSnafu {
            action: "remove promotion preimage stage",
            path: stage_root,
        })?;
    }
    fs::create_dir_all(stage_root.join(FILES_DIR)).context(PromotionIoSnafu {
        action: "create promotion preimage stage",
        path: stage_root,
    })
}

fn capture_absent(
    volume: &FilesystemVolumeStorage,
    path: &str,
    manifest: &mut FilesystemPreimageManifest,
) -> Result<()> {
    let host_path = volume.host_path().join(safe_relative(volume.id(), path)?);
    match fs::symlink_metadata(&host_path) {
        Ok(_) => {
            return PromotionHostDriftSnafu {
                volume_id: volume.id().to_owned(),
                path: path.to_owned(),
                reason: String::from("layer expected a create but host path exists"),
            }
            .fail();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(source).context(PromotionIoSnafu {
                action: "inspect absent host preimage path",
                path: host_path.as_path(),
            });
        }
    }
    manifest.entries.push(FilesystemPreimageEntry {
        path: path.to_owned(),
        state: FilesystemPreimageEntryState::Absent,
        metadata: None,
    });
    Ok(())
}

fn capture_present(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    path: &str,
    limit_bytes: u64,
    manifest: &mut FilesystemPreimageManifest,
) -> Result<()> {
    let relative = safe_relative(volume.id(), path)?;
    let host_path = volume.host_path().join(&relative);
    let metadata = fs::symlink_metadata(&host_path).context(PromotionIoSnafu {
        action: "inspect host preimage path",
        path: host_path.as_path(),
    })?;
    let target = stage_root.join(FILES_DIR).join(&relative);
    let entry_type = if metadata.is_dir() {
        copy_directory(&host_path, &target, volume, path, limit_bytes, manifest)?
    } else if metadata.is_file() {
        add_bytes(volume, path, metadata.len(), limit_bytes, manifest)?;
        create_parent(&target)?;
        fs::copy(&host_path, &target).context(PromotionIoSnafu {
            action: "copy promotion regular preimage",
            path: host_path.as_path(),
        })?;
        metadata::copy_path_metadata(&host_path, &target)?;
        FilesystemPreimageEntryType::Regular {
            source: path.to_owned(),
        }
    } else if metadata.file_type().is_symlink() {
        create_parent(&target)?;
        let target_path = fs::read_link(&host_path).context(PromotionIoSnafu {
            action: "read promotion symlink preimage",
            path: host_path.as_path(),
        })?;
        symlink(&target_path, &target).context(PromotionIoSnafu {
            action: "copy promotion symlink preimage",
            path: target.as_path(),
        })?;
        metadata::copy_path_metadata(&host_path, &target)?;
        FilesystemPreimageEntryType::Symlink {
            target: target_path.display().to_string(),
        }
    } else {
        return crate::error::UnsupportedLayerSnafu {
            volume_id: volume.id().to_owned(),
            reason: format!("preimage path `{path}` is an unsupported special file"),
        }
        .fail();
    };
    manifest.entries.push(FilesystemPreimageEntry {
        path: path.to_owned(),
        state: FilesystemPreimageEntryState::Present { entry_type },
        metadata: Some(metadata::host_metadata(&host_path, &metadata)?),
    });
    Ok(())
}

fn copy_directory(
    source: &Path,
    target: &Path,
    volume: &FilesystemVolumeStorage,
    manifest_path: &str,
    limit_bytes: u64,
    manifest: &mut FilesystemPreimageManifest,
) -> Result<FilesystemPreimageEntryType> {
    fs::create_dir_all(target).context(PromotionIoSnafu {
        action: "create promotion directory preimage",
        path: target,
    })?;
    for entry in fs::read_dir(source).context(PromotionIoSnafu {
        action: "read promotion directory preimage",
        path: source,
    })? {
        let entry = entry.context(PromotionIoSnafu {
            action: "read promotion directory preimage entry",
            path: source,
        })?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).context(PromotionIoSnafu {
            action: "inspect promotion directory preimage entry",
            path: source_path.as_path(),
        })?;
        if metadata.is_dir() {
            copy_directory(
                &source_path,
                &target_path,
                volume,
                manifest_path,
                limit_bytes,
                manifest,
            )?;
        } else if metadata.is_file() {
            add_bytes(volume, manifest_path, metadata.len(), limit_bytes, manifest)?;
            fs::copy(&source_path, &target_path).context(PromotionIoSnafu {
                action: "copy promotion directory file preimage",
                path: source_path.as_path(),
            })?;
            crate::metadata::copy_path_metadata(&source_path, &target_path)?;
        } else if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(&source_path).context(PromotionIoSnafu {
                action: "read promotion directory symlink preimage",
                path: source_path.as_path(),
            })?;
            symlink(link_target, &target_path).context(PromotionIoSnafu {
                action: "copy promotion directory symlink preimage",
                path: target_path.as_path(),
            })?;
            crate::metadata::copy_path_metadata(&source_path, &target_path)?;
        } else {
            return crate::error::UnsupportedLayerSnafu {
                volume_id: volume.id().to_owned(),
                reason: format!("preimage directory `{manifest_path}` contains a special file"),
            }
            .fail();
        }
    }
    crate::metadata::copy_path_metadata(source, target)?;
    Ok(FilesystemPreimageEntryType::Directory)
}

fn add_bytes(
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

fn operation_path(operation: &FilesystemLayerOperation) -> &str {
    match operation {
        FilesystemLayerOperation::Create { path, .. }
        | FilesystemLayerOperation::Replace { path, .. }
        | FilesystemLayerOperation::Delete { path } => path,
    }
}
