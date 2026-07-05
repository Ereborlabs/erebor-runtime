use std::{fs, os::unix::fs::symlink, path::Path};

use snafu::ResultExt;

use crate::{
    error::PromotionIoSnafu,
    manifest::{FilesystemLayerEntry, FilesystemLayerOperation},
    FilesystemLayerManifest, FilesystemVolumeStorage, Result,
};

use super::{
    journal::{PromotionJournal, PromotionJournalState},
    manifest::{
        FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
        FilesystemPreimageManifest,
    },
    path::{create_parent, remove_path, safe_relative},
};

const FILES_DIR: &str = "files";

pub(super) fn apply_volume_layer(
    journal_root: &Path,
    volume: &FilesystemVolumeStorage,
    layer: &FilesystemLayerManifest,
    journal: &mut PromotionJournal,
) -> Result<()> {
    journal.state = PromotionJournalState::Applying;
    journal.write(journal_root)?;
    for operation in &layer.operations {
        apply_operation(volume, operation)?;
        journal
            .applied_operations
            .push(format!("{}:{}", volume.id(), operation_path(operation)));
        journal.write(journal_root)?;
    }
    Ok(())
}

pub(super) fn rollback_volume(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    manifest: &FilesystemPreimageManifest,
) -> Result<()> {
    for entry in manifest.entries.iter().rev() {
        rollback_entry(stage_root, volume, entry)?;
    }
    Ok(())
}

fn apply_operation(
    volume: &FilesystemVolumeStorage,
    operation: &FilesystemLayerOperation,
) -> Result<()> {
    match operation {
        FilesystemLayerOperation::Create { path, entry } => write_layer_entry(volume, path, entry),
        FilesystemLayerOperation::Replace { path, entry } => {
            let host_path = volume.host_path().join(safe_relative(volume.id(), path)?);
            remove_path(&host_path)?;
            write_layer_entry(volume, path, entry)
        }
        FilesystemLayerOperation::Delete { path } => {
            let host_path = volume.host_path().join(safe_relative(volume.id(), path)?);
            remove_path(&host_path)
        }
    }
}

fn write_layer_entry(
    volume: &FilesystemVolumeStorage,
    path: &str,
    entry: &FilesystemLayerEntry,
) -> Result<()> {
    let host_path = volume.host_path().join(safe_relative(volume.id(), path)?);
    match entry {
        FilesystemLayerEntry::Directory { .. } => {
            fs::create_dir_all(&host_path).context(PromotionIoSnafu {
                action: "create promotion directory",
                path: host_path.as_path(),
            })?;
        }
        FilesystemLayerEntry::Regular { source, .. } => {
            let upper = volume
                .overlay()
                .upper_path()
                .join(safe_relative(volume.id(), source)?);
            create_parent(&host_path)?;
            fs::copy(&upper, &host_path).context(PromotionIoSnafu {
                action: "copy promotion regular file",
                path: upper.as_path(),
            })?;
        }
        FilesystemLayerEntry::Symlink { target, .. } => {
            create_parent(&host_path)?;
            symlink(target, &host_path).context(PromotionIoSnafu {
                action: "create promotion symlink",
                path: host_path.as_path(),
            })?;
        }
    }
    Ok(())
}

fn rollback_entry(
    stage_root: &Path,
    volume: &FilesystemVolumeStorage,
    entry: &FilesystemPreimageEntry,
) -> Result<()> {
    let relative = safe_relative(volume.id(), &entry.path)?;
    let host_path = volume.host_path().join(&relative);
    match &entry.state {
        FilesystemPreimageEntryState::Absent => remove_path(&host_path),
        FilesystemPreimageEntryState::Present { entry_type } => {
            remove_path(&host_path)?;
            match entry_type {
                FilesystemPreimageEntryType::Directory => {
                    copy_directory(&stage_root.join(FILES_DIR).join(&relative), &host_path)
                }
                FilesystemPreimageEntryType::Regular { source } => {
                    let source = stage_root
                        .join(FILES_DIR)
                        .join(safe_relative(volume.id(), source)?);
                    create_parent(&host_path)?;
                    fs::copy(&source, &host_path).context(PromotionIoSnafu {
                        action: "restore rollback regular file",
                        path: source.as_path(),
                    })?;
                    Ok(())
                }
                FilesystemPreimageEntryType::Symlink { target } => {
                    create_parent(&host_path)?;
                    symlink(target, &host_path).context(PromotionIoSnafu {
                        action: "restore rollback symlink",
                        path: host_path.as_path(),
                    })
                }
            }
        }
    }
}

fn copy_directory(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target).context(PromotionIoSnafu {
        action: "restore rollback directory",
        path: target,
    })?;
    for entry in fs::read_dir(source).context(PromotionIoSnafu {
        action: "read rollback directory",
        path: source,
    })? {
        let entry = entry.context(PromotionIoSnafu {
            action: "read rollback directory entry",
            path: source,
        })?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).context(PromotionIoSnafu {
            action: "inspect rollback directory entry",
            path: source_path.as_path(),
        })?;
        if metadata.is_dir() {
            copy_directory(&source_path, &target_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &target_path).context(PromotionIoSnafu {
                action: "restore rollback directory file",
                path: source_path.as_path(),
            })?;
        } else if metadata.file_type().is_symlink() {
            let target_link = fs::read_link(&source_path).context(PromotionIoSnafu {
                action: "read rollback directory symlink",
                path: source_path.as_path(),
            })?;
            symlink(target_link, &target_path).context(PromotionIoSnafu {
                action: "restore rollback directory symlink",
                path: target_path.as_path(),
            })?;
        }
    }
    Ok(())
}

fn operation_path(operation: &FilesystemLayerOperation) -> &str {
    match operation {
        FilesystemLayerOperation::Create { path, .. }
        | FilesystemLayerOperation::Replace { path, .. }
        | FilesystemLayerOperation::Delete { path } => path,
    }
}
