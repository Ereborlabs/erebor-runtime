use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Component, Path},
};

use snafu::ResultExt;

use crate::{
    error::{ReadLayerPathSnafu, UnsupportedLayerSnafu},
    manifest::{
        FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerMetadata,
        FilesystemLayerMetadataSidecar, FilesystemLayerOperation, FilesystemLayerUnsupported,
    },
    FilesystemVolumeStorage, Result,
};

use super::xattrs;

pub(super) fn normalize_entry(
    volume: &FilesystemVolumeStorage,
    path: &Path,
    metadata: &fs::Metadata,
    manifest: &mut FilesystemLayerManifest,
) -> Result<()> {
    let relative = manifest_path(volume.overlay().upper_path(), path)?;
    let file_type = metadata.file_type();
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".wh..wh..opq")
    {
        manifest.push_unsupported(FilesystemLayerUnsupported {
            path: relative.clone(),
            reason: String::from("opaque directory marker is not promotable in this phase"),
        });
        return Ok(());
    }

    if let Some(delete_path) =
        whiteout_delete_path(volume.overlay().upper_path(), path, metadata, &relative)?
    {
        manifest
            .operations
            .push(FilesystemLayerOperation::Delete { path: delete_path });
        return Ok(());
    }

    for reason in xattrs::unsupported_reasons(path)? {
        manifest.push_unsupported(FilesystemLayerUnsupported {
            path: relative.clone(),
            reason,
        });
    }
    for name in xattrs::metadata_sidecars(path)? {
        manifest
            .metadata_sidecars
            .push(FilesystemLayerMetadataSidecar {
                path: relative.clone(),
                name,
            });
    }

    if xattrs::is_opaque_directory(path)? {
        manifest.push_unsupported(FilesystemLayerUnsupported {
            path: relative.clone(),
            reason: String::from("opaque directories are not promotable in this phase"),
        });
    }

    if file_type.is_dir() {
        let operation = create_or_replace_operation(
            volume,
            &relative,
            FilesystemLayerEntry::Directory {
                metadata: layer_metadata(metadata),
            },
        );
        manifest.operations.push(operation);
        super::walk_upperdir(volume, path, manifest)?;
    } else if file_type.is_file() {
        let operation = create_or_replace_operation(
            volume,
            &relative,
            FilesystemLayerEntry::Regular {
                source: relative.clone(),
                metadata: layer_metadata(metadata),
            },
        );
        manifest.operations.push(operation);
    } else if file_type.is_symlink() {
        normalize_symlink(volume, path, &relative, metadata, manifest)?;
    } else {
        manifest.push_unsupported(FilesystemLayerUnsupported {
            path: relative,
            reason: String::from("unsupported special file type in upperdir"),
        });
    }
    Ok(())
}

pub(super) fn operation_path(operation: &FilesystemLayerOperation) -> &str {
    match operation {
        FilesystemLayerOperation::Create { path, .. }
        | FilesystemLayerOperation::Replace { path, .. }
        | FilesystemLayerOperation::Delete { path } => path,
    }
}

fn normalize_symlink(
    volume: &FilesystemVolumeStorage,
    path: &Path,
    relative: &str,
    metadata: &fs::Metadata,
    manifest: &mut FilesystemLayerManifest,
) -> Result<()> {
    let target = fs::read_link(path).context(ReadLayerPathSnafu { path })?;
    match safe_symlink_target(&target) {
        Ok(target) => {
            let operation = create_or_replace_operation(
                volume,
                relative,
                FilesystemLayerEntry::Symlink {
                    target,
                    metadata: layer_metadata(metadata),
                },
            );
            manifest.operations.push(operation);
        }
        Err(reason) => manifest.push_unsupported(FilesystemLayerUnsupported {
            path: relative.to_owned(),
            reason,
        }),
    }
    Ok(())
}

fn create_or_replace_operation(
    volume: &FilesystemVolumeStorage,
    relative: &str,
    entry: FilesystemLayerEntry,
) -> FilesystemLayerOperation {
    let lower_path = volume.host_path().join(relative);
    if fs::symlink_metadata(lower_path).is_ok() {
        FilesystemLayerOperation::Replace {
            path: relative.to_owned(),
            entry,
        }
    } else {
        FilesystemLayerOperation::Create {
            path: relative.to_owned(),
            entry,
        }
    }
}

fn whiteout_delete_path(
    upperdir: &Path,
    path: &Path,
    metadata: &fs::Metadata,
    relative: &str,
) -> Result<Option<String>> {
    if metadata.file_type().is_char_device() && metadata.rdev() == 0 || xattrs::is_whiteout(path)? {
        return Ok(Some(relative.to_owned()));
    }

    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let Some(stripped) = file_name.strip_prefix(".wh.") else {
        return Ok(None);
    };
    let parent = path
        .parent()
        .and_then(|parent| parent.strip_prefix(upperdir).ok())
        .and_then(Path::to_str)
        .unwrap_or_default();
    let target = if parent.is_empty() {
        stripped.to_owned()
    } else {
        format!("{parent}/{stripped}")
    };
    Ok(Some(target))
}

fn manifest_path(upperdir: &Path, path: &Path) -> Result<String> {
    let relative =
        path.strip_prefix(upperdir)
            .map_err(|_| crate::FilesystemError::UnsupportedLayer {
                volume_id: String::from("<unknown>"),
                reason: format!("upperdir path `{}` escaped root", path.display()),
                location: snafu::Location::default(),
            })?;
    validate_relative_path(relative)?;
    relative.to_str().map(ToOwned::to_owned).ok_or_else(|| {
        crate::FilesystemError::UnsupportedLayer {
            volume_id: String::from("<unknown>"),
            reason: format!("path `{}` is not valid UTF-8", relative.display()),
            location: snafu::Location::default(),
        }
    })
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return unsupported_path("empty relative path");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return unsupported_path("relative path contains traversal or root component");
            }
        }
    }
    Ok(())
}

fn safe_symlink_target(target: &Path) -> std::result::Result<String, String> {
    if target.is_absolute()
        || target.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(String::from("symlink target escapes the layer"));
    }
    target
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| String::from("symlink target is not valid UTF-8"))
}

fn unsupported_path(reason: &str) -> Result<()> {
    UnsupportedLayerSnafu {
        volume_id: String::from("<unknown>"),
        reason: reason.to_owned(),
    }
    .fail()
}

fn layer_metadata(metadata: &fs::Metadata) -> FilesystemLayerMetadata {
    FilesystemLayerMetadata {
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
    }
}
