use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Component, Path},
};

use snafu::ResultExt;

use crate::{
    error::{InspectLayerPathSnafu, ReadLayerPathSnafu, UnsupportedLayerSnafu},
    manifest::{
        FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerMetadata,
        FilesystemLayerMetadataSidecar, FilesystemLayerOperation, FilesystemLayerUnsupported,
    },
    metadata::FilesystemMetadataReader,
    overlay::OverlayMarkerProbe,
    FilesystemVolumeStorage, Result,
};

use super::opaque::OpaqueLayerNormalizer;

pub(super) struct FilesystemLayerEntryNormalizer<'a, 'm> {
    volume: &'a FilesystemVolumeStorage,
    manifest: &'m mut FilesystemLayerManifest,
}

impl<'a, 'm> FilesystemLayerEntryNormalizer<'a, 'm> {
    pub(super) fn new(
        volume: &'a FilesystemVolumeStorage,
        manifest: &'m mut FilesystemLayerManifest,
    ) -> Self {
        Self { volume, manifest }
    }

    pub(super) fn walk_directory(&mut self, directory: &Path) -> Result<()> {
        let entries = fs::read_dir(directory).context(ReadLayerPathSnafu { path: directory })?;
        for entry in entries {
            let entry = entry.context(ReadLayerPathSnafu { path: directory })?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).context(InspectLayerPathSnafu { path: &path })?;
            self.normalize_entry(&path, &metadata)?;
        }
        Ok(())
    }

    fn normalize_entry(&mut self, path: &Path, metadata: &fs::Metadata) -> Result<()> {
        let relative = self.manifest_path(path)?;
        let file_type = metadata.file_type();
        if OverlayMarkerProbe::new(path).is_opaque_marker_file() {
            return Ok(());
        }

        if let Some(delete_path) = self.whiteout_delete_path(path, metadata, &relative)? {
            self.manifest
                .operations
                .push(FilesystemLayerOperation::Delete { path: delete_path });
            return Ok(());
        }

        let overlay_probe = OverlayMarkerProbe::new(path);
        for reason in overlay_probe.unsupported_reasons()? {
            self.manifest.push_unsupported(FilesystemLayerUnsupported {
                path: relative.clone(),
                reason,
            });
        }
        for name in overlay_probe.metadata_sidecars()? {
            self.manifest
                .metadata_sidecars
                .push(FilesystemLayerMetadataSidecar {
                    path: relative.clone(),
                    name,
                });
        }

        if file_type.is_dir() {
            if let Some(operation) =
                OpaqueLayerNormalizer::new(path, &relative, metadata).operation()?
            {
                self.manifest.operations.push(operation);
                return Ok(());
            }
            let operation = self.create_or_replace_operation(
                &relative,
                FilesystemLayerEntry::Directory {
                    metadata: Self::layer_metadata(path, metadata)?,
                },
            );
            self.manifest.operations.push(operation);
            self.walk_directory(path)?;
        } else if file_type.is_file() {
            let operation = self.create_or_replace_operation(
                &relative,
                FilesystemLayerEntry::Regular {
                    source: relative.clone(),
                    metadata: Self::layer_metadata(path, metadata)?,
                },
            );
            self.manifest.operations.push(operation);
        } else if file_type.is_symlink() {
            self.normalize_symlink(path, &relative, metadata)?;
        } else {
            self.manifest.push_unsupported(FilesystemLayerUnsupported {
                path: relative,
                reason: String::from("unsupported special file type in upperdir"),
            });
        }
        Ok(())
    }

    fn normalize_symlink(
        &mut self,
        path: &Path,
        relative: &str,
        metadata: &fs::Metadata,
    ) -> Result<()> {
        let target = fs::read_link(path).context(ReadLayerPathSnafu { path })?;
        match Self::safe_symlink_target(&target) {
            Ok(target) => {
                let operation = self.create_or_replace_operation(
                    relative,
                    FilesystemLayerEntry::Symlink {
                        target,
                        metadata: Self::layer_metadata(path, metadata)?,
                    },
                );
                self.manifest.operations.push(operation);
            }
            Err(reason) => self.manifest.push_unsupported(FilesystemLayerUnsupported {
                path: relative.to_owned(),
                reason,
            }),
        }
        Ok(())
    }

    fn create_or_replace_operation(
        &self,
        relative: &str,
        entry: FilesystemLayerEntry,
    ) -> FilesystemLayerOperation {
        let lower_path = self.volume.host_path().join(relative);
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
        &self,
        path: &Path,
        metadata: &fs::Metadata,
        relative: &str,
    ) -> Result<Option<String>> {
        if metadata.file_type().is_char_device() && metadata.rdev() == 0
            || OverlayMarkerProbe::new(path).is_whiteout()?
        {
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
            .and_then(|parent| parent.strip_prefix(self.volume.overlay().upper_path()).ok())
            .and_then(Path::to_str)
            .unwrap_or_default();
        let target = if parent.is_empty() {
            stripped.to_owned()
        } else {
            format!("{parent}/{stripped}")
        };
        Ok(Some(target))
    }

    fn manifest_path(&self, path: &Path) -> Result<String> {
        let relative = path
            .strip_prefix(self.volume.overlay().upper_path())
            .map_err(|_| crate::FilesystemError::UnsupportedLayer {
                volume_id: self.volume.id().to_owned(),
                reason: format!("upperdir path `{}` escaped root", path.display()),
                location: snafu::Location::default(),
            })?;
        self.ensure_relative_path(relative)?;
        relative.to_str().map(ToOwned::to_owned).ok_or_else(|| {
            crate::FilesystemError::UnsupportedLayer {
                volume_id: self.volume.id().to_owned(),
                reason: format!("path `{}` is not valid UTF-8", relative.display()),
                location: snafu::Location::default(),
            }
        })
    }

    fn ensure_relative_path(&self, path: &Path) -> Result<()> {
        if path.as_os_str().is_empty() {
            return self.unsupported_path("empty relative path");
        }
        for component in path.components() {
            match component {
                Component::Normal(_) => {}
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return self
                        .unsupported_path("relative path contains traversal or root component");
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

    fn unsupported_path<T>(&self, reason: &str) -> Result<T> {
        UnsupportedLayerSnafu {
            volume_id: self.volume.id().to_owned(),
            reason: reason.to_owned(),
        }
        .fail()
    }

    fn layer_metadata(path: &Path, metadata: &fs::Metadata) -> Result<FilesystemLayerMetadata> {
        FilesystemMetadataReader::new(path, metadata).layer_metadata()
    }
}
