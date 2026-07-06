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
    metadata::{FilesystemMetadataApplier, FilesystemMetadataReader},
    overlay::OverlayMarkerProbe,
    FilesystemLayerMetadata, FilesystemVolumeStorage, Result,
};

const FILES_DIR: &str = "files";

pub(super) struct CheckpointLayerStage<'a> {
    stage_root: &'a Path,
    volume: &'a FilesystemVolumeStorage,
    manifest: &'a FilesystemLayerManifest,
}

impl<'a> CheckpointLayerStage<'a> {
    pub(super) const fn new(
        stage_root: &'a Path,
        volume: &'a FilesystemVolumeStorage,
        manifest: &'a FilesystemLayerManifest,
    ) -> Self {
        Self {
            stage_root,
            volume,
            manifest,
        }
    }

    pub(super) fn stage(&self) -> Result<()> {
        self.reset_stage()?;
        self.write_layer_manifest()?;

        for operation in &self.manifest.operations {
            match operation {
                FilesystemLayerOperation::Create { path, entry }
                | FilesystemLayerOperation::Replace { path, entry } => {
                    self.stage_entry(path, entry)?;
                }
                FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                    self.stage_opaque_replace(path)?;
                }
                FilesystemLayerOperation::Delete { .. } => {}
            }
        }
        self.apply_directory_metadata()
    }

    fn reset_stage(&self) -> Result<()> {
        if self.stage_root.exists() {
            fs::remove_dir_all(self.stage_root).context(CheckpointIoSnafu {
                action: "remove checkpoint stage",
                path: self.stage_root,
            })?;
        }
        fs::create_dir_all(self.stage_root.join(FILES_DIR)).context(CheckpointIoSnafu {
            action: "create checkpoint stage",
            path: self.stage_root,
        })
    }

    fn write_layer_manifest(&self) -> Result<()> {
        let path = self.stage_root.join(LAYER_MANIFEST_FILE);
        let source =
            serde_json::to_vec_pretty(self.manifest).context(EncodeLayerManifestSnafu {
                path: path.as_path(),
            })?;
        fs::write(&path, source).context(CheckpointIoSnafu {
            action: "write checkpoint layer manifest",
            path: path.as_path(),
        })
    }

    fn stage_entry(&self, path: &str, entry: &FilesystemLayerEntry) -> Result<()> {
        let target = self.stage_path(path)?;
        match entry {
            FilesystemLayerEntry::Directory { .. } => {
                fs::create_dir_all(&target).context(CheckpointIoSnafu {
                    action: "create checkpoint directory entry",
                    path: target.as_path(),
                })?;
            }
            FilesystemLayerEntry::Regular { source, metadata } => {
                self.copy_regular(source, &target)?;
                FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
            }
            FilesystemLayerEntry::Symlink {
                target: source,
                metadata,
            } => {
                self.write_symlink(source, &target)?;
                FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
            }
        }
        Ok(())
    }

    fn apply_directory_metadata(&self) -> Result<()> {
        for operation in self.manifest.operations.iter().rev() {
            let Some((path, metadata)) = Self::directory_metadata(operation) else {
                continue;
            };
            let target = self.stage_path(path)?;
            FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
        }
        Ok(())
    }

    fn directory_metadata(
        operation: &FilesystemLayerOperation,
    ) -> Option<(&str, &FilesystemLayerMetadata)> {
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

    fn stage_opaque_replace(&self, path: &str) -> Result<()> {
        let relative = CheckpointPath::new(path)?.relative();
        let source = self.volume.overlay().upper_path().join(&relative);
        let target = self.stage_root.join(FILES_DIR).join(relative);
        self.stage_visible_tree(&source, &target)
    }

    fn stage_visible_tree(&self, source: &Path, target: &Path) -> Result<()> {
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
            if OverlayMarkerProbe::new(&source_path).is_whiteout_entry(&file_metadata)? {
                continue;
            }
            let target_path = target.join(entry.file_name());
            if file_metadata.is_dir() {
                self.stage_visible_tree(&source_path, &target_path)?;
            } else if file_metadata.is_file() {
                fs::copy(&source_path, &target_path).context(CheckpointIoSnafu {
                    action: "copy checkpoint opaque regular entry",
                    path: source_path.as_path(),
                })?;
                self.apply_source_metadata(&source_path, &target_path, &file_metadata)?;
            } else if file_metadata.file_type().is_symlink() {
                let link = fs::read_link(&source_path).context(CheckpointIoSnafu {
                    action: "read checkpoint opaque symlink entry",
                    path: source_path.as_path(),
                })?;
                symlink(link, &target_path).context(CheckpointIoSnafu {
                    action: "copy checkpoint opaque symlink entry",
                    path: target_path.as_path(),
                })?;
                self.apply_source_metadata(&source_path, &target_path, &file_metadata)?;
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
        self.apply_source_metadata(source, target, &directory_metadata)
    }

    fn apply_source_metadata(
        &self,
        source: &Path,
        target: &Path,
        metadata: &fs::Metadata,
    ) -> Result<()> {
        let metadata = FilesystemMetadataReader::new(source, metadata).layer_metadata()?;
        FilesystemMetadataApplier::new(target).apply_layer_metadata(&metadata)
    }

    fn copy_regular(&self, source: &str, target: &Path) -> Result<()> {
        let source = self
            .volume
            .overlay()
            .upper_path()
            .join(CheckpointPath::new(source)?.relative());
        Self::create_parent(target)?;
        fs::copy(&source, target).context(CheckpointIoSnafu {
            action: "copy checkpoint regular entry",
            path: target,
        })?;
        Ok(())
    }

    fn write_symlink(&self, source: &str, target: &Path) -> Result<()> {
        Self::create_parent(target)?;
        symlink(source, target).context(CheckpointIoSnafu {
            action: "create checkpoint symlink entry",
            path: target,
        })
    }

    fn stage_path(&self, value: &str) -> Result<PathBuf> {
        Ok(self
            .stage_root
            .join(FILES_DIR)
            .join(CheckpointPath::new(value)?.relative()))
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
}

struct CheckpointPath {
    relative: PathBuf,
}

impl CheckpointPath {
    fn new(value: &str) -> Result<Self> {
        let path = Path::new(value);
        if path.as_os_str().is_empty() {
            return Self::invalid(value);
        }
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => return Self::invalid(value),
            }
        }
        Ok(Self { relative })
    }

    fn relative(self) -> PathBuf {
        self.relative
    }

    fn invalid<T>(value: &str) -> Result<T> {
        UnsupportedLayerSnafu {
            volume_id: String::from("<checkpoint>"),
            reason: format!("checkpoint layer path `{value}` is not a safe relative path"),
        }
        .fail()
    }
}
