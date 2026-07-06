use std::{fs, os::unix::fs::symlink, path::Path};

use snafu::{ensure, ResultExt};

use crate::{
    error::{PromotionHostDriftSnafu, PromotionIoSnafu},
    manifest::FilesystemLayerOperation,
    metadata::{FilesystemMetadataReader, FilesystemPathMetadataCopier},
    FilesystemLayerManifest, FilesystemVolumeStorage, Result,
};

use super::{
    manifest::{
        FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
        FilesystemPreimageManifest,
    },
    path::{PromotionPath, PromotionTargetPath},
    preimage_size::PreimageSizeBudget,
};

const FILES_DIR: &str = "files";

pub(super) struct PromotionPreimageCapture<'a> {
    stage_root: &'a Path,
    promotion_id: &'a str,
    volume: &'a FilesystemVolumeStorage,
    layer: &'a FilesystemLayerManifest,
    budget: PreimageSizeBudget<'a>,
}

impl<'a> PromotionPreimageCapture<'a> {
    pub(super) fn new(
        stage_root: &'a Path,
        promotion_id: &'a str,
        volume: &'a FilesystemVolumeStorage,
        layer: &'a FilesystemLayerManifest,
        limit_bytes: u64,
    ) -> Self {
        Self {
            stage_root,
            promotion_id,
            volume,
            layer,
            budget: PreimageSizeBudget::new(volume, limit_bytes),
        }
    }

    pub(super) fn capture(&self) -> Result<FilesystemPreimageManifest> {
        self.reset_stage()?;
        let mut manifest = FilesystemPreimageManifest::new(
            self.promotion_id,
            self.volume.id(),
            self.volume.host_path().display().to_string(),
        );
        for operation in &self.layer.operations {
            let path = operation.path();
            match operation {
                FilesystemLayerOperation::Create { .. } => {
                    self.capture_absent(path, &mut manifest)?;
                }
                FilesystemLayerOperation::Replace { .. }
                | FilesystemLayerOperation::Delete { .. } => {
                    self.capture_present(path, &mut manifest)?;
                }
                FilesystemLayerOperation::OpaqueReplace { .. } => {
                    self.capture_present_or_absent(path, &mut manifest)?;
                }
            }
        }
        Ok(manifest)
    }

    fn reset_stage(&self) -> Result<()> {
        if self.stage_root.exists() {
            fs::remove_dir_all(self.stage_root).context(PromotionIoSnafu {
                action: "remove promotion preimage stage",
                path: self.stage_root,
            })?;
        }
        fs::create_dir_all(self.stage_root.join(FILES_DIR)).context(PromotionIoSnafu {
            action: "create promotion preimage stage",
            path: self.stage_root,
        })
    }

    fn capture_absent(&self, path: &str, manifest: &mut FilesystemPreimageManifest) -> Result<()> {
        let host_path = self.host_path(path)?;
        match fs::symlink_metadata(&host_path) {
            Ok(_) => {
                return PromotionHostDriftSnafu {
                    volume_id: self.volume.id().to_owned(),
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

    fn capture_present(&self, path: &str, manifest: &mut FilesystemPreimageManifest) -> Result<()> {
        let relative = self.relative(path)?;
        let host_path = self.volume.host_path().join(&relative);
        let metadata = fs::symlink_metadata(&host_path).context(PromotionIoSnafu {
            action: "inspect host preimage path",
            path: host_path.as_path(),
        })?;
        let target = self.stage_root.join(FILES_DIR).join(&relative);
        let entry_type = if metadata.is_dir() {
            self.copy_directory(&host_path, &target, path, manifest)?
        } else if metadata.is_file() {
            self.budget.add_bytes(path, metadata.len(), manifest)?;
            PromotionTargetPath::new(&target).create_parent()?;
            fs::copy(&host_path, &target).context(PromotionIoSnafu {
                action: "copy promotion regular preimage",
                path: host_path.as_path(),
            })?;
            FilesystemPathMetadataCopier::new(&host_path, &target).copy()?;
            FilesystemPreimageEntryType::Regular {
                source: path.to_owned(),
            }
        } else if metadata.file_type().is_symlink() {
            PromotionTargetPath::new(&target).create_parent()?;
            let target_path = fs::read_link(&host_path).context(PromotionIoSnafu {
                action: "read promotion symlink preimage",
                path: host_path.as_path(),
            })?;
            symlink(&target_path, &target).context(PromotionIoSnafu {
                action: "copy promotion symlink preimage",
                path: target.as_path(),
            })?;
            FilesystemPathMetadataCopier::new(&host_path, &target).copy()?;
            FilesystemPreimageEntryType::Symlink {
                target: target_path.display().to_string(),
            }
        } else {
            return crate::error::UnsupportedLayerSnafu {
                volume_id: self.volume.id().to_owned(),
                reason: format!("preimage path `{path}` is an unsupported special file"),
            }
            .fail();
        };
        manifest.entries.push(FilesystemPreimageEntry {
            path: path.to_owned(),
            state: FilesystemPreimageEntryState::Present { entry_type },
            metadata: Some(FilesystemMetadataReader::new(&host_path, &metadata).host_metadata()?),
        });
        Ok(())
    }

    fn capture_present_or_absent(
        &self,
        path: &str,
        manifest: &mut FilesystemPreimageManifest,
    ) -> Result<()> {
        let host_path = self.host_path(path)?;
        match fs::symlink_metadata(&host_path) {
            Ok(_) => self.capture_present(path, manifest),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.capture_absent(path, manifest)
            }
            Err(source) => Err(source).context(PromotionIoSnafu {
                action: "inspect opaque host preimage path",
                path: host_path.as_path(),
            }),
        }
    }

    fn copy_directory(
        &self,
        source: &Path,
        target: &Path,
        manifest_path: &str,
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
                self.copy_directory(&source_path, &target_path, manifest_path, manifest)?;
            } else if metadata.is_file() {
                self.budget
                    .add_bytes(manifest_path, metadata.len(), manifest)?;
                fs::copy(&source_path, &target_path).context(PromotionIoSnafu {
                    action: "copy promotion directory file preimage",
                    path: source_path.as_path(),
                })?;
                FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
            } else if metadata.file_type().is_symlink() {
                let link_target = fs::read_link(&source_path).context(PromotionIoSnafu {
                    action: "read promotion directory symlink preimage",
                    path: source_path.as_path(),
                })?;
                symlink(link_target, &target_path).context(PromotionIoSnafu {
                    action: "copy promotion directory symlink preimage",
                    path: target_path.as_path(),
                })?;
                FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
            } else {
                return crate::error::UnsupportedLayerSnafu {
                    volume_id: self.volume.id().to_owned(),
                    reason: format!("preimage directory `{manifest_path}` contains a special file"),
                }
                .fail();
            }
        }
        FilesystemPathMetadataCopier::new(source, target).copy()?;
        Ok(FilesystemPreimageEntryType::Directory)
    }

    fn host_path(&self, value: &str) -> Result<std::path::PathBuf> {
        Ok(self.volume.host_path().join(self.relative(value)?))
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
    }
}

pub(super) struct PromotionPreimageVerifier<'a> {
    volume: &'a FilesystemVolumeStorage,
    manifest: &'a FilesystemPreimageManifest,
}

impl<'a> PromotionPreimageVerifier<'a> {
    pub(super) const fn new(
        volume: &'a FilesystemVolumeStorage,
        manifest: &'a FilesystemPreimageManifest,
    ) -> Self {
        Self { volume, manifest }
    }

    pub(super) fn verify(&self) -> Result<()> {
        for entry in &self.manifest.entries {
            let host_path = self.volume.host_path().join(self.relative(&entry.path)?);
            match &entry.state {
                FilesystemPreimageEntryState::Absent => self.verify_absent(entry, &host_path)?,
                FilesystemPreimageEntryState::Present { .. } => {
                    self.verify_present(entry, &host_path)?
                }
            }
        }
        Ok(())
    }

    fn verify_absent(&self, entry: &FilesystemPreimageEntry, host_path: &Path) -> Result<()> {
        match fs::symlink_metadata(host_path) {
            Ok(_) => PromotionHostDriftSnafu {
                volume_id: self.volume.id().to_owned(),
                path: entry.path.clone(),
                reason: String::from("expected path to remain absent"),
            }
            .fail()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(PromotionIoSnafu {
                    action: "inspect absent host preimage path for drift",
                    path: host_path,
                });
            }
        }
        Ok(())
    }

    fn verify_present(&self, entry: &FilesystemPreimageEntry, host_path: &Path) -> Result<()> {
        let current = fs::symlink_metadata(host_path).context(PromotionIoSnafu {
            action: "inspect host preimage path for drift",
            path: host_path,
        })?;
        let Some(expected) = &entry.metadata else {
            return Ok(());
        };
        let current = FilesystemMetadataReader::new(host_path, &current).host_metadata()?;
        ensure!(
            current == *expected,
            PromotionHostDriftSnafu {
                volume_id: self.volume.id().to_owned(),
                path: entry.path.clone(),
                reason: String::from("metadata no longer matches captured preimage")
            }
        );
        Ok(())
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
    }
}
