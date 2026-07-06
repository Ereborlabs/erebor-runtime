use std::{fs, os::unix::fs::symlink, path::Path};

use snafu::{ensure, ResultExt};

use crate::{
    error::{PromotionHostDriftSnafu, PromotionIoSnafu},
    manifest::FilesystemLayerOperation,
    metadata::{FilesystemMetadataReader, FilesystemPathMetadataCopier},
    FilesystemLayerManifest, FilesystemPreimageBackendKind, FilesystemVolumeStorage, Result,
};

use super::{
    manifest::{
        FilesystemDirectoryPreimageFile, FilesystemPreimageEntry, FilesystemPreimageEntryState,
        FilesystemPreimageEntryType, FilesystemPreimageManifest, FilesystemRegularPreimage,
    },
    path::{PromotionPath, PromotionTargetPath},
    preimage_artifact::LinuxReflinkPreimageStore,
    preimage_size::PreimageSizeBudget,
};

const FILES_DIR: &str = "files";

pub(super) struct PromotionPreimageCapture<'a> {
    stage_root: &'a Path,
    work_root: &'a Path,
    artifact_root: &'a Path,
    promotion_id: &'a str,
    volume: &'a FilesystemVolumeStorage,
    layer: &'a FilesystemLayerManifest,
    budget: PreimageSizeBudget<'a>,
    preimage_backend: FilesystemPreimageBackendKind,
}

pub(super) struct PromotionPreimageCaptureRequest<'a> {
    pub(super) stage_root: &'a Path,
    pub(super) work_root: &'a Path,
    pub(super) artifact_root: &'a Path,
    pub(super) promotion_id: &'a str,
    pub(super) volume: &'a FilesystemVolumeStorage,
    pub(super) layer: &'a FilesystemLayerManifest,
    pub(super) limit_bytes: u64,
    pub(super) preimage_backend: FilesystemPreimageBackendKind,
}

impl<'a> PromotionPreimageCapture<'a> {
    pub(super) fn new(request: PromotionPreimageCaptureRequest<'a>) -> Self {
        Self {
            stage_root: request.stage_root,
            work_root: request.work_root,
            artifact_root: request.artifact_root,
            promotion_id: request.promotion_id,
            volume: request.volume,
            layer: request.layer,
            budget: PreimageSizeBudget::new(request.volume, request.limit_bytes),
            preimage_backend: request.preimage_backend,
        }
    }

    pub(super) fn capture(&self) -> Result<FilesystemPreimageManifest> {
        self.reset_stage()?;
        self.reset_artifacts()?;
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

    fn reset_artifacts(&self) -> Result<()> {
        if self.artifact_root.exists() {
            fs::remove_dir_all(self.artifact_root).context(PromotionIoSnafu {
                action: "remove linux reflink preimage artifacts",
                path: self.artifact_root,
            })?;
        }
        fs::create_dir_all(self.artifact_root).context(PromotionIoSnafu {
            action: "create linux reflink preimage artifact directory",
            path: self.artifact_root,
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
            FilesystemPreimageEntryType::Regular {
                source: path.to_owned(),
                preimage: self
                    .capture_regular_file(path, &host_path, &target, &relative, manifest)?,
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

    fn capture_regular_file(
        &self,
        path: &str,
        source: &Path,
        target: &Path,
        relative: &Path,
        manifest: &mut FilesystemPreimageManifest,
    ) -> Result<FilesystemRegularPreimage> {
        let metadata = fs::symlink_metadata(source).context(PromotionIoSnafu {
            action: "inspect regular promotion preimage",
            path: source,
        })?;
        if self.budget.can_add_bytes(metadata.len(), manifest) {
            self.capture_ostree_bytes_file(path, source, target, metadata.len(), manifest)?;
            return Ok(FilesystemRegularPreimage::OstreeBytes);
        }
        if self.preimage_backend == FilesystemPreimageBackendKind::LinuxReflink {
            return LinuxReflinkPreimageStore::new(self.work_root, self.volume.id()).capture_file(
                self.artifact_root,
                path,
                source,
                relative,
            );
        }
        self.budget.add_bytes(path, metadata.len(), manifest)?;
        Ok(FilesystemRegularPreimage::OstreeBytes)
    }

    fn capture_ostree_bytes_file(
        &self,
        path: &str,
        source: &Path,
        target: &Path,
        bytes: u64,
        manifest: &mut FilesystemPreimageManifest,
    ) -> Result<()> {
        self.budget.add_bytes(path, bytes, manifest)?;
        PromotionTargetPath::new(target).create_parent()?;
        fs::copy(source, target).context(PromotionIoSnafu {
            action: "copy promotion regular preimage",
            path: source,
        })?;
        FilesystemPathMetadataCopier::new(source, target).copy()
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
        let mut external_files = Vec::new();
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
            let entry_manifest_path =
                Self::child_manifest_path(manifest_path, &entry.file_name().to_string_lossy());
            let metadata = fs::symlink_metadata(&source_path).context(PromotionIoSnafu {
                action: "inspect promotion directory preimage entry",
                path: source_path.as_path(),
            })?;
            if metadata.is_dir() {
                if let FilesystemPreimageEntryType::Directory {
                    external_files: nested,
                } =
                    self.copy_directory(&source_path, &target_path, &entry_manifest_path, manifest)?
                {
                    external_files.extend(nested);
                }
            } else if metadata.is_file() {
                let relative = self.relative(&entry_manifest_path)?;
                let preimage = self.capture_regular_file(
                    &entry_manifest_path,
                    &source_path,
                    &target_path,
                    &relative,
                    manifest,
                )?;
                if matches!(preimage, FilesystemRegularPreimage::LinuxReflink { .. }) {
                    external_files.push(FilesystemDirectoryPreimageFile {
                        path: entry_manifest_path,
                        preimage,
                        metadata: FilesystemMetadataReader::new(&source_path, &metadata)
                            .host_metadata()?,
                    });
                }
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
        Ok(FilesystemPreimageEntryType::Directory { external_files })
    }

    fn child_manifest_path(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_owned()
        } else {
            format!("{parent}/{child}")
        }
    }

    fn host_path(&self, value: &str) -> Result<std::path::PathBuf> {
        Ok(self.volume.host_path().join(self.relative(value)?))
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
    }
}

pub(super) struct PromotionPreimageVerifier<'a> {
    work_root: &'a Path,
    volume: &'a FilesystemVolumeStorage,
    manifest: &'a FilesystemPreimageManifest,
}

impl<'a> PromotionPreimageVerifier<'a> {
    pub(super) const fn new(
        work_root: &'a Path,
        volume: &'a FilesystemVolumeStorage,
        manifest: &'a FilesystemPreimageManifest,
    ) -> Self {
        Self {
            work_root,
            volume,
            manifest,
        }
    }

    pub(super) fn verify(&self) -> Result<()> {
        for entry in &self.manifest.entries {
            let host_path = self.volume.host_path().join(self.relative(&entry.path)?);
            match &entry.state {
                FilesystemPreimageEntryState::Absent => self.verify_absent(entry, &host_path)?,
                FilesystemPreimageEntryState::Present { entry_type } => {
                    self.verify_present(entry, entry_type, &host_path)?
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

    fn verify_present(
        &self,
        entry: &FilesystemPreimageEntry,
        entry_type: &FilesystemPreimageEntryType,
        host_path: &Path,
    ) -> Result<()> {
        let current = fs::symlink_metadata(host_path).context(PromotionIoSnafu {
            action: "inspect host preimage path for drift",
            path: host_path,
        })?;
        let Some(expected) = &entry.metadata else {
            self.verify_preimage_artifacts(entry_type)?;
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
        self.verify_preimage_artifacts(entry_type)?;
        Ok(())
    }

    fn verify_preimage_artifacts(&self, entry_type: &FilesystemPreimageEntryType) -> Result<()> {
        let store = LinuxReflinkPreimageStore::new(self.work_root, self.volume.id());
        match entry_type {
            FilesystemPreimageEntryType::Directory { external_files } => {
                for file in external_files {
                    let host_path = self.volume.host_path().join(self.relative(&file.path)?);
                    self.verify_external_file_metadata(file, &host_path)?;
                    store.validate_regular_preimage(&file.path, &file.preimage)?;
                }
            }
            FilesystemPreimageEntryType::Regular { source, preimage } => {
                store.validate_regular_preimage(source, preimage)?;
            }
            FilesystemPreimageEntryType::Symlink { .. } => {}
        }
        Ok(())
    }

    fn verify_external_file_metadata(
        &self,
        file: &FilesystemDirectoryPreimageFile,
        host_path: &Path,
    ) -> Result<()> {
        let current = fs::symlink_metadata(host_path).context(PromotionIoSnafu {
            action: "inspect external preimage file for drift",
            path: host_path,
        })?;
        let current = FilesystemMetadataReader::new(host_path, &current).host_metadata()?;
        ensure!(
            current == file.metadata,
            PromotionHostDriftSnafu {
                volume_id: self.volume.id().to_owned(),
                path: file.path.clone(),
                reason: String::from("external preimage file metadata drifted")
            }
        );
        Ok(())
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
    }
}
