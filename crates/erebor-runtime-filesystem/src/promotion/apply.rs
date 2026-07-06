use std::{fs, os::unix::fs::symlink, path::Path};

use snafu::ResultExt;

use crate::{
    error::PromotionIoSnafu,
    manifest::{FilesystemLayerEntry, FilesystemLayerOperation},
    metadata::{FilesystemMetadataApplier, FilesystemPathMetadataCopier},
    FilesystemLayerManifest, FilesystemLayerMetadata, FilesystemVolumeStorage, Result,
};

use super::{
    journal::{PromotionJournal, PromotionJournalState},
    manifest::{
        FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
        FilesystemPreimageManifest,
    },
    path::{PromotionPath, PromotionTargetPath},
};

const FILES_DIR: &str = "files";

pub(super) struct PromotionVolumeApplier<'a> {
    journal_root: &'a Path,
    layer_stage: &'a Path,
    volume: &'a FilesystemVolumeStorage,
    layer: &'a FilesystemLayerManifest,
    journal: &'a mut PromotionJournal,
}

impl<'a> PromotionVolumeApplier<'a> {
    pub(super) fn new(
        journal_root: &'a Path,
        layer_stage: &'a Path,
        volume: &'a FilesystemVolumeStorage,
        layer: &'a FilesystemLayerManifest,
        journal: &'a mut PromotionJournal,
    ) -> Self {
        Self {
            journal_root,
            layer_stage,
            volume,
            layer,
            journal,
        }
    }

    pub(super) fn apply(&mut self) -> Result<()> {
        self.journal.state = PromotionJournalState::Applying;
        self.journal.write(self.journal_root)?;
        for operation in &self.layer.operations {
            self.apply_operation(operation)?;
            self.journal.applied_operations.push(format!(
                "{}:{}",
                self.volume.id(),
                operation.path()
            ));
            self.journal.write(self.journal_root)?;
        }
        self.apply_layer_directory_metadata()
    }

    fn apply_operation(&self, operation: &FilesystemLayerOperation) -> Result<()> {
        match operation {
            FilesystemLayerOperation::Create { path, entry } => self.write_layer_entry(path, entry),
            FilesystemLayerOperation::Replace { path, entry } => {
                let host_path = self.host_path(path)?;
                PromotionTargetPath::new(&host_path).remove()?;
                self.write_layer_entry(path, entry)
            }
            FilesystemLayerOperation::Delete { path } => {
                let host_path = self.host_path(path)?;
                PromotionTargetPath::new(&host_path).remove()
            }
            FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                let host_path = self.host_path(path)?;
                let source = self.layer_stage.join(FILES_DIR).join(self.relative(path)?);
                PromotionTargetPath::new(&host_path).remove()?;
                Self::copy_directory(&source, &host_path)
            }
        }
    }

    fn write_layer_entry(&self, path: &str, entry: &FilesystemLayerEntry) -> Result<()> {
        let host_path = self.host_path(path)?;
        match entry {
            FilesystemLayerEntry::Directory { .. } => {
                fs::create_dir_all(&host_path).context(PromotionIoSnafu {
                    action: "create promotion directory",
                    path: host_path.as_path(),
                })?;
            }
            FilesystemLayerEntry::Regular { source, metadata } => {
                let upper = self
                    .layer_stage
                    .join(FILES_DIR)
                    .join(self.relative(source)?);
                PromotionTargetPath::new(&host_path).create_parent()?;
                fs::copy(&upper, &host_path).context(PromotionIoSnafu {
                    action: "copy promotion regular file",
                    path: upper.as_path(),
                })?;
                FilesystemMetadataApplier::new(&host_path).apply_layer_metadata(metadata)?;
            }
            FilesystemLayerEntry::Symlink { target, metadata } => {
                PromotionTargetPath::new(&host_path).create_parent()?;
                symlink(target, &host_path).context(PromotionIoSnafu {
                    action: "create promotion symlink",
                    path: host_path.as_path(),
                })?;
                FilesystemMetadataApplier::new(&host_path).apply_layer_metadata(metadata)?;
            }
        }
        Ok(())
    }

    fn apply_layer_directory_metadata(&self) -> Result<()> {
        for operation in self.layer.operations.iter().rev() {
            let Some((path, metadata)) = Self::directory_metadata(operation) else {
                continue;
            };
            let host_path = self.host_path(path)?;
            FilesystemMetadataApplier::new(&host_path).apply_layer_metadata(metadata)?;
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

    fn host_path(&self, value: &str) -> Result<std::path::PathBuf> {
        Ok(self.volume.host_path().join(self.relative(value)?))
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
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
                Self::copy_directory(&source_path, &target_path)?;
            } else if metadata.is_file() {
                fs::copy(&source_path, &target_path).context(PromotionIoSnafu {
                    action: "restore rollback directory file",
                    path: source_path.as_path(),
                })?;
                FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
            } else if metadata.file_type().is_symlink() {
                let target_link = fs::read_link(&source_path).context(PromotionIoSnafu {
                    action: "read rollback directory symlink",
                    path: source_path.as_path(),
                })?;
                symlink(target_link, &target_path).context(PromotionIoSnafu {
                    action: "restore rollback directory symlink",
                    path: target_path.as_path(),
                })?;
                FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
            }
        }
        FilesystemPathMetadataCopier::new(source, target).copy()
    }
}

pub(super) struct PromotionVolumeRollback<'a> {
    stage_root: &'a Path,
    volume: &'a FilesystemVolumeStorage,
    manifest: &'a FilesystemPreimageManifest,
}

impl<'a> PromotionVolumeRollback<'a> {
    pub(super) const fn new(
        stage_root: &'a Path,
        volume: &'a FilesystemVolumeStorage,
        manifest: &'a FilesystemPreimageManifest,
    ) -> Self {
        Self {
            stage_root,
            volume,
            manifest,
        }
    }

    pub(super) fn rollback(&self) -> Result<()> {
        for entry in self.manifest.entries.iter().rev() {
            self.rollback_entry(entry)?;
        }
        Ok(())
    }

    fn rollback_entry(&self, entry: &FilesystemPreimageEntry) -> Result<()> {
        let relative = self.relative(&entry.path)?;
        let host_path = self.volume.host_path().join(&relative);
        match &entry.state {
            FilesystemPreimageEntryState::Absent => PromotionTargetPath::new(&host_path).remove(),
            FilesystemPreimageEntryState::Present { entry_type } => {
                PromotionTargetPath::new(&host_path).remove()?;
                match entry_type {
                    FilesystemPreimageEntryType::Directory => {
                        PromotionVolumeApplier::copy_directory(
                            &self.stage_root.join(FILES_DIR).join(&relative),
                            &host_path,
                        )?;
                        if let Some(metadata) = &entry.metadata {
                            FilesystemMetadataApplier::new(&host_path)
                                .apply_host_metadata(metadata)?;
                        }
                        Ok(())
                    }
                    FilesystemPreimageEntryType::Regular { source } => {
                        let source = self.stage_root.join(FILES_DIR).join(self.relative(source)?);
                        PromotionTargetPath::new(&host_path).create_parent()?;
                        fs::copy(&source, &host_path).context(PromotionIoSnafu {
                            action: "restore rollback regular file",
                            path: source.as_path(),
                        })?;
                        if let Some(metadata) = &entry.metadata {
                            FilesystemMetadataApplier::new(&host_path)
                                .apply_host_metadata(metadata)?;
                        }
                        Ok(())
                    }
                    FilesystemPreimageEntryType::Symlink { target } => {
                        PromotionTargetPath::new(&host_path).create_parent()?;
                        symlink(target, &host_path).context(PromotionIoSnafu {
                            action: "restore rollback symlink",
                            path: host_path.as_path(),
                        })?;
                        if let Some(metadata) = &entry.metadata {
                            FilesystemMetadataApplier::new(&host_path)
                                .apply_host_metadata(metadata)?;
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    fn relative(&self, value: &str) -> Result<std::path::PathBuf> {
        PromotionPath::new(self.volume.id(), value).relative()
    }
}
