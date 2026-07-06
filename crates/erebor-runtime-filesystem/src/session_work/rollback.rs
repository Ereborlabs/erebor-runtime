use std::{
    fs,
    os::unix::fs::symlink,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;
use snafu::ResultExt;

use crate::{
    error::{EncodeSessionWorkSnafu, SessionWorkIoSnafu, UnsupportedLayerSnafu},
    manifest::{
        FilesystemLayerEntry, FilesystemLayerManifest, FilesystemLayerOperation,
        LAYER_MANIFEST_FILE,
    },
    metadata::{FilesystemMetadataApplier, FilesystemMetadataReader},
    ostree::{OstreeRepository, OstreeTreeCheckout, SystemOstreeRepository},
    FilesystemSessionStorage, FilesystemVolumeStorage, Result,
};

use super::{
    catalog::{FilesystemSessionWorkCatalog, SessionWorkCatalogResolver},
    state::{SessionWorkRollbackJournal, SessionWorkState},
};

const FILES_DIR: &str = "files";
const OPAQUE_MARKER_FILE: &str = ".wh..wh..opq";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSessionWorkRollback {
    transaction_id: String,
    handle: String,
    restored_volumes: Vec<String>,
}

impl FilesystemSessionWorkRollback {
    pub fn rollback(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
    ) -> Result<Self> {
        Self::rollback_using_repository(storage, session_id, selector, &SystemOstreeRepository)
    }

    pub(crate) fn rollback_using_repository(
        storage: &FilesystemSessionStorage,
        session_id: &str,
        selector: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        SessionWorkRollbackWorkflow::new(storage, session_id, selector, repository)?.rollback()
    }

    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn restored_volumes(&self) -> &[String] {
        &self.restored_volumes
    }
}

struct SessionWorkRollbackWorkflow<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    session_id: &'a str,
    selector: &'a str,
    repository: &'a R,
}

impl<'a, R> SessionWorkRollbackWorkflow<'a, R>
where
    R: OstreeRepository,
{
    const fn new(
        storage: &'a FilesystemSessionStorage,
        session_id: &'a str,
        selector: &'a str,
        repository: &'a R,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            session_id,
            selector,
            repository,
        })
    }

    fn rollback(&self) -> Result<FilesystemSessionWorkRollback> {
        let catalog = FilesystemSessionWorkCatalog::load_using_repository(
            self.storage,
            self.session_id,
            self.repository,
        )?;
        let target = SessionWorkCatalogResolver::new(&catalog).resolve(self.selector)?;
        let transaction_id = target.transaction_id().to_owned();
        let selected = target.selected_volumes();
        self.storage.ensure_quiescent()?;
        let restored = match self.restore_layers(&target.selected_layers()) {
            Ok(restored) => restored,
            Err(error) => {
                self.append_failed_event(&transaction_id, &selected, error.to_string())?;
                return Err(error);
            }
        };
        let mut state = SessionWorkState::read(self.storage)?;
        state.mark_current(&transaction_id);
        state.write(self.storage)?;
        state.append_rollback_event(
            self.storage,
            SessionWorkRollbackJournal {
                selector: self.selector.to_owned(),
                transaction_id: transaction_id.clone(),
                selected_volumes: selected,
                restored_volumes: restored.clone(),
                outcome: String::from("success"),
                error: None,
            },
        )?;
        Ok(FilesystemSessionWorkRollback {
            transaction_id,
            handle: self.selector.to_owned(),
            restored_volumes: restored,
        })
    }

    fn restore_layers(
        &self,
        layers: &[super::catalog::SessionWorkSelectedLayer],
    ) -> Result<Vec<String>> {
        let mut restored = Vec::new();
        for layer in layers {
            let volume = self.volume(&layer.volume_id)?;
            let checkout_root = self.checkout_root(&layer.volume_id);
            OstreeTreeCheckout::new(
                self.storage.repo_path(),
                &layer.layer_ref,
                &checkout_root,
                "checkout session-work rollback layer",
            )
            .checkout(self.repository)?;
            let manifest = self.read_layer_manifest(&checkout_root)?;
            SessionWorkOverlayRestorer::new(volume, &checkout_root, &manifest).restore()?;
            restored.push(layer.volume_id.clone());
        }
        Ok(restored)
    }

    fn append_failed_event(
        &self,
        transaction_id: &str,
        selected: &[String],
        error: String,
    ) -> Result<()> {
        let state = SessionWorkState::read(self.storage)?;
        state.append_rollback_event(
            self.storage,
            SessionWorkRollbackJournal {
                selector: self.selector.to_owned(),
                transaction_id: transaction_id.to_owned(),
                selected_volumes: selected.to_vec(),
                restored_volumes: Vec::new(),
                outcome: String::from("failed"),
                error: Some(error),
            },
        )
    }

    fn volume(&self, volume_id: &str) -> Result<&'a FilesystemVolumeStorage> {
        self.storage
            .volumes()
            .iter()
            .find(|volume| volume.id() == volume_id)
            .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
                volume_id: volume_id.to_owned(),
                reason: String::from("session-work target references an unknown volume"),
                location: snafu::Location::default(),
            })
    }

    fn read_layer_manifest(&self, root: &Path) -> Result<FilesystemLayerManifest> {
        let path = root.join(LAYER_MANIFEST_FILE);
        let source = fs::read_to_string(&path).context(SessionWorkIoSnafu {
            action: "read session-work rollback layer manifest",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeSessionWorkSnafu { path })
    }

    fn checkout_root(&self, volume_id: &str) -> PathBuf {
        self.storage
            .work_path()
            .join("session-work")
            .join("rollback")
            .join(self.selector.replace(['{', '}', '@', '.'], "_"))
            .join(volume_id)
            .join("layer")
    }
}

struct SessionWorkOverlayRestorer<'a> {
    volume: &'a FilesystemVolumeStorage,
    layer_root: &'a Path,
    manifest: &'a FilesystemLayerManifest,
}

impl<'a> SessionWorkOverlayRestorer<'a> {
    const fn new(
        volume: &'a FilesystemVolumeStorage,
        layer_root: &'a Path,
        manifest: &'a FilesystemLayerManifest,
    ) -> Self {
        Self {
            volume,
            layer_root,
            manifest,
        }
    }

    fn restore(&self) -> Result<()> {
        self.reset_upperdir()?;
        for operation in &self.manifest.operations {
            match operation {
                FilesystemLayerOperation::Create { path, entry }
                | FilesystemLayerOperation::Replace { path, entry } => {
                    self.restore_entry(path, entry)?;
                }
                FilesystemLayerOperation::Delete { path } => self.restore_delete(path)?,
                FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                    self.restore_opaque_replace(path)?;
                }
            }
        }
        self.apply_directory_metadata()
    }

    fn reset_upperdir(&self) -> Result<()> {
        let upper = self.volume.overlay().upper_path();
        if upper.exists() {
            fs::remove_dir_all(upper).context(SessionWorkIoSnafu {
                action: "remove session-work rollback upperdir",
                path: upper,
            })?;
        }
        fs::create_dir_all(upper).context(SessionWorkIoSnafu {
            action: "create session-work rollback upperdir",
            path: upper,
        })
    }

    fn restore_entry(&self, path: &str, entry: &FilesystemLayerEntry) -> Result<()> {
        let target = self.upper_path(path)?;
        match entry {
            FilesystemLayerEntry::Directory { .. } => {
                fs::create_dir_all(&target).context(SessionWorkIoSnafu {
                    action: "create session-work rollback directory",
                    path: target.as_path(),
                })?;
            }
            FilesystemLayerEntry::Regular { metadata, .. } => {
                self.copy_regular(path, &target)?;
                FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
            }
            FilesystemLayerEntry::Symlink {
                target: link,
                metadata,
            } => {
                Self::create_parent(&target)?;
                symlink(link, &target).context(SessionWorkIoSnafu {
                    action: "create session-work rollback symlink",
                    path: target.as_path(),
                })?;
                FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
            }
        }
        Ok(())
    }

    fn restore_delete(&self, path: &str) -> Result<()> {
        let marker = self.delete_marker_path(path)?;
        Self::create_parent(&marker)?;
        fs::write(&marker, []).context(SessionWorkIoSnafu {
            action: "write session-work rollback whiteout",
            path: marker.as_path(),
        })
    }

    fn restore_opaque_replace(&self, path: &str) -> Result<()> {
        let source = self.layer_file_path(path)?;
        let target = self.upper_path(path)?;
        SessionWorkTreeCopier::new(&source, &target).copy()?;
        fs::write(target.join(OPAQUE_MARKER_FILE), []).context(SessionWorkIoSnafu {
            action: "write session-work rollback opaque marker",
            path: target.as_path(),
        })
    }

    fn apply_directory_metadata(&self) -> Result<()> {
        for operation in self.manifest.operations.iter().rev() {
            let Some((path, metadata)) = Self::directory_metadata(operation) else {
                continue;
            };
            let target = self.upper_path(path)?;
            FilesystemMetadataApplier::new(&target).apply_layer_metadata(metadata)?;
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

    fn copy_regular(&self, path: &str, target: &Path) -> Result<()> {
        let source = self.layer_file_path(path)?;
        Self::create_parent(target)?;
        fs::copy(&source, target).context(SessionWorkIoSnafu {
            action: "copy session-work rollback regular file",
            path: source.as_path(),
        })?;
        Ok(())
    }

    fn upper_path(&self, value: &str) -> Result<PathBuf> {
        Ok(self
            .volume
            .overlay()
            .upper_path()
            .join(SessionWorkLayerPath::new(value)?.relative()))
    }

    fn layer_file_path(&self, value: &str) -> Result<PathBuf> {
        Ok(self
            .layer_root
            .join(FILES_DIR)
            .join(SessionWorkLayerPath::new(value)?.relative()))
    }

    fn delete_marker_path(&self, value: &str) -> Result<PathBuf> {
        let relative = SessionWorkLayerPath::new(value)?.relative();
        let file_name = relative
            .file_name()
            .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
                volume_id: self.volume.id().to_owned(),
                reason: format!("delete path `{value}` has no final component"),
                location: snafu::Location::default(),
            })?
            .to_string_lossy();
        let parent = relative.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(self
            .volume
            .overlay()
            .upper_path()
            .join(parent)
            .join(format!(".wh.{file_name}")))
    }

    fn create_parent(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(SessionWorkIoSnafu {
                action: "create session-work rollback parent",
                path: parent,
            })?;
        }
        Ok(())
    }
}

struct SessionWorkTreeCopier<'a> {
    source: &'a Path,
    target: &'a Path,
}

impl<'a> SessionWorkTreeCopier<'a> {
    const fn new(source: &'a Path, target: &'a Path) -> Self {
        Self { source, target }
    }

    fn copy(&self) -> Result<()> {
        fs::create_dir_all(self.target).context(SessionWorkIoSnafu {
            action: "create session-work rollback copied directory",
            path: self.target,
        })?;
        for entry in fs::read_dir(self.source).context(SessionWorkIoSnafu {
            action: "read session-work rollback copied directory",
            path: self.source,
        })? {
            let entry = entry.context(SessionWorkIoSnafu {
                action: "read session-work rollback copied entry",
                path: self.source,
            })?;
            SessionWorkTreeEntryCopier::new(entry.path(), self.target.join(entry.file_name()))
                .copy()?;
        }
        self.apply_source_metadata(self.source, self.target)
    }

    fn apply_source_metadata(&self, source: &Path, target: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(source).context(SessionWorkIoSnafu {
            action: "inspect session-work rollback copied metadata",
            path: source,
        })?;
        let metadata = FilesystemMetadataReader::new(source, &metadata).layer_metadata()?;
        FilesystemMetadataApplier::new(target).apply_layer_metadata(&metadata)
    }
}

struct SessionWorkTreeEntryCopier {
    source: PathBuf,
    target: PathBuf,
}

impl SessionWorkTreeEntryCopier {
    const fn new(source: PathBuf, target: PathBuf) -> Self {
        Self { source, target }
    }

    fn copy(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.source).context(SessionWorkIoSnafu {
            action: "inspect session-work rollback copied entry",
            path: self.source.as_path(),
        })?;
        if metadata.is_dir() {
            SessionWorkTreeCopier::new(&self.source, &self.target).copy()
        } else if metadata.is_file() {
            fs::copy(&self.source, &self.target).context(SessionWorkIoSnafu {
                action: "copy session-work rollback copied regular entry",
                path: self.source.as_path(),
            })?;
            SessionWorkTreeCopier::new(&self.source, &self.target)
                .apply_source_metadata(&self.source, &self.target)
        } else if metadata.file_type().is_symlink() {
            let link = fs::read_link(&self.source).context(SessionWorkIoSnafu {
                action: "read session-work rollback copied symlink",
                path: self.source.as_path(),
            })?;
            symlink(link, &self.target).context(SessionWorkIoSnafu {
                action: "copy session-work rollback copied symlink",
                path: self.target.as_path(),
            })?;
            SessionWorkTreeCopier::new(&self.source, &self.target)
                .apply_source_metadata(&self.source, &self.target)
        } else {
            UnsupportedLayerSnafu {
                volume_id: String::from("<session-work>"),
                reason: format!(
                    "session-work rollback source `{}` is special",
                    self.source.display()
                ),
            }
            .fail()
        }
    }
}

struct SessionWorkLayerPath {
    relative: PathBuf,
}

impl SessionWorkLayerPath {
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
            volume_id: String::from("<session-work>"),
            reason: format!("session-work layer path `{value}` is not a safe relative path"),
        }
        .fail()
    }
}
