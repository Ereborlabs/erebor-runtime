use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::CreateStorageDirSnafu, manifest::LAYER_MANIFEST_FILE, FilesystemVolumeMode, Result,
};

mod ostree;
mod validation;

use ostree::initialize_ostree_repo;
use validation::{validate_volume_id, validate_volume_path};

const FILESYSTEM_DIR: &str = "filesystem";
const REPO_DIR: &str = "repo";
const WORK_DIR: &str = "work";
const VOLUMES_DIR: &str = "volumes";
const LOWER_RO_DIR: &str = "lower-ro";
const OVERLAY_DIR: &str = "overlay";
const UPPER_DIR: &str = "upper";
const WORKDIR_DIR: &str = "workdir";
const MERGED_DIR: &str = "merged";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemVolumeStorageRequest {
    id: String,
    host_path: PathBuf,
    session_path: PathBuf,
    mode: FilesystemVolumeMode,
}

impl FilesystemVolumeStorageRequest {
    pub fn new(
        id: impl Into<String>,
        host_path: impl Into<PathBuf>,
        session_path: impl Into<PathBuf>,
        mode: FilesystemVolumeMode,
    ) -> Result<Self> {
        let request = Self {
            id: id.into(),
            host_path: host_path.into(),
            session_path: session_path.into(),
            mode,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        validate_volume_id(&self.id)?;
        validate_volume_path(&self.id, "host_path", &self.host_path)?;
        validate_volume_path(&self.id, "session_path", &self.session_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSessionStorage {
    root: PathBuf,
    repo_path: PathBuf,
    work_path: PathBuf,
    volumes: Vec<FilesystemVolumeStorage>,
}

impl FilesystemSessionStorage {
    pub fn prepare(
        session_dir: impl AsRef<Path>,
        volumes: impl IntoIterator<Item = FilesystemVolumeStorageRequest>,
    ) -> Result<Self> {
        let volumes = volumes.into_iter().collect();
        prepare_with_initializer(session_dir.as_ref(), volumes, initialize_ostree_repo)
    }

    pub fn open_existing(
        session_dir: impl AsRef<Path>,
        volumes: impl IntoIterator<Item = FilesystemVolumeStorageRequest>,
    ) -> Result<Self> {
        storage_plan(session_dir.as_ref(), volumes.into_iter().collect())
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    #[must_use]
    pub fn work_path(&self) -> &Path {
        &self.work_path
    }

    #[must_use]
    pub fn volumes(&self) -> &[FilesystemVolumeStorage] {
        &self.volumes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemVolumeStorage {
    id: String,
    host_path: PathBuf,
    session_path: PathBuf,
    root: PathBuf,
    lower_ro_path: PathBuf,
    overlay: FilesystemOverlayStorage,
    mode: FilesystemVolumeMode,
}

impl FilesystemVolumeStorage {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    #[must_use]
    pub fn session_path(&self) -> &Path {
        &self.session_path
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn lower_ro_path(&self) -> &Path {
        &self.lower_ro_path
    }

    #[must_use]
    pub const fn overlay(&self) -> &FilesystemOverlayStorage {
        &self.overlay
    }

    #[must_use]
    pub const fn mode(&self) -> FilesystemVolumeMode {
        self.mode
    }

    #[must_use]
    pub fn layer_manifest_path(&self) -> PathBuf {
        self.root.join(LAYER_MANIFEST_FILE)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemOverlayStorage {
    root: PathBuf,
    upper_path: PathBuf,
    workdir_path: PathBuf,
    merged_path: PathBuf,
}

impl FilesystemOverlayStorage {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn upper_path(&self) -> &Path {
        &self.upper_path
    }

    #[must_use]
    pub fn workdir_path(&self) -> &Path {
        &self.workdir_path
    }

    #[must_use]
    pub fn merged_path(&self) -> &Path {
        &self.merged_path
    }
}

pub(crate) fn prepare_with_initializer(
    session_dir: &Path,
    volumes: Vec<FilesystemVolumeStorageRequest>,
    initialize_repo: impl FnOnce(&Path) -> Result<()>,
) -> Result<FilesystemSessionStorage> {
    let storage = storage_plan(session_dir, volumes)?;
    for path in required_directories(&storage) {
        fs::create_dir_all(&path).context(CreateStorageDirSnafu { path })?;
    }
    initialize_repo(&storage.repo_path)?;
    Ok(storage)
}

fn storage_plan(
    session_dir: &Path,
    volumes: Vec<FilesystemVolumeStorageRequest>,
) -> Result<FilesystemSessionStorage> {
    let root = session_dir.join(FILESYSTEM_DIR);
    let repo_path = root.join(REPO_DIR);
    let work_path = root.join(WORK_DIR);
    let volume_root = work_path.join(VOLUMES_DIR);
    let volumes = volumes
        .into_iter()
        .map(|volume| volume_storage_plan(&volume_root, volume))
        .collect::<Result<Vec<_>>>()?;

    Ok(FilesystemSessionStorage {
        root,
        repo_path,
        work_path,
        volumes,
    })
}

fn volume_storage_plan(
    volume_root: &Path,
    volume: FilesystemVolumeStorageRequest,
) -> Result<FilesystemVolumeStorage> {
    volume.validate()?;
    let root = volume_root.join(&volume.id);
    let lower_ro_path = root.join(LOWER_RO_DIR);
    let overlay_root = root.join(OVERLAY_DIR);
    let overlay = FilesystemOverlayStorage {
        root: overlay_root.clone(),
        upper_path: overlay_root.join(UPPER_DIR),
        workdir_path: overlay_root.join(WORKDIR_DIR),
        merged_path: overlay_root.join(MERGED_DIR),
    };
    Ok(FilesystemVolumeStorage {
        id: volume.id,
        host_path: volume.host_path,
        session_path: volume.session_path,
        root,
        lower_ro_path,
        overlay,
        mode: volume.mode,
    })
}

fn required_directories(storage: &FilesystemSessionStorage) -> Vec<PathBuf> {
    let mut paths = vec![
        storage.repo_path.clone(),
        storage.work_path.join(VOLUMES_DIR),
    ];
    for volume in &storage.volumes {
        paths.extend([
            volume.lower_ro_path.clone(),
            volume.overlay.upper_path.clone(),
            volume.overlay.workdir_path.clone(),
            volume.overlay.merged_path.clone(),
        ]);
    }
    paths
}

#[cfg(test)]
mod tests;
