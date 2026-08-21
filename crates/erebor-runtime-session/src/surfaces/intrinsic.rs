use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

use erebor_runtime_core::{
    FilesystemProjection, PreparedPrivateStateProjection, PreparedWritableFilesystemView,
    PrivateStateProjection, SafePathBinding, SafePathKind, SessionSpec,
};
use erebor_runtime_filesystem::{
    FilesystemSessionStorage, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};
use rustix::{
    fs::{makedev, openat2, statx, AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags},
    io::Errno,
    process::{Gid, Uid},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use snafu::ResultExt;
use users::os::unix::UserExt;

use crate::{
    error::session_manager::{RuntimeFilesystemSnafu, RuntimeIoSnafu},
    ResolvedSessionPath, SessionManagerError, SessionPathResolver,
};

const CODEX_STATE_DIRECTORY: &str = ".codex";
const STATE_VOLUME_ID: &str = "agent-state";
const CALLER_SOURCE_VOLUME_PREFIX: &str = "caller-source-";
const PRIVATE_FILE_SOURCE_NAME: &str = "source";
const SNAPSHOT_MANIFEST: &str = "state-snapshot-manifest.json";

/// Daemon-long-lived realization of the intrinsic `filesystem` Surface.
///
/// It preserves the existing per-Session `FilesystemSessionStorage` layout and
/// OSTree repository. A Session owns the returned binding/view; this runtime
/// owns only the implementation and storage policy.
pub struct LinuxOstreeOverlayFilesystemRuntime {
    state_root: PathBuf,
}

pub(crate) struct FilesystemBinding {
    storage: FilesystemSessionStorage,
    private_state_projection: Option<PreparedPrivateStateProjection>,
}

impl LinuxOstreeOverlayFilesystemRuntime {
    pub(crate) fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }

    pub(crate) fn bind(
        &self,
        spec: &SessionSpec,
        resolver: &dyn SessionPathResolver,
        recovering: bool,
    ) -> Result<Option<FilesystemBinding>, SessionManagerError> {
        let volumes = self.filesystem_volumes(spec)?;
        if volumes.is_empty() {
            return Ok(None);
        }
        let session_dir = self.session_directory(spec);
        let storage = if recovering {
            FilesystemSessionStorage::open_existing(&session_dir, volumes)
        } else {
            FilesystemSessionStorage::prepare(&session_dir, volumes)
        }
        .context(RuntimeFilesystemSnafu)?;
        let private_state_projection = if let Some(projection) = spec.private_state_projection() {
            let state_volume = self.volume(&storage, STATE_VOLUME_ID, spec)?;
            if recovering {
                self.require_existing_private_state_view(spec, &storage, state_volume)?;
            } else {
                self.snapshot_codex_state(
                    spec,
                    resolver,
                    projection,
                    storage.root(),
                    state_volume.lower_ro_path(),
                )?;
                self.prepare_writable_overlay(spec, state_volume)?;
            }
            Some(PreparedPrivateStateProjection::new(
                state_volume.lower_ro_path().to_path_buf(),
                state_volume.overlay().upper_path().to_path_buf(),
                state_volume.overlay().workdir_path().to_path_buf(),
                state_volume.overlay().merged_path().to_path_buf(),
                projection.target().to_path_buf(),
            ))
        } else {
            None
        };
        for (index, filesystem_projection) in spec.filesystem_projections().iter().enumerate() {
            if !Self::requires_writable_session_view(filesystem_projection) {
                continue;
            }
            let volume = self.volume(&storage, &Self::caller_source_volume_id(index), spec)?;
            if recovering {
                self.require_existing_caller_source_view(spec, volume, filesystem_projection)?;
            } else {
                self.prepare_writable_overlay(spec, volume)?;
                if filesystem_projection.source().kind() == SafePathKind::File {
                    self.copy_writable_file_source(
                        spec,
                        resolver,
                        filesystem_projection,
                        &volume
                            .overlay()
                            .merged_path()
                            .join(PRIVATE_FILE_SOURCE_NAME),
                    )?;
                }
            }
        }
        Ok(Some(FilesystemBinding {
            storage,
            private_state_projection,
        }))
    }

    /// Removes only the mutable session views when a Session is removed.
    /// The repository, lower snapshots, and manifests remain available to the
    /// daemon's retained evidence; caller sources are never touched.
    pub(crate) fn discard_writable_view(
        &self,
        spec: &SessionSpec,
    ) -> Result<(), SessionManagerError> {
        let volumes = self.filesystem_volumes(spec)?;
        if volumes.is_empty() {
            return Ok(());
        }
        let session_dir = self.session_directory(spec);
        let storage = FilesystemSessionStorage::open_existing(&session_dir, volumes)
            .context(RuntimeFilesystemSnafu)?;
        for volume in storage.volumes() {
            if volume.mode() != FilesystemVolumeMode::Writable {
                continue;
            }
            for path in [
                volume.overlay().upper_path(),
                volume.overlay().workdir_path(),
                volume.overlay().merged_path(),
            ] {
                match fs::remove_dir_all(path) {
                    Ok(()) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(source).context(RuntimeIoSnafu {
                            action: "discarding removed session's writable filesystem view",
                            path,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Opens the existing per-Session storage owned by this intrinsic Surface.
    /// A caller receives no path input: the immutable admitted projections fix
    /// the one storage plan for the Session.
    pub(crate) fn open_storage(
        &self,
        spec: &SessionSpec,
    ) -> Result<Option<FilesystemSessionStorage>, SessionManagerError> {
        let volumes = self.filesystem_volumes(spec)?;
        if volumes.is_empty() {
            return Ok(None);
        }
        let session_dir = self.session_directory(spec);
        FilesystemSessionStorage::open_existing(&session_dir, volumes)
            .context(RuntimeFilesystemSnafu)
            .map(Some)
    }

    fn filesystem_volumes(
        &self,
        spec: &SessionSpec,
    ) -> Result<Vec<FilesystemVolumeStorageRequest>, SessionManagerError> {
        let session_dir = self.session_directory(spec);
        let mut volumes = Vec::new();
        if let Some(projection) = spec.private_state_projection() {
            volumes.push(self.private_state_volume(&session_dir, projection)?);
        }
        for (index, projection) in spec.filesystem_projections().iter().enumerate() {
            if Self::requires_writable_session_view(projection) {
                volumes.push(self.caller_source_volume(index, projection)?);
            }
        }
        Ok(volumes)
    }

    fn requires_writable_session_view(projection: &FilesystemProjection) -> bool {
        !projection.read_only() && projection.target().session_view_root().is_some()
    }

    fn caller_source_volume(
        &self,
        index: usize,
        projection: &FilesystemProjection,
    ) -> Result<FilesystemVolumeStorageRequest, SessionManagerError> {
        FilesystemVolumeStorageRequest::new(
            Self::caller_source_volume_id(index),
            projection.source().requested_path().to_path_buf(),
            projection.workload_path().to_path_buf(),
            FilesystemVolumeMode::Writable,
        )
        .context(RuntimeFilesystemSnafu)
    }

    fn caller_source_volume_id(index: usize) -> String {
        format!("{CALLER_SOURCE_VOLUME_PREFIX}{index}")
    }

    fn volume<'a>(
        &self,
        storage: &'a FilesystemSessionStorage,
        id: &str,
        spec: &SessionSpec,
    ) -> Result<&'a erebor_runtime_filesystem::FilesystemVolumeStorage, SessionManagerError> {
        storage
            .volumes()
            .iter()
            .find(|volume| volume.id() == id)
            .ok_or_else(|| SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!("filesystem binding has no `{id}` volume"),
                location: snafu::Location::default(),
            })
    }

    fn private_state_volume(
        &self,
        session_dir: &Path,
        projection: &PrivateStateProjection,
    ) -> Result<FilesystemVolumeStorageRequest, SessionManagerError> {
        FilesystemVolumeStorageRequest::new(
            STATE_VOLUME_ID,
            session_dir
                .join("filesystem/work/volumes")
                .join(STATE_VOLUME_ID)
                .join("lower-ro"),
            projection.target().to_path_buf(),
            FilesystemVolumeMode::Writable,
        )
        .context(RuntimeFilesystemSnafu)
    }

    fn session_directory(&self, spec: &SessionSpec) -> PathBuf {
        self.state_root
            .join("users")
            .join(spec.owner().uid().to_string())
            .join("sessions")
            .join(spec.session_id().as_str())
    }

    fn snapshot_codex_state(
        &self,
        spec: &SessionSpec,
        resolver: &dyn SessionPathResolver,
        projection: &PrivateStateProjection,
        storage_root: &Path,
        lower: &Path,
    ) -> Result<(), SessionManagerError> {
        let home_path = codex_home_directory(spec.owner().uid())?;
        let source_path = home_path.join(CODEX_STATE_DIRECTORY);
        let home = resolver
            .resolve(
                spec.owner().uid(),
                spec.owner().gid(),
                &home_path,
                SafePathKind::Directory,
            )
            .map_err(|source| SessionManagerError::PathResolution {
                uid: spec.owner().uid(),
                gid: spec.owner().gid(),
                path: home_path,
                source,
                location: snafu::Location::default(),
            })?;
        if home.binding().owner_uid() != spec.owner().uid() {
            return self.invalid_runtime(
                spec,
                "the resolved Codex home directory is not owned by the session UID",
            );
        }
        let source = self.resolve_codex_state_source(spec, &home, source_path)?;
        self.clear_directory(lower)?;
        let manifest = StateSnapshotManifest::from_source(
            source.as_ref(),
            lower,
            spec.session_id().as_str(),
            projection.lower_snapshot().to_owned(),
        )?;
        self.chown_tree(spec, lower)?;
        self.write_manifest(storage_root, &manifest)
    }

    fn resolve_codex_state_source(
        &self,
        spec: &SessionSpec,
        home: &ResolvedSessionPath,
        source_path: PathBuf,
    ) -> Result<Option<ResolvedSessionPath>, SessionManagerError> {
        let descriptor = match openat2(
            home.descriptor(),
            CODEX_STATE_DIRECTORY,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(descriptor) => File::from(descriptor),
            Err(Errno::NOENT) => return Ok(None),
            Err(source) => {
                return Err(std::io::Error::from(source)).context(RuntimeIoSnafu {
                    action: "resolving private Codex state beneath the held caller home",
                    path: &source_path,
                });
            }
        };
        let status = statx(
            &descriptor,
            "",
            AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "observing held private Codex state identity",
            path: &source_path,
        })?;
        if !FileType::from_raw_mode(status.stx_mode.into()).is_dir() {
            return self.invalid_runtime(
                spec,
                "the caller's private Codex state path is not a directory",
            );
        }
        if status.stx_uid != spec.owner().uid() {
            return self.invalid_runtime(
                spec,
                "the resolved Codex state source is not owned by the session UID",
            );
        }
        let binding = SafePathBinding::new(
            source_path,
            makedev(status.stx_dev_major, status.stx_dev_minor),
            status.stx_ino,
            status.stx_mnt_id,
            status.stx_uid,
            status.stx_gid,
            SafePathKind::Directory,
        )
        .map_err(|source| SessionManagerError::InvalidRuntime {
            session_id: spec.session_id().as_str().to_owned(),
            reason: format!("private Codex state identity is invalid: {source}"),
            location: snafu::Location::default(),
        })?;
        Ok(Some(ResolvedSessionPath::new(descriptor, binding)))
    }

    fn prepare_writable_overlay(
        &self,
        spec: &SessionSpec,
        state_volume: &erebor_runtime_filesystem::FilesystemVolumeStorage,
    ) -> Result<(), SessionManagerError> {
        for path in [
            state_volume.overlay().upper_path(),
            state_volume.overlay().workdir_path(),
            state_volume.overlay().merged_path(),
        ] {
            self.clear_directory(path)?;
            self.chown_tree(spec, path)?;
        }
        Ok(())
    }

    fn require_existing_private_state_view(
        &self,
        spec: &SessionSpec,
        storage: &FilesystemSessionStorage,
        state_volume: &erebor_runtime_filesystem::FilesystemVolumeStorage,
    ) -> Result<(), SessionManagerError> {
        for path in [
            storage.root().join(SNAPSHOT_MANIFEST),
            state_volume.lower_ro_path().to_path_buf(),
            state_volume.overlay().upper_path().to_path_buf(),
            state_volume.overlay().workdir_path().to_path_buf(),
            state_volume.overlay().merged_path().to_path_buf(),
        ] {
            let metadata = fs::symlink_metadata(&path).context(RuntimeIoSnafu {
                action: "opening recovered filesystem binding view",
                path: &path,
            })?;
            let is_manifest = path
                .file_name()
                .is_some_and(|name| name == SNAPSHOT_MANIFEST);
            if metadata.file_type().is_symlink()
                || (is_manifest && !metadata.is_file())
                || (!is_manifest && !metadata.is_dir())
            {
                return self.invalid_runtime(
                    spec,
                    format!("recovered filesystem view `{}` is unsafe", path.display()),
                );
            }
        }
        Ok(())
    }

    fn require_existing_caller_source_view(
        &self,
        spec: &SessionSpec,
        volume: &erebor_runtime_filesystem::FilesystemVolumeStorage,
        projection: &FilesystemProjection,
    ) -> Result<(), SessionManagerError> {
        for path in [
            volume.overlay().upper_path().to_path_buf(),
            volume.overlay().workdir_path().to_path_buf(),
            volume.overlay().merged_path().to_path_buf(),
        ] {
            let metadata = fs::symlink_metadata(&path).context(RuntimeIoSnafu {
                action: "opening recovered caller-source filesystem view",
                path: &path,
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return self.invalid_runtime(
                    spec,
                    format!(
                        "recovered caller-source view `{}` is unsafe",
                        path.display()
                    ),
                );
            }
        }
        if projection.source().kind() == SafePathKind::File {
            let source = volume
                .overlay()
                .merged_path()
                .join(PRIVATE_FILE_SOURCE_NAME);
            let metadata = fs::symlink_metadata(&source).context(RuntimeIoSnafu {
                action: "opening recovered writable caller-source file view",
                path: &source,
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return self.invalid_runtime(
                    spec,
                    format!(
                        "recovered writable caller-source file view `{}` is unsafe",
                        source.display()
                    ),
                );
            }
        }
        Ok(())
    }

    fn copy_writable_file_source(
        &self,
        spec: &SessionSpec,
        resolver: &dyn SessionPathResolver,
        projection: &FilesystemProjection,
        target: &Path,
    ) -> Result<(), SessionManagerError> {
        let source = resolver
            .resolve(
                spec.owner().uid(),
                spec.owner().gid(),
                projection.source().requested_path(),
                SafePathKind::File,
            )
            .map_err(|source| SessionManagerError::PathResolution {
                uid: spec.owner().uid(),
                gid: spec.owner().gid(),
                path: projection.source().requested_path().to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        if source.binding() != projection.source() {
            return self.invalid_runtime(
                spec,
                "writable caller-source file identity changed after session admission",
            );
        }
        copy_file_from_descriptor(
            source.descriptor(),
            target,
            spec.owner().uid(),
            spec.owner().gid(),
        )
    }

    fn clear_directory(&self, path: &Path) -> Result<(), SessionManagerError> {
        match fs::remove_dir_all(path) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(RuntimeIoSnafu {
                    action: "clearing daemon-owned filesystem state directory",
                    path,
                });
            }
        }
        fs::create_dir_all(path).context(RuntimeIoSnafu {
            action: "creating daemon-owned filesystem state directory",
            path,
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).context(RuntimeIoSnafu {
            action: "protecting daemon-owned filesystem state directory",
            path,
        })
    }

    fn write_manifest(
        &self,
        storage_root: &Path,
        manifest: &StateSnapshotManifest,
    ) -> Result<(), SessionManagerError> {
        let path = storage_root.join(SNAPSHOT_MANIFEST);
        let encoded =
            serde_json::to_vec(manifest).map_err(|source| SessionManagerError::InvalidRuntime {
                session_id: manifest.session_id.clone(),
                reason: format!("encoding private state snapshot manifest failed: {source}"),
                location: snafu::Location::default(),
            })?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .context(RuntimeIoSnafu {
                action: "writing private state snapshot manifest",
                path: &path,
            })?;
        file.write_all(&encoded).context(RuntimeIoSnafu {
            action: "writing private state snapshot manifest",
            path: &path,
        })?;
        file.sync_all().context(RuntimeIoSnafu {
            action: "syncing private state snapshot manifest",
            path: &path,
        })
    }

    fn chown_tree(&self, spec: &SessionSpec, root: &Path) -> Result<(), SessionManagerError> {
        let descriptor = File::open(root).context(RuntimeIoSnafu {
            action: "opening private state view for ownership assignment",
            path: root,
        })?;
        copy_tree_ownership(&descriptor, spec.owner().uid(), spec.owner().gid(), root)
    }

    fn invalid_runtime<T>(
        &self,
        spec: &SessionSpec,
        reason: impl Into<String>,
    ) -> Result<T, SessionManagerError> {
        Err(SessionManagerError::InvalidRuntime {
            session_id: spec.session_id().as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        })
    }
}

impl FilesystemBinding {
    pub(crate) fn private_state_projection(&self) -> Option<PreparedPrivateStateProjection> {
        self.private_state_projection.as_ref().map(|projection| {
            debug_assert!(projection.lower().starts_with(self.storage.root()));
            debug_assert!(projection.upper().starts_with(self.storage.root()));
            debug_assert!(projection.workdir().starts_with(self.storage.root()));
            debug_assert!(projection.merged().starts_with(self.storage.root()));
            projection.clone()
        })
    }

    pub(crate) fn writable_projection_view(
        &self,
        spec: &SessionSpec,
        index: usize,
    ) -> Result<Option<PreparedWritableFilesystemView>, SessionManagerError> {
        let projection = spec.filesystem_projections().get(index).ok_or_else(|| {
            SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!("filesystem projection index {index} is unavailable"),
                location: snafu::Location::default(),
            }
        })?;
        if !LinuxOstreeOverlayFilesystemRuntime::requires_writable_session_view(projection) {
            return Ok(None);
        }
        let volume = self
            .storage
            .volumes()
            .iter()
            .find(|volume| {
                volume.id() == LinuxOstreeOverlayFilesystemRuntime::caller_source_volume_id(index)
            })
            .ok_or_else(|| SessionManagerError::InvalidRuntime {
                session_id: spec.session_id().as_str().to_owned(),
                reason: format!("filesystem binding has no caller-source-{index} volume"),
                location: snafu::Location::default(),
            })?;
        let view = match projection.source().kind() {
            SafePathKind::Directory => PreparedWritableFilesystemView::overlay(
                volume.root().to_path_buf(),
                volume.overlay().upper_path().to_path_buf(),
                volume.overlay().workdir_path().to_path_buf(),
            ),
            SafePathKind::File => PreparedWritableFilesystemView::private_file(
                volume.root().to_path_buf(),
                volume
                    .overlay()
                    .merged_path()
                    .join(PRIVATE_FILE_SOURCE_NAME),
            ),
            SafePathKind::Executable => {
                return Err(SessionManagerError::InvalidRuntime {
                    session_id: spec.session_id().as_str().to_owned(),
                    reason: String::from(
                        "a writable caller-source projection cannot be an executable",
                    ),
                    location: snafu::Location::default(),
                });
            }
        };
        Ok(Some(view))
    }
}

#[derive(Serialize)]
struct StateSnapshotManifest {
    session_id: String,
    lower_snapshot: String,
    source: StateSnapshotSource,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StateSnapshotSource {
    Absent,
    Existing {
        device: u64,
        inode: u64,
        mount_id: u64,
        owner_uid: u32,
        owner_gid: u32,
        content_sha256: String,
    },
}

impl StateSnapshotManifest {
    fn from_source(
        source: Option<&ResolvedSessionPath>,
        lower: &Path,
        session_id: &str,
        lower_snapshot: String,
    ) -> Result<Self, SessionManagerError> {
        let mut digest = Sha256::new();
        let source = if let Some(source) = source {
            copy_directory_from_descriptor(source.descriptor(), lower, &mut digest)?;
            let binding = source.binding();
            StateSnapshotSource::Existing {
                device: binding.device(),
                inode: binding.inode(),
                mount_id: binding.mount_id(),
                owner_uid: binding.owner_uid(),
                owner_gid: binding.owner_gid(),
                content_sha256: format!("{:x}", digest.finalize()),
            }
        } else {
            StateSnapshotSource::Absent
        };
        Ok(Self {
            session_id: session_id.to_owned(),
            lower_snapshot,
            source,
        })
    }
}

fn codex_home_directory(uid: u32) -> Result<PathBuf, SessionManagerError> {
    let home = users::get_user_by_uid(uid)
        .map(|user| user.home_dir().to_path_buf())
        .ok_or_else(|| SessionManagerError::InvalidRuntime {
            session_id: String::from("private-state-source"),
            reason: format!("could not resolve a home directory for UID {uid}"),
            location: snafu::Location::default(),
        })?;
    if !home.is_absolute() {
        return Err(SessionManagerError::InvalidRuntime {
            session_id: String::from("private-state-source"),
            reason: format!("the home directory for UID {uid} is not absolute"),
            location: snafu::Location::default(),
        });
    }
    Ok(home)
}

fn copy_directory_from_descriptor(
    source: &File,
    destination: &Path,
    digest: &mut Sha256,
) -> Result<(), SessionManagerError> {
    let source_path = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
    let mut names = fs::read_dir(&source_path)
        .context(RuntimeIoSnafu {
            action: "enumerating held private state source",
            path: &source_path,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|source| SessionManagerError::RuntimeIo {
                    action: "enumerating held private state source",
                    path: source_path.clone(),
                    source,
                    location: snafu::Location::default(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        copy_directory_entry(source, &name, destination, digest)?;
    }
    Ok(())
}

fn copy_file_from_descriptor(
    source: &File,
    target: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), SessionManagerError> {
    let source_path = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
    let mut source_file = File::open(&source_path).context(RuntimeIoSnafu {
        action: "opening held writable caller-source file",
        path: &source_path,
    })?;
    let metadata = source_file.metadata().context(RuntimeIoSnafu {
        action: "observing held writable caller-source file",
        path: &source_path,
    })?;
    if !metadata.is_file() {
        return Err(SessionManagerError::InvalidRuntime {
            session_id: String::from("writable-caller-source"),
            reason: format!(
                "writable caller-source `{}` is not a regular file",
                source_path.display()
            ),
            location: snafu::Location::default(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    let mut target_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(target)
        .context(RuntimeIoSnafu {
            action: "creating private writable caller-source file view",
            path: target,
        })?;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = source_file.read(&mut buffer).context(RuntimeIoSnafu {
            action: "reading held writable caller-source file",
            path: &source_path,
        })?;
        if count == 0 {
            break;
        }
        target_file
            .write_all(&buffer[..count])
            .context(RuntimeIoSnafu {
                action: "writing private writable caller-source file view",
                path: target,
            })?;
    }
    target_file.sync_all().context(RuntimeIoSnafu {
        action: "syncing private writable caller-source file view",
        path: target,
    })?;
    rustix::fs::chown(
        target,
        Some(Uid::from_raw(owner_uid)),
        Some(Gid::from_raw(owner_gid)),
    )
    .map_err(std::io::Error::from)
    .context(RuntimeIoSnafu {
        action: "assigning private writable caller-source file ownership",
        path: target,
    })?;
    Ok(())
}

fn copy_directory_entry(
    source: &File,
    name: &OsString,
    destination: &Path,
    digest: &mut Sha256,
) -> Result<(), SessionManagerError> {
    let descriptor = openat2(
        source,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .context(RuntimeIoSnafu {
        action: "opening private state source entry without symlinks",
        path: destination.join(name),
    })?;
    let status = statx(
        &descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS,
    )
    .map_err(std::io::Error::from)
    .context(RuntimeIoSnafu {
        action: "observing private state source entry",
        path: destination.join(name),
    })?;
    let target = destination.join(name);
    let file_type = FileType::from_raw_mode(status.stx_mode.into());
    digest.update(name.as_bytes());
    if file_type.is_dir() {
        fs::create_dir(&target).context(RuntimeIoSnafu {
            action: "creating private state snapshot directory",
            path: &target,
        })?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).context(
            RuntimeIoSnafu {
                action: "protecting private state snapshot directory",
                path: &target,
            },
        )?;
        copy_directory_from_descriptor(&descriptor, &target, digest)?;
        return Ok(());
    }
    if !file_type.is_file() {
        return Err(SessionManagerError::InvalidRuntime {
            session_id: String::from("private-state-snapshot"),
            reason: format!(
                "private state source entry `{}` is not a regular file or directory",
                target.display()
            ),
            location: snafu::Location::default(),
        });
    }
    let mut target_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&target)
        .context(RuntimeIoSnafu {
            action: "creating private state snapshot file",
            path: &target,
        })?;
    let mut source_file = descriptor;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = source_file.read(&mut buffer).context(RuntimeIoSnafu {
            action: "reading private state source file",
            path: &target,
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        target_file
            .write_all(&buffer[..count])
            .context(RuntimeIoSnafu {
                action: "writing private state snapshot file",
                path: &target,
            })?;
    }
    target_file.sync_all().context(RuntimeIoSnafu {
        action: "syncing private state snapshot file",
        path: &target,
    })
}

fn copy_tree_ownership(
    directory: &File,
    uid: u32,
    gid: u32,
    path: &Path,
) -> Result<(), SessionManagerError> {
    rustix::fs::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(std::io::Error::from)
        .context(RuntimeIoSnafu {
            action: "assigning private state view ownership",
            path,
        })?;
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    for entry in fs::read_dir(&descriptor_path).context(RuntimeIoSnafu {
        action: "enumerating daemon-owned private state view",
        path,
    })? {
        let entry = entry.context(RuntimeIoSnafu {
            action: "enumerating daemon-owned private state view",
            path,
        })?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).context(RuntimeIoSnafu {
            action: "observing daemon-owned private state view entry",
            path: &child,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SessionManagerError::InvalidRuntime {
                session_id: String::from("private-state-view"),
                reason: format!(
                    "daemon-owned private state view contains symlink `{}`",
                    child.display()
                ),
                location: snafu::Location::default(),
            });
        }
        rustix::fs::chown(&child, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .map_err(std::io::Error::from)
            .context(RuntimeIoSnafu {
                action: "assigning private state view ownership",
                path: &child,
            })?;
        if metadata.is_dir() {
            let child_descriptor = File::open(&child).context(RuntimeIoSnafu {
                action: "opening daemon-owned private state view directory",
                path: &child,
            })?;
            copy_tree_ownership(&child_descriptor, uid, gid, &child)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, path::Path};

    use rustix::process::{getgid, getuid};

    use super::{copy_file_from_descriptor, StateSnapshotManifest};

    #[test]
    fn absent_caller_state_is_recorded_as_an_empty_initial_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manifest = StateSnapshotManifest::from_source(
            None,
            Path::new("/daemon-owned/lower"),
            "session-1",
            String::from("session-1-state"),
        )?;
        let encoded = serde_json::to_value(manifest)?;
        assert_eq!(encoded["source"]["kind"], "absent");
        assert_eq!(encoded["lower_snapshot"], "session-1-state");
        Ok(())
    }

    #[test]
    fn writable_file_source_is_copied_into_its_private_session_view(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        let target = temporary.path().join("target");
        fs::write(&source, "caller-content")?;
        let source_file = File::open(&source)?;

        copy_file_from_descriptor(&source_file, &target, getuid().as_raw(), getgid().as_raw())?;
        fs::write(&target, "session-content")?;

        assert_eq!(fs::read_to_string(&source)?, "caller-content");
        assert_eq!(fs::read_to_string(&target)?, "session-content");
        Ok(())
    }
}
