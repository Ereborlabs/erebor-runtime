use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::{ensure, ResultExt};

use crate::{
    error::{
        CreateOverlaySessionDirSnafu, InspectOverlaySessionPathSnafu,
        InvalidOverlaySessionViewSnafu, InvalidVolumePathSnafu,
    },
    FilesystemSessionStorage, FilesystemVolumeMode, FilesystemVolumeStorage, Result,
};

const HOST_MASK_DIR: &str = "host-mask";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LinuxOverlayVolumeMount {
    pub(super) volume_id: String,
    pub(super) host_path: String,
    pub(super) session_path: String,
    pub(super) lower_ro_path: String,
    pub(super) upper_path: String,
    pub(super) workdir_path: String,
    pub(super) merged_path: String,
    pub(super) mask_path: String,
    pub(super) read_only: bool,
}

pub(super) struct LinuxOverlaySessionPlanner<'a> {
    storage: &'a FilesystemSessionStorage,
    storage_root: PathBuf,
}

impl<'a> LinuxOverlaySessionPlanner<'a> {
    pub(super) fn new(storage: &'a FilesystemSessionStorage) -> Result<Self> {
        let storage_root = LinuxOverlayMountPath::new("storage", "root", storage.root())
            .canonical_existing_dir()?;
        Ok(Self {
            storage,
            storage_root,
        })
    }

    pub(super) fn prepare_mounts(&self) -> Result<Vec<LinuxOverlayVolumeMount>> {
        let mounts = self
            .storage
            .volumes()
            .iter()
            .map(|volume| LinuxOverlayMountPlan::new(volume, &self.storage_root).prepare())
            .collect::<Result<Vec<_>>>()?;
        LinuxOverlayMountIsolation::new(&mounts).validate()?;
        Ok(mounts)
    }
}

struct LinuxOverlayMountPlan<'a> {
    volume: &'a FilesystemVolumeStorage,
    storage_root: &'a Path,
}

impl<'a> LinuxOverlayMountPlan<'a> {
    const fn new(volume: &'a FilesystemVolumeStorage, storage_root: &'a Path) -> Self {
        Self {
            volume,
            storage_root,
        }
    }

    fn prepare(&self) -> Result<LinuxOverlayVolumeMount> {
        fs::create_dir_all(self.volume.session_path()).context(CreateOverlaySessionDirSnafu {
            volume_id: self.volume.id().to_owned(),
            path: self.volume.session_path(),
        })?;
        let mask_path = self.volume.root().join(HOST_MASK_DIR);
        fs::create_dir_all(&mask_path).context(CreateOverlaySessionDirSnafu {
            volume_id: self.volume.id().to_owned(),
            path: &mask_path,
        })?;

        let host_path = self.canonical_volume_dir("host_path", self.volume.host_path())?;
        let session_path = self.canonical_volume_dir("session_path", self.volume.session_path())?;
        self.ensure_safe_mount_pair(&host_path, &session_path)?;

        Ok(LinuxOverlayVolumeMount {
            volume_id: self.volume.id().to_owned(),
            host_path: self.mount_path_text("host_path", &host_path)?,
            session_path: self.mount_path_text("session_path", &session_path)?,
            lower_ro_path: self.mount_path_text(
                "lower_ro_path",
                &self.canonical_volume_dir("lower_ro_path", self.volume.lower_ro_path())?,
            )?,
            upper_path: self.mount_path_text(
                "upper_path",
                &self.canonical_volume_dir("upper_path", self.volume.overlay().upper_path())?,
            )?,
            workdir_path: self.mount_path_text(
                "workdir_path",
                &self.canonical_volume_dir("workdir_path", self.volume.overlay().workdir_path())?,
            )?,
            merged_path: self.mount_path_text(
                "merged_path",
                &self.canonical_volume_dir("merged_path", self.volume.overlay().merged_path())?,
            )?,
            mask_path: self.mount_path_text(
                "mask_path",
                &self.canonical_volume_dir("mask_path", &mask_path)?,
            )?,
            read_only: self.volume.mode() == FilesystemVolumeMode::ReadOnly,
        })
    }

    fn canonical_volume_dir(&self, field: &'static str, path: &Path) -> Result<PathBuf> {
        LinuxOverlayMountPath::new(self.volume.id(), field, path).canonical_existing_dir()
    }

    fn ensure_safe_mount_pair(&self, host_path: &Path, session_path: &Path) -> Result<()> {
        self.ensure_not_root("host_path", host_path)?;
        self.ensure_not_root("session_path", session_path)?;
        ensure!(
            !LinuxOverlayMountIsolation::paths_overlap(host_path, session_path),
            InvalidOverlaySessionViewSnafu {
                volume_id: self.volume.id().to_owned(),
                reason: format!(
                    "host_path `{}` and session_path `{}` must not overlap",
                    host_path.display(),
                    session_path.display()
                )
            }
        );
        ensure!(
            !LinuxOverlayMountIsolation::paths_overlap(host_path, self.storage_root),
            InvalidOverlaySessionViewSnafu {
                volume_id: self.volume.id().to_owned(),
                reason: format!(
                    "host_path `{}` must not overlap storage root `{}`",
                    host_path.display(),
                    self.storage_root.display()
                )
            }
        );
        Ok(())
    }

    fn ensure_not_root(&self, field: &'static str, path: &Path) -> Result<()> {
        ensure!(
            path.parent().is_some(),
            InvalidVolumePathSnafu {
                volume_id: self.volume.id().to_owned(),
                field,
                path: path.to_path_buf(),
                reason: String::from("path cannot be the filesystem root")
            }
        );
        Ok(())
    }

    fn mount_path_text(&self, field: &'static str, path: &Path) -> Result<String> {
        LinuxOverlayMountPath::new(self.volume.id(), field, path).shell_text()
    }
}

struct LinuxOverlayMountPath<'a> {
    volume_id: &'a str,
    field: &'static str,
    path: &'a Path,
}

impl<'a> LinuxOverlayMountPath<'a> {
    const fn new(volume_id: &'a str, field: &'static str, path: &'a Path) -> Self {
        Self {
            volume_id,
            field,
            path,
        }
    }

    fn canonical_existing_dir(&self) -> Result<PathBuf> {
        let path = fs::canonicalize(self.path).context(InspectOverlaySessionPathSnafu {
            volume_id: self.volume_id.to_owned(),
            field: self.field,
            path: self.path,
        })?;
        ensure!(
            path.is_dir(),
            InvalidVolumePathSnafu {
                volume_id: self.volume_id.to_owned(),
                field: self.field,
                path: path.clone(),
                reason: String::from("path must resolve to a directory")
            }
        );
        Ok(path)
    }

    fn shell_text(&self) -> Result<String> {
        let path = self
            .path
            .to_str()
            .ok_or_else(|| crate::FilesystemError::InvalidVolumePath {
                volume_id: self.volume_id.to_owned(),
                field: self.field,
                path: self.path.to_path_buf(),
                reason: String::from("path must be valid UTF-8 for the shell overlay wrapper"),
                location: snafu::Location::default(),
            })?
            .to_owned();
        ensure!(
            !path.contains(',') && !path.contains('\n'),
            InvalidVolumePathSnafu {
                volume_id: self.volume_id.to_owned(),
                field: self.field,
                path: PathBuf::from(&path),
                reason: String::from("path cannot contain comma or newline")
            }
        );
        Ok(path)
    }
}

struct LinuxOverlayMountIsolation<'a> {
    mounts: &'a [LinuxOverlayVolumeMount],
}

impl<'a> LinuxOverlayMountIsolation<'a> {
    const fn new(mounts: &'a [LinuxOverlayVolumeMount]) -> Self {
        Self { mounts }
    }

    fn validate(&self) -> Result<()> {
        for (index, current) in self.mounts.iter().enumerate() {
            for other in self.mounts.iter().skip(index + 1) {
                Self::validate_pair(current, other)?;
            }
        }
        Ok(())
    }

    fn validate_pair(
        current: &LinuxOverlayVolumeMount,
        other: &LinuxOverlayVolumeMount,
    ) -> Result<()> {
        for (current_field, current_path) in [
            ("host_path", current.host_path.as_str()),
            ("session_path", current.session_path.as_str()),
        ] {
            for (other_field, other_path) in [
                ("host_path", other.host_path.as_str()),
                ("session_path", other.session_path.as_str()),
            ] {
                ensure!(
                    !Self::paths_overlap(Path::new(current_path), Path::new(other_path)),
                    InvalidOverlaySessionViewSnafu {
                        volume_id: current.volume_id.clone(),
                        reason: format!(
                            "{current_field} `{current_path}` overlaps volume `{}` {other_field} `{other_path}`",
                            other.volume_id
                        )
                    }
                );
            }
        }
        Ok(())
    }

    fn paths_overlap(first: &Path, second: &Path) -> bool {
        first == second || first.starts_with(second) || second.starts_with(first)
    }
}
