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

pub(super) fn prepare_mounts(
    storage: &FilesystemSessionStorage,
) -> Result<Vec<LinuxOverlayVolumeMount>> {
    let storage_root = canonical_existing_dir("storage", "root", storage.root())?;
    let mounts = storage
        .volumes()
        .iter()
        .map(|volume| prepare_volume_mount(volume, &storage_root))
        .collect::<Result<Vec<_>>>()?;
    validate_mount_isolation(&mounts)?;
    Ok(mounts)
}

fn prepare_volume_mount(
    volume: &FilesystemVolumeStorage,
    storage_root: &Path,
) -> Result<LinuxOverlayVolumeMount> {
    fs::create_dir_all(volume.session_path()).context(CreateOverlaySessionDirSnafu {
        volume_id: volume.id().to_owned(),
        path: volume.session_path(),
    })?;
    let mask_path = volume.root().join(HOST_MASK_DIR);
    fs::create_dir_all(&mask_path).context(CreateOverlaySessionDirSnafu {
        volume_id: volume.id().to_owned(),
        path: &mask_path,
    })?;

    let host_path = canonical_volume_dir(volume.id(), "host_path", volume.host_path())?;
    let session_path = canonical_volume_dir(volume.id(), "session_path", volume.session_path())?;
    ensure_safe_mount_pair(volume.id(), &host_path, &session_path, storage_root)?;

    Ok(LinuxOverlayVolumeMount {
        volume_id: volume.id().to_owned(),
        host_path: mount_path_text(volume.id(), "host_path", &host_path)?,
        session_path: mount_path_text(volume.id(), "session_path", &session_path)?,
        lower_ro_path: mount_path_text(
            volume.id(),
            "lower_ro_path",
            &canonical_volume_dir(volume.id(), "lower_ro_path", volume.lower_ro_path())?,
        )?,
        upper_path: mount_path_text(
            volume.id(),
            "upper_path",
            &canonical_volume_dir(volume.id(), "upper_path", volume.overlay().upper_path())?,
        )?,
        workdir_path: mount_path_text(
            volume.id(),
            "workdir_path",
            &canonical_volume_dir(volume.id(), "workdir_path", volume.overlay().workdir_path())?,
        )?,
        merged_path: mount_path_text(
            volume.id(),
            "merged_path",
            &canonical_volume_dir(volume.id(), "merged_path", volume.overlay().merged_path())?,
        )?,
        mask_path: mount_path_text(
            volume.id(),
            "mask_path",
            &canonical_volume_dir(volume.id(), "mask_path", &mask_path)?,
        )?,
        read_only: volume.mode() == FilesystemVolumeMode::ReadOnly,
    })
}

fn canonical_existing_dir(volume_id: &str, field: &'static str, path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(path).context(InspectOverlaySessionPathSnafu {
        volume_id: volume_id.to_owned(),
        field,
        path,
    })?;
    ensure!(
        path.is_dir(),
        InvalidVolumePathSnafu {
            volume_id: volume_id.to_owned(),
            field,
            path: path.clone(),
            reason: String::from("path must resolve to a directory")
        }
    );
    Ok(path)
}

fn canonical_volume_dir(volume_id: &str, field: &'static str, path: &Path) -> Result<PathBuf> {
    canonical_existing_dir(volume_id, field, path)
}

fn ensure_safe_mount_pair(
    volume_id: &str,
    host_path: &Path,
    session_path: &Path,
    storage_root: &Path,
) -> Result<()> {
    ensure_not_root(volume_id, "host_path", host_path)?;
    ensure_not_root(volume_id, "session_path", session_path)?;
    ensure!(
        !paths_overlap(host_path, session_path),
        InvalidOverlaySessionViewSnafu {
            volume_id: volume_id.to_owned(),
            reason: format!(
                "host_path `{}` and session_path `{}` must not overlap",
                host_path.display(),
                session_path.display()
            )
        }
    );
    ensure!(
        !paths_overlap(host_path, storage_root),
        InvalidOverlaySessionViewSnafu {
            volume_id: volume_id.to_owned(),
            reason: format!(
                "host_path `{}` must not overlap storage root `{}`",
                host_path.display(),
                storage_root.display()
            )
        }
    );
    Ok(())
}

fn ensure_not_root(volume_id: &str, field: &'static str, path: &Path) -> Result<()> {
    ensure!(
        path.parent().is_some(),
        InvalidVolumePathSnafu {
            volume_id: volume_id.to_owned(),
            field,
            path: path.to_path_buf(),
            reason: String::from("path cannot be the filesystem root")
        }
    );
    Ok(())
}

fn mount_path_text(volume_id: &str, field: &'static str, path: &Path) -> Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| crate::FilesystemError::InvalidVolumePath {
            volume_id: volume_id.to_owned(),
            field,
            path: path.to_path_buf(),
            reason: String::from("path must be valid UTF-8 for the shell overlay wrapper"),
            location: snafu::Location::default(),
        })?
        .to_owned();
    ensure!(
        !path.contains(',') && !path.contains('\n'),
        InvalidVolumePathSnafu {
            volume_id: volume_id.to_owned(),
            field,
            path: PathBuf::from(&path),
            reason: String::from("path cannot contain comma or newline")
        }
    );
    Ok(path)
}

fn validate_mount_isolation(mounts: &[LinuxOverlayVolumeMount]) -> Result<()> {
    for (index, current) in mounts.iter().enumerate() {
        for other in mounts.iter().skip(index + 1) {
            validate_mounts_do_not_overlap(current, other)?;
        }
    }
    Ok(())
}

fn validate_mounts_do_not_overlap(
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
                !paths_overlap(Path::new(current_path), Path::new(other_path)),
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
