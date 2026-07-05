use std::{
    fs, io,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{ActiveLayerWriterSnafu, ReadLayerPathSnafu},
    FilesystemVolumeStorage, Result,
};

const PROC: &str = "/proc";

pub(super) fn ensure_no_active_writers(volume: &FilesystemVolumeStorage) -> Result<()> {
    let watched = [
        volume.session_path(),
        volume.overlay().merged_path(),
        volume.overlay().upper_path(),
    ];
    let entries = fs::read_dir(PROC).context(ReadLayerPathSnafu { path: PROC })?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if permission_or_race(&error) => continue,
            Err(error) => return Err(error).context(ReadLayerPathSnafu { path: PROC }),
        };
        let Some(pid) = pid_from_name(&entry.file_name()) else {
            continue;
        };
        inspect_process(volume.id(), pid, entry.path(), &watched)?;
    }
    Ok(())
}

fn inspect_process(volume_id: &str, pid: u32, proc_path: PathBuf, watched: &[&Path]) -> Result<()> {
    let fd_dir = proc_path.join("fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(error) if permission_or_race(&error) => return Ok(()),
        Err(error) => return Err(error).context(ReadLayerPathSnafu { path: fd_dir }),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if permission_or_race(&error) => continue,
            Err(error) => {
                return Err(error).context(ReadLayerPathSnafu {
                    path: fd_dir.clone(),
                })
            }
        };
        let fd = entry.file_name().to_string_lossy().to_string();
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if permission_or_race(&error) => continue,
            Err(error) => return Err(error).context(ReadLayerPathSnafu { path: entry.path() }),
        };
        if path_is_watched(&target, watched) && fd_is_writer(&proc_path, &fd)? {
            ActiveLayerWriterSnafu {
                volume_id: volume_id.to_owned(),
                path: target,
                pid,
                fd,
            }
            .fail()?;
        }
    }
    Ok(())
}

fn fd_is_writer(proc_path: &Path, fd: &str) -> Result<bool> {
    let fdinfo = proc_path.join("fdinfo").join(fd);
    let source = match fs::read_to_string(&fdinfo) {
        Ok(source) => source,
        Err(error) if permission_or_race(&error) => return Ok(false),
        Err(error) => return Err(error).context(ReadLayerPathSnafu { path: fdinfo }),
    };
    Ok(source
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(parse_flags)
        .is_some_and(|flags| matches!(flags & 0o3, 0o1 | 0o2)))
}

fn parse_flags(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim(), 8).ok()
}

fn path_is_watched(target: &Path, watched: &[&Path]) -> bool {
    watched
        .iter()
        .any(|root| target == *root || target.starts_with(root))
}

fn pid_from_name(name: &std::ffi::OsStr) -> Option<u32> {
    name.to_str()?.parse().ok()
}

fn permission_or_race(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}
