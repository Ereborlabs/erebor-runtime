use std::{fs, os::unix::fs::MetadataExt, path::Path};

use rustix::{
    fs::{
        chmodat, chownat, lgetxattr, llistxattr, lsetxattr, utimensat, AtFlags, Gid, Mode,
        Timespec, Timestamps, Uid, XattrFlags, CWD, UTIME_OMIT,
    },
    io::Errno,
};
use snafu::ResultExt;

use crate::{
    error::{InspectLayerPathSnafu, PromotionIoSnafu, ReadLayerPathSnafu},
    promotion::FilesystemHostMetadata,
    FilesystemLayerMetadata, FilesystemXattr, Result,
};

const OVERLAY_XATTRS: &[&str] = &[
    "trusted.overlay.whiteout",
    "trusted.overlay.opaque",
    "trusted.overlay.origin",
    "user.overlay.whiteout",
    "user.overlay.opaque",
    "user.overlay.origin",
];

pub(crate) fn layer_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FilesystemLayerMetadata> {
    Ok(FilesystemLayerMetadata {
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        xattrs: restorable_xattrs(path)?,
    })
}

pub(crate) fn host_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<FilesystemHostMetadata> {
    Ok(FilesystemHostMetadata {
        file_type: file_type(metadata),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        device: metadata.dev(),
        inode: metadata.ino(),
        xattrs: restorable_xattrs(path)?,
    })
}

pub(crate) fn apply_layer_metadata(path: &Path, metadata: &FilesystemLayerMetadata) -> Result<()> {
    apply_metadata(
        path,
        metadata.mode,
        metadata.uid,
        metadata.gid,
        metadata.mtime_sec,
        metadata.mtime_nsec,
        &metadata.xattrs,
    )
}

pub(crate) fn apply_host_metadata(path: &Path, metadata: &FilesystemHostMetadata) -> Result<()> {
    apply_metadata(
        path,
        metadata.mode,
        metadata.uid,
        metadata.gid,
        metadata.mtime_sec,
        metadata.mtime_nsec,
        &metadata.xattrs,
    )
}

pub(crate) fn copy_path_metadata(source: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source).context(PromotionIoSnafu {
        action: "inspect source metadata",
        path: source,
    })?;
    let metadata = host_metadata(source, &metadata)?;
    apply_host_metadata(target, &metadata)
}

fn apply_metadata(
    path: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_sec: i64,
    mtime_nsec: i64,
    xattrs: &[FilesystemXattr],
) -> Result<()> {
    apply_ownership(path, uid, gid)?;
    apply_xattrs(path, xattrs)?;
    apply_mode(path, mode)?;
    apply_mtime(path, mtime_sec, mtime_nsec)
}

fn apply_ownership(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let current = fs::symlink_metadata(path).context(PromotionIoSnafu {
        action: "inspect restored metadata owner",
        path,
    })?;
    if current.uid() == uid && current.gid() == gid {
        return Ok(());
    }
    chownat(
        CWD,
        path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(std::io::Error::from)
    .context(PromotionIoSnafu {
        action: "restore metadata owner",
        path,
    })
}

fn apply_mode(path: &Path, mode: u32) -> Result<()> {
    if fs::symlink_metadata(path)
        .context(PromotionIoSnafu {
            action: "inspect restored metadata mode",
            path,
        })?
        .file_type()
        .is_symlink()
    {
        return Ok(());
    }
    chmodat(
        CWD,
        path,
        Mode::from_raw_mode(mode & 0o7777),
        AtFlags::empty(),
    )
    .map_err(std::io::Error::from)
    .context(PromotionIoSnafu {
        action: "restore metadata mode",
        path,
    })
}

fn apply_mtime(path: &Path, mtime_sec: i64, mtime_nsec: i64) -> Result<()> {
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: mtime_sec,
            tv_nsec: mtime_nsec as _,
        },
    };
    utimensat(CWD, path, &times, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)
        .context(PromotionIoSnafu {
            action: "restore metadata mtime",
            path,
        })
}

fn apply_xattrs(path: &Path, xattrs: &[FilesystemXattr]) -> Result<()> {
    for xattr in xattrs {
        lsetxattr(path, xattr.name.as_str(), &xattr.value, XattrFlags::empty())
            .map_err(std::io::Error::from)
            .context(PromotionIoSnafu {
                action: "restore metadata xattr",
                path,
            })?;
    }
    Ok(())
}

fn restorable_xattrs(path: &Path) -> Result<Vec<FilesystemXattr>> {
    let mut xattrs = Vec::new();
    for name in list_xattrs(path)? {
        if OVERLAY_XATTRS.contains(&name.as_str()) {
            continue;
        }
        xattrs.push(FilesystemXattr {
            value: read_xattr(path, &name)?,
            name,
        });
    }
    xattrs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(xattrs)
}

fn list_xattrs(path: &Path) -> Result<Vec<String>> {
    let mut buffer = vec![0_u8; 8192];
    loop {
        match llistxattr(path, &mut buffer) {
            Ok(len) => {
                buffer.truncate(len);
                return Ok(buffer
                    .split(|byte| *byte == 0)
                    .filter(|name| !name.is_empty())
                    .map(|name| String::from_utf8_lossy(name).to_string())
                    .collect());
            }
            Err(error) if missing_or_unsupported(error) => return Ok(Vec::new()),
            Err(Errno::RANGE) => buffer.resize(buffer.len() * 2, 0),
            Err(source) => {
                return Err(std::io::Error::from(source)).context(ReadLayerPathSnafu { path });
            }
        }
    }
}

fn read_xattr(path: &Path, name: &str) -> Result<Vec<u8>> {
    let mut buffer = vec![0_u8; 256];
    loop {
        match lgetxattr(path, name, &mut buffer) {
            Ok(len) => {
                buffer.truncate(len);
                return Ok(buffer);
            }
            Err(Errno::RANGE) => buffer.resize(buffer.len() * 2, 0),
            Err(source) => {
                return Err(std::io::Error::from(source)).context(InspectLayerPathSnafu { path });
            }
        }
    }
}

fn missing_or_unsupported(error: Errno) -> bool {
    matches!(error, Errno::NODATA | Errno::NOTSUP)
}

fn file_type(metadata: &fs::Metadata) -> String {
    if metadata.is_dir() {
        String::from("directory")
    } else if metadata.is_file() {
        String::from("regular")
    } else if metadata.file_type().is_symlink() {
        String::from("symlink")
    } else {
        String::from("special")
    }
}
