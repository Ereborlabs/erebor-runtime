use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

use rustix::{
    fs::{lgetxattr, llistxattr},
    io::Errno,
};
use snafu::ResultExt;

use crate::{
    error::{InspectLayerPathSnafu, ReadLayerPathSnafu},
    FilesystemOpaqueMarker, Result,
};

const OPAQUE_MARKER_FILE: &str = ".wh..wh..opq";
const OVERLAY_WHITEOUT: &[&str] = &["trusted.overlay.whiteout", "user.overlay.whiteout"];
const OVERLAY_OPAQUE: &[&str] = &["trusted.overlay.opaque", "user.overlay.opaque"];
const OVERLAY_SIDECARS: &[&str] = &["trusted.overlay.origin", "user.overlay.origin"];

pub(crate) fn is_control_file_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == OPAQUE_MARKER_FILE || name.starts_with(".wh."))
}

pub(crate) fn is_opaque_marker_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == OPAQUE_MARKER_FILE)
}

pub(crate) fn is_whiteout(path: &Path) -> Result<bool> {
    has_overlay_marker(path, OVERLAY_WHITEOUT)
}

pub(crate) fn is_whiteout_entry(path: &Path, metadata: &fs::Metadata) -> Result<bool> {
    if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
        return Ok(true);
    }
    if is_control_file_name(path) {
        return Ok(true);
    }
    is_whiteout(path)
}

pub(crate) fn opaque_marker(path: &Path) -> Result<Option<FilesystemOpaqueMarker>> {
    for name in OVERLAY_OPAQUE {
        if let Some(value) = read_xattr(path, name)? {
            if value.is_empty() || value == b"y" || value == b"1" {
                return Ok(Some(FilesystemOpaqueMarker {
                    kind: String::from("xattr"),
                    name: (*name).to_owned(),
                    value,
                }));
            }
        }
    }
    if path.join(OPAQUE_MARKER_FILE).exists() {
        return Ok(Some(FilesystemOpaqueMarker {
            kind: String::from("whiteout_file"),
            name: String::from(OPAQUE_MARKER_FILE),
            value: Vec::new(),
        }));
    }
    Ok(None)
}

pub(crate) fn unsupported_reasons(path: &Path) -> Result<Vec<String>> {
    let _xattrs = list_xattrs(path)?;
    Ok(Vec::new())
}

pub(crate) fn metadata_sidecars(path: &Path) -> Result<Vec<String>> {
    Ok(list_xattrs(path)?
        .into_iter()
        .filter(|name| OVERLAY_SIDECARS.contains(&name.as_str()))
        .collect())
}

fn has_overlay_marker(path: &Path, names: &[&str]) -> Result<bool> {
    for name in names {
        match read_xattr(path, name)? {
            Some(value) if value.is_empty() || value == b"y" || value == b"1" => return Ok(true),
            Some(_) | None => {}
        }
    }
    Ok(false)
}

fn read_xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let mut buffer = [0_u8; 64];
    match lgetxattr(path, name, &mut buffer) {
        Ok(len) => Ok(Some(buffer[..len].to_vec())),
        Err(error) if missing_or_unsupported(error) || error == Errno::PERM => Ok(None),
        Err(source) => Err(std::io::Error::from(source)).context(InspectLayerPathSnafu { path }),
    }
}

fn list_xattrs(path: &Path) -> Result<Vec<String>> {
    let mut buffer = vec![0_u8; 8192];
    let len = match llistxattr(path, &mut buffer) {
        Ok(len) => len,
        Err(error) if missing_or_unsupported(error) || error == Errno::PERM => {
            return Ok(Vec::new())
        }
        Err(source) => {
            return Err(std::io::Error::from(source)).context(ReadLayerPathSnafu { path });
        }
    };
    buffer.truncate(len);
    Ok(buffer
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).to_string())
        .collect())
}

fn missing_or_unsupported(error: Errno) -> bool {
    matches!(error, Errno::NODATA | Errno::NOTSUP)
}
