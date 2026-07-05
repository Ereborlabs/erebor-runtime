use std::path::Path;

use rustix::{
    fs::{lgetxattr, llistxattr},
    io::Errno,
};
use snafu::ResultExt;

use crate::{
    error::{InspectLayerPathSnafu, ReadLayerPathSnafu},
    Result,
};

const OVERLAY_WHITEOUT: &[&str] = &["trusted.overlay.whiteout", "user.overlay.whiteout"];
const OVERLAY_OPAQUE: &[&str] = &["trusted.overlay.opaque", "user.overlay.opaque"];
const OVERLAY_SIDECARS: &[&str] = &["trusted.overlay.origin", "user.overlay.origin"];
const KNOWN_OVERLAY_XATTRS: &[&str] = &[
    "trusted.overlay.whiteout",
    "trusted.overlay.opaque",
    "trusted.overlay.origin",
    "user.overlay.whiteout",
    "user.overlay.opaque",
    "user.overlay.origin",
];

pub(super) fn is_whiteout(path: &Path) -> Result<bool> {
    has_overlay_marker(path, OVERLAY_WHITEOUT)
}

pub(super) fn is_opaque_directory(path: &Path) -> Result<bool> {
    has_overlay_marker(path, OVERLAY_OPAQUE)
}

pub(super) fn unsupported_reasons(path: &Path) -> Result<Vec<String>> {
    Ok(list_xattrs(path)?
        .into_iter()
        .filter(|name| !KNOWN_OVERLAY_XATTRS.contains(&name.as_str()))
        .map(|name| unsupported_reason(&name))
        .collect())
}

pub(super) fn metadata_sidecars(path: &Path) -> Result<Vec<String>> {
    Ok(list_xattrs(path)?
        .into_iter()
        .filter(|name| OVERLAY_SIDECARS.contains(&name.as_str()))
        .collect())
}

fn has_overlay_marker(path: &Path, names: &[&str]) -> Result<bool> {
    for name in names {
        match read_xattr(path, name)? {
            Some(value) if value.is_empty() || value == b"y" || value == b"1" => return Ok(true),
            Some(_) => {}
            None => {}
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

fn unsupported_reason(name: &str) -> String {
    if name == "security.capability" {
        String::from("file capabilities are not supported in this phase")
    } else if name.starts_with("system.posix_acl") {
        String::from("POSIX ACLs are not supported in this phase")
    } else {
        format!("unsupported xattr `{name}`")
    }
}
