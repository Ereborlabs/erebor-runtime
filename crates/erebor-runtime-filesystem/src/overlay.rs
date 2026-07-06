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

pub(crate) struct OverlayMarkerProbe<'a> {
    path: &'a Path,
}

impl<'a> OverlayMarkerProbe<'a> {
    pub(crate) const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub(crate) fn is_control_file_name(&self) -> bool {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(Self::is_control_name)
    }

    pub(crate) fn is_opaque_marker_file(&self) -> bool {
        self.path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == OPAQUE_MARKER_FILE)
    }

    pub(crate) fn is_whiteout(&self) -> Result<bool> {
        self.has_overlay_marker(OVERLAY_WHITEOUT)
    }

    pub(crate) fn is_whiteout_entry(&self, metadata: &fs::Metadata) -> Result<bool> {
        if metadata.file_type().is_char_device() && metadata.rdev() == 0 {
            return Ok(true);
        }
        if self.is_control_file_name() {
            return Ok(true);
        }
        self.is_whiteout()
    }

    pub(crate) fn opaque_marker(&self) -> Result<Option<FilesystemOpaqueMarker>> {
        for name in OVERLAY_OPAQUE {
            if let Some(value) = self.read_xattr(name)? {
                if Self::marker_value_is_enabled(&value) {
                    return Ok(Some(FilesystemOpaqueMarker {
                        kind: String::from("xattr"),
                        name: (*name).to_owned(),
                        value,
                    }));
                }
            }
        }
        if self.path.join(OPAQUE_MARKER_FILE).exists() {
            return Ok(Some(FilesystemOpaqueMarker {
                kind: String::from("whiteout_file"),
                name: String::from(OPAQUE_MARKER_FILE),
                value: Vec::new(),
            }));
        }
        Ok(None)
    }

    pub(crate) fn unsupported_reasons(&self) -> Result<Vec<String>> {
        let _xattrs = self.list_xattrs()?;
        Ok(Vec::new())
    }

    pub(crate) fn metadata_sidecars(&self) -> Result<Vec<String>> {
        Ok(self
            .list_xattrs()?
            .into_iter()
            .filter(|name| OVERLAY_SIDECARS.contains(&name.as_str()))
            .collect())
    }

    fn has_overlay_marker(&self, names: &[&str]) -> Result<bool> {
        for name in names {
            match self.read_xattr(name)? {
                Some(value) if Self::marker_value_is_enabled(&value) => return Ok(true),
                Some(_) | None => {}
            }
        }
        Ok(false)
    }

    fn read_xattr(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let mut buffer = [0_u8; 64];
        match lgetxattr(self.path, name, &mut buffer) {
            Ok(len) => Ok(Some(buffer[..len].to_vec())),
            Err(error) if Self::missing_or_unsupported(error) || error == Errno::PERM => Ok(None),
            Err(source) => {
                Err(std::io::Error::from(source)).context(InspectLayerPathSnafu { path: self.path })
            }
        }
    }

    fn list_xattrs(&self) -> Result<Vec<String>> {
        let mut buffer = vec![0_u8; 8192];
        let len = match llistxattr(self.path, &mut buffer) {
            Ok(len) => len,
            Err(error) if Self::missing_or_unsupported(error) || error == Errno::PERM => {
                return Ok(Vec::new())
            }
            Err(source) => {
                return Err(std::io::Error::from(source))
                    .context(ReadLayerPathSnafu { path: self.path });
            }
        };
        buffer.truncate(len);
        Ok(buffer
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(name).to_string())
            .collect())
    }

    const fn marker_value_is_enabled(value: &[u8]) -> bool {
        value.is_empty() || matches!(value, b"y" | b"1")
    }

    fn is_control_name(name: &str) -> bool {
        name == OPAQUE_MARKER_FILE || name.starts_with(".wh.")
    }

    const fn missing_or_unsupported(error: Errno) -> bool {
        matches!(error, Errno::NODATA | Errno::NOTSUP)
    }
}
