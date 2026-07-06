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

pub(crate) struct FilesystemMetadataReader<'a> {
    path: &'a Path,
    metadata: &'a fs::Metadata,
}

impl<'a> FilesystemMetadataReader<'a> {
    pub(crate) const fn new(path: &'a Path, metadata: &'a fs::Metadata) -> Self {
        Self { path, metadata }
    }

    pub(crate) fn layer_metadata(&self) -> Result<FilesystemLayerMetadata> {
        Ok(FilesystemLayerMetadata {
            mode: self.metadata.mode(),
            uid: self.metadata.uid(),
            gid: self.metadata.gid(),
            size: self.metadata.len(),
            mtime_sec: self.metadata.mtime(),
            mtime_nsec: self.metadata.mtime_nsec(),
            xattrs: self.restorable_xattrs()?,
        })
    }

    pub(crate) fn host_metadata(&self) -> Result<FilesystemHostMetadata> {
        Ok(FilesystemHostMetadata {
            file_type: self.file_type(),
            mode: self.metadata.mode(),
            uid: self.metadata.uid(),
            gid: self.metadata.gid(),
            size: self.metadata.len(),
            mtime_sec: self.metadata.mtime(),
            mtime_nsec: self.metadata.mtime_nsec(),
            device: self.metadata.dev(),
            inode: self.metadata.ino(),
            xattrs: self.restorable_xattrs()?,
        })
    }

    fn restorable_xattrs(&self) -> Result<Vec<FilesystemXattr>> {
        let mut xattrs = Vec::new();
        for name in self.list_xattrs()? {
            if OVERLAY_XATTRS.contains(&name.as_str()) {
                continue;
            }
            xattrs.push(FilesystemXattr {
                value: self.read_xattr(&name)?,
                name,
            });
        }
        xattrs.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(xattrs)
    }

    fn list_xattrs(&self) -> Result<Vec<String>> {
        let mut buffer = vec![0_u8; 8192];
        loop {
            match llistxattr(self.path, &mut buffer) {
                Ok(len) => {
                    buffer.truncate(len);
                    return Ok(buffer
                        .split(|byte| *byte == 0)
                        .filter(|name| !name.is_empty())
                        .map(|name| String::from_utf8_lossy(name).to_string())
                        .collect());
                }
                Err(error) if Self::missing_or_unsupported(error) => return Ok(Vec::new()),
                Err(Errno::RANGE) => buffer.resize(buffer.len() * 2, 0),
                Err(source) => {
                    return Err(std::io::Error::from(source))
                        .context(ReadLayerPathSnafu { path: self.path });
                }
            }
        }
    }

    fn read_xattr(&self, name: &str) -> Result<Vec<u8>> {
        let mut buffer = vec![0_u8; 256];
        loop {
            match lgetxattr(self.path, name, &mut buffer) {
                Ok(len) => {
                    buffer.truncate(len);
                    return Ok(buffer);
                }
                Err(Errno::RANGE) => buffer.resize(buffer.len() * 2, 0),
                Err(source) => {
                    return Err(std::io::Error::from(source))
                        .context(InspectLayerPathSnafu { path: self.path });
                }
            }
        }
    }

    fn file_type(&self) -> String {
        if self.metadata.is_dir() {
            String::from("directory")
        } else if self.metadata.is_file() {
            String::from("regular")
        } else if self.metadata.file_type().is_symlink() {
            String::from("symlink")
        } else {
            String::from("special")
        }
    }

    const fn missing_or_unsupported(error: Errno) -> bool {
        matches!(error, Errno::NODATA | Errno::NOTSUP)
    }
}

pub(crate) struct FilesystemMetadataApplier<'a> {
    path: &'a Path,
}

impl<'a> FilesystemMetadataApplier<'a> {
    pub(crate) const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    pub(crate) fn apply_layer_metadata(&self, metadata: &FilesystemLayerMetadata) -> Result<()> {
        self.apply_metadata(
            metadata.mode,
            metadata.uid,
            metadata.gid,
            metadata.mtime_sec,
            metadata.mtime_nsec,
            &metadata.xattrs,
        )
    }

    pub(crate) fn apply_host_metadata(&self, metadata: &FilesystemHostMetadata) -> Result<()> {
        self.apply_metadata(
            metadata.mode,
            metadata.uid,
            metadata.gid,
            metadata.mtime_sec,
            metadata.mtime_nsec,
            &metadata.xattrs,
        )
    }

    fn apply_metadata(
        &self,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_sec: i64,
        mtime_nsec: i64,
        xattrs: &[FilesystemXattr],
    ) -> Result<()> {
        self.apply_ownership(uid, gid)?;
        self.apply_xattrs(xattrs)?;
        self.apply_mode(mode)?;
        self.apply_mtime(mtime_sec, mtime_nsec)
    }

    fn apply_ownership(&self, uid: u32, gid: u32) -> Result<()> {
        let current = fs::symlink_metadata(self.path).context(PromotionIoSnafu {
            action: "inspect restored metadata owner",
            path: self.path,
        })?;
        if current.uid() == uid && current.gid() == gid {
            return Ok(());
        }
        chownat(
            CWD,
            self.path,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(std::io::Error::from)
        .context(PromotionIoSnafu {
            action: "restore metadata owner",
            path: self.path,
        })
    }

    fn apply_mode(&self, mode: u32) -> Result<()> {
        if fs::symlink_metadata(self.path)
            .context(PromotionIoSnafu {
                action: "inspect restored metadata mode",
                path: self.path,
            })?
            .file_type()
            .is_symlink()
        {
            return Ok(());
        }
        chmodat(
            CWD,
            self.path,
            Mode::from_raw_mode(mode & 0o7777),
            AtFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .context(PromotionIoSnafu {
            action: "restore metadata mode",
            path: self.path,
        })
    }

    fn apply_mtime(&self, mtime_sec: i64, mtime_nsec: i64) -> Result<()> {
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
        utimensat(CWD, self.path, &times, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)
            .context(PromotionIoSnafu {
                action: "restore metadata mtime",
                path: self.path,
            })
    }

    fn apply_xattrs(&self, xattrs: &[FilesystemXattr]) -> Result<()> {
        for xattr in xattrs {
            lsetxattr(
                self.path,
                xattr.name.as_str(),
                &xattr.value,
                XattrFlags::empty(),
            )
            .map_err(std::io::Error::from)
            .context(PromotionIoSnafu {
                action: "restore metadata xattr",
                path: self.path,
            })?;
        }
        Ok(())
    }
}

pub(crate) struct FilesystemPathMetadataCopier<'a> {
    source: &'a Path,
    target: &'a Path,
}

impl<'a> FilesystemPathMetadataCopier<'a> {
    pub(crate) const fn new(source: &'a Path, target: &'a Path) -> Self {
        Self { source, target }
    }

    pub(crate) fn copy(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(self.source).context(PromotionIoSnafu {
            action: "inspect source metadata",
            path: self.source,
        })?;
        let metadata = FilesystemMetadataReader::new(self.source, &metadata).host_metadata()?;
        FilesystemMetadataApplier::new(self.target).apply_host_metadata(&metadata)
    }
}
