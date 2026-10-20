use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use snafu::IntoError as _;

use super::artifact::NativeAdmission;
use super::{Code, Qualification};
use crate::Result;

pub(super) struct FilePin {
    file: File,
    path: PathBuf,
    name: String,
    digest: String,
    packaged: bool,
}

impl FilePin {
    pub(super) fn package(directory: &Path, name: &str, bytes: &[u8]) -> Result<Self> {
        let digest = Qualification::digest(bytes);
        let alias = NativeAdmission::soname(bytes)
            .ok()
            .flatten()
            .unwrap_or_else(|| name.to_owned());
        let path = directory.join(name);
        #[cfg(target_os = "linux")]
        let mut file = {
            let label = format!(
                "araphor-{}-{digest}",
                Qualification::digest(alias.as_bytes())
            );
            File::from(
                rustix::fs::memfd_create(
                    label,
                    rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
                )
                .map_err(|source| crate::IoSnafu { path: &path }.into_error(source.into()))?,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| crate::IoSnafu { path: &path }.into_error(source))?;
        file.write_all(bytes)
            .map_err(|source| crate::IoSnafu { path: &path }.into_error(source))?;
        #[cfg(not(target_os = "linux"))]
        {
            let mut permissions = file
                .metadata()
                .map_err(|source| crate::IoSnafu { path: &path }.into_error(source))?
                .permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)
                .map_err(|source| crate::IoSnafu { path: &path }.into_error(source))?;
        }
        #[cfg(target_os = "linux")]
        {
            rustix::fs::fcntl_add_seals(
                &file,
                rustix::fs::SealFlags::WRITE
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::SEAL,
            )
            .map_err(|source| crate::IoSnafu { path: &path }.into_error(source.into()))?;
            Self::link(&file, &path)?;
        }
        Ok(Self {
            file,
            path,
            name: alias,
            digest,
            packaged: true,
        })
    }

    pub(super) fn system(directory: &Path, name: &str) -> Result<(Self, Vec<u8>)> {
        let source = NativeAdmission::system_path(name)?;
        let mut file = File::open(&source)
            .map_err(|error| crate::IoSnafu { path: &source }.into_error(error))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| crate::IoSnafu { path: &source }.into_error(error))?;
        #[cfg(target_os = "linux")]
        let path = {
            let path = directory.join(format!("system-{}", Qualification::digest(name.as_bytes())));
            Self::link(&file, &path)?;
            path
        };
        #[cfg(not(target_os = "linux"))]
        let path = source;
        Ok((
            Self {
                file,
                path,
                name: name.into(),
                digest: Qualification::digest(&bytes),
                packaged: false,
            },
            bytes,
        ))
    }

    #[cfg(target_os = "linux")]
    fn link(file: &File, path: &Path) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", file.as_raw_fd()), path)
            .map_err(|source| crate::IoSnafu { path }.into_error(source))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn check(&self) -> Result<()> {
        let actual = std::fs::metadata(&self.path)
            .map_err(|source| crate::IoSnafu { path: &self.path }.into_error(source))?;
        let expected = self
            .file
            .metadata()
            .map_err(|source| crate::IoSnafu { path: &self.path }.into_error(source))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
                return Err(crate::Error::from(
                    Code::Conflict.error("native file identity"),
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn mapped(&self, bytes: &[u8]) -> Result<bool> {
        MappedFiles::read()?.check(self, bytes)
    }
}

pub(super) struct MappedFiles {
    #[cfg(target_os = "linux")]
    entries: Vec<(u32, u32, u64, String)>,
    #[cfg(target_os = "linux")]
    names: BTreeMap<String, Option<String>>,
}

impl MappedFiles {
    pub(super) fn read() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let maps = std::fs::read_to_string("/proc/self/maps").map_err(|source| {
                crate::IoSnafu {
                    path: "/proc/self/maps",
                }
                .into_error(source)
            })?;
            let mut entries = BTreeMap::new();
            for line in maps.lines() {
                let mut fields = line.split_whitespace();
                let _ = (fields.next(), fields.next(), fields.next());
                let Some(device) = fields.next() else {
                    continue;
                };
                let Some(inode) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                    continue;
                };
                let Some(path) = fields.next() else { continue };
                let Some((major, minor)) = device.split_once(':') else {
                    continue;
                };
                let (Ok(major), Ok(minor)) = (
                    u32::from_str_radix(major, 16),
                    u32::from_str_radix(minor, 16),
                ) else {
                    continue;
                };
                if inode != 0 {
                    entries.insert((major, minor, inode), path.to_owned());
                }
            }
            Ok(Self {
                entries: entries
                    .into_iter()
                    .map(|((major, minor, inode), path)| (major, minor, inode, path))
                    .collect(),
                names: BTreeMap::new(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        Ok(Self {})
    }

    #[cfg(target_os = "linux")]
    pub(super) fn check(&mut self, pin: &FilePin, bytes: &[u8]) -> Result<bool> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = pin
            .file
            .metadata()
            .map_err(|source| crate::IoSnafu { path: &pin.path }.into_error(source))?;
        let identity = (
            rustix::fs::major(metadata.dev()),
            rustix::fs::minor(metadata.dev()),
            metadata.ino(),
        );
        let soname = NativeAdmission::soname(bytes)?;
        let label = format!(
            "/memfd:araphor-{}-",
            Qualification::digest(pin.name.as_bytes())
        );
        let mut matched = false;
        for (major, minor, inode, path) in &self.entries {
            if (*major, *minor, *inode) == identity {
                matched = true;
                continue;
            }
            let same_name = (pin.name != "algorithm.so" && path.starts_with(&label))
                || (!pin.packaged
                    && Path::new(path)
                        .file_name()
                        .is_some_and(|name| name == pin.name.as_str()));
            let same_soname =
                if soname.is_some() && path.starts_with('/') && !path.starts_with("/memfd:") {
                    let name = self.names.entry(path.clone()).or_insert_with(|| {
                        File::open(path)
                            .ok()
                            .and_then(|file| NativeAdmission::file_soname(file).ok().flatten())
                    });
                    name.as_ref() == soname.as_ref()
                } else {
                    false
                };
            if same_name || same_soname {
                let sealed_match = path.starts_with(&label)
                    && path
                        .strip_prefix(&label)
                        .is_some_and(|value| value == pin.digest);
                if !pin.packaged
                    || (!sealed_match
                        && std::fs::read(path)
                            .ok()
                            .is_none_or(|bytes| Qualification::digest(&bytes) != pin.digest))
                {
                    return Err(crate::Error::from(
                        Code::Conflict.error("loaded native library identity"),
                    ));
                }
            }
        }
        Ok(matched)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn check(&mut self, _pin: &FilePin, _bytes: &[u8]) -> Result<bool> {
        Ok(false)
    }
}
