use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor_abi::Id128V1;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

pub(crate) struct ProbeDirectory {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeDirectory {
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) struct ProbeFile {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeFile {
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeFile {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::remove_file(&self.path);
        }
    }
}

pub(crate) struct ProbeCgroup {
    path: PathBuf,
    cleaned: bool,
}

impl ProbeCgroup {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        ensure!(
            !path.exists(),
            InvalidInputSnafu {
                path,
                reason: "the dedicated test cgroup must not already exist",
            }
        );
        fs::create_dir(path).context(IoSnafu { path })?;
        let path = fs::canonicalize(path).context(IoSnafu { path })?;
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn cleanup(mut self) -> Result<()> {
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).context(IoSnafu { path: &self.path }),
        }
        .inspect(|()| self.cleaned = true)
    }
}

impl Drop for ProbeCgroup {
    fn drop(&mut self) {
        if !self.cleaned {
            let _result = fs::write(self.path.join("cgroup.kill"), b"1");
            let _result = fs::remove_dir(&self.path);
        }
    }
}

pub(crate) fn boot_identity() -> Result<(String, Id128V1)> {
    let path = Path::new("/proc/sys/kernel/random/boot_id");
    let text = fs::read_to_string(path).context(IoSnafu { path })?;
    let uuid = uuid::Uuid::parse_str(text.trim()).map_err(|error| {
        InvalidInputSnafu {
            path,
            reason: format!("kernel boot ID is invalid: {error}"),
        }
        .build()
    })?;
    let value = uuid.as_u128();
    Ok((
        uuid.simple().to_string(),
        Id128V1::new((value >> 64) as u64, value as u64),
    ))
}
