use crate::{AnalysisStateSnafu, IoSnafu, Result};
use snafu::ResultExt as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

pub(in crate::analysis) struct AnalysisLease {
    pub(in crate::analysis) file: std::fs::File,
    process_id: u32,
}

impl AnalysisLease {
    pub(in crate::analysis) fn acquire(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return crate::Error::reject_path(root, "the analysis path is not absolute");
        }
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source).context(IoSnafu { path: root }),
        }
        let metadata = fs::symlink_metadata(root).context(IoSnafu { path: root })?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return crate::Error::reject_path(root, "the analysis directory is not private");
        }
        let filesystem = rustix::fs::statfs(root)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: root })?;
        if !matches!(filesystem.f_type, 0xef53 | 0x0102_1994) {
            return crate::Error::reject_path(root, "the analysis filesystem is not qualified");
        }
        let path = root.join("analysis.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        let metadata = file.metadata().context(IoSnafu { path: &path })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return crate::Error::reject_path(&path, "the analysis lease file is not private");
        }
        file.try_lock().map_err(|error| {
            AnalysisStateSnafu {
                path: root,
                reason: format!("the analysis writer is already owned: {error}"),
            }
            .build()
        })?;
        Ok(Self::from(file))
    }
}

impl From<std::fs::File> for AnalysisLease {
    fn from(file: std::fs::File) -> Self {
        Self {
            file,
            process_id: std::process::id(),
        }
    }
}

impl Drop for AnalysisLease {
    fn drop(&mut self) {
        // A child descriptor must not retain or release the parent's lease.
        if self.process_id == std::process::id() {
            let _result = self.file.unlock();
        }
    }
}
