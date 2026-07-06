use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use snafu::{ensure, ResultExt};

use crate::{
    error::{
        MissingOverlayCommandSnafu, SetOverlayWrapperPermissionsSnafu,
        UnsupportedOverlayPlatformSnafu, WriteOverlayWrapperSnafu,
    },
    FilesystemSessionStorage, Result,
};

use plan::LinuxOverlaySessionPlanner;
use script::LinuxOverlayWrapperScript;

mod plan;
mod script;

#[cfg(test)]
mod tests;

const WRAPPER_FILE: &str = "linux-overlay-session-view.sh";
const REQUIRED_COMMANDS: &[&str] = &["unshare", "mount", "umount"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxOverlaySessionView {
    wrapper_path: PathBuf,
}

impl LinuxOverlaySessionView {
    pub fn prepare(storage: &FilesystemSessionStorage) -> Result<Self> {
        LinuxOverlayHostRequirements::ensure()?;

        let mounts = LinuxOverlaySessionPlanner::new(storage)?.prepare_mounts()?;
        let wrapper_path = storage.work_path().join(WRAPPER_FILE);
        LinuxOverlayWrapperFile::new(&wrapper_path)
            .write(LinuxOverlayWrapperScript::new(&mounts))?;

        Ok(Self { wrapper_path })
    }

    #[must_use]
    pub fn wrapper_path(&self) -> &Path {
        &self.wrapper_path
    }
}

struct LinuxOverlayHostRequirements;

impl LinuxOverlayHostRequirements {
    fn ensure() -> Result<()> {
        Self::ensure_linux_platform()?;
        Self::ensure_required_commands()
    }

    fn ensure_linux_platform() -> Result<()> {
        ensure!(
            cfg!(target_os = "linux"),
            UnsupportedOverlayPlatformSnafu {
                platform: std::env::consts::OS
            }
        );
        Ok(())
    }

    fn ensure_required_commands() -> Result<()> {
        for &command in REQUIRED_COMMANDS {
            ensure!(
                Self::command_available(command),
                MissingOverlayCommandSnafu { command }
            );
        }
        Ok(())
    }

    fn command_available(command: &str) -> bool {
        Command::new(command)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

struct LinuxOverlayWrapperFile<'a> {
    path: &'a Path,
}

impl<'a> LinuxOverlayWrapperFile<'a> {
    const fn new(path: &'a Path) -> Self {
        Self { path }
    }

    fn write(&self, script: LinuxOverlayWrapperScript<'_>) -> Result<()> {
        fs::write(self.path, script.render())
            .context(WriteOverlayWrapperSnafu { path: self.path })?;
        self.set_permissions()
    }

    #[cfg(unix)]
    fn set_permissions(&self) -> Result<()> {
        let mut permissions = fs::metadata(self.path)
            .context(SetOverlayWrapperPermissionsSnafu { path: self.path })?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(self.path, permissions)
            .context(SetOverlayWrapperPermissionsSnafu { path: self.path })
    }

    #[cfg(not(unix))]
    fn set_permissions(&self) -> Result<()> {
        Ok(())
    }
}
