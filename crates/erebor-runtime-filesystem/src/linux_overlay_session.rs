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
        ensure_linux_platform()?;
        ensure_required_commands()?;

        let mounts = plan::prepare_mounts(storage)?;
        let wrapper_path = storage.work_path().join(WRAPPER_FILE);
        fs::write(&wrapper_path, script::render_wrapper(&mounts)).context(
            WriteOverlayWrapperSnafu {
                path: &wrapper_path,
            },
        )?;
        set_wrapper_permissions(&wrapper_path)?;

        Ok(Self { wrapper_path })
    }

    #[must_use]
    pub fn wrapper_path(&self) -> &Path {
        &self.wrapper_path
    }
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
            command_available(command),
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

#[cfg(unix)]
fn set_wrapper_permissions(path: &Path) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .context(SetOverlayWrapperPermissionsSnafu { path })?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).context(SetOverlayWrapperPermissionsSnafu { path })
}

#[cfg(not(unix))]
fn set_wrapper_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
