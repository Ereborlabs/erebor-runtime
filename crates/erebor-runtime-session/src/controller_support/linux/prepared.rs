use std::{
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use crate::runners::linux::LinuxControllerHandoff;
use rustix::{
    fs::{open, Mode, OFlags},
    io::{fcntl_setfd, FdFlags},
};

use crate::SessionControllerError;

pub(super) struct PreparedLinuxExecution {
    workspace: File,
    executable: Option<File>,
}

impl PreparedLinuxExecution {
    pub(super) fn open(handoff: &LinuxControllerHandoff) -> Result<Self, SessionControllerError> {
        let workspace_path = handoff
            .prepared_workspace
            .as_deref()
            .unwrap_or_else(|| handoff.spec.workspace().requested_path());
        let workspace = open_path(
            workspace_path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            "opening admitted Linux workspace before namespace isolation",
        )?;
        let executable = handoff
            .prepared_executable
            .as_deref()
            .map(|path| {
                let executable = open_path(
                    path,
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    "opening admitted Linux executable before namespace isolation",
                )?;
                fcntl_setfd(&executable, FdFlags::empty())
                    .map_err(std::io::Error::from)
                    .map_err(|source| SessionControllerError::Io {
                        action: "preserving admitted Linux executable across guard launch",
                        path: path.to_path_buf(),
                        source,
                        location: snafu::Location::default(),
                    })?;
                Ok(executable)
            })
            .transpose()?;
        Ok(Self {
            workspace,
            executable,
        })
    }

    pub(super) fn workspace_path(&self) -> PathBuf {
        descriptor_path(&self.workspace)
    }

    pub(super) fn admitted_command(&self, handoff: &LinuxControllerHandoff) -> Vec<String> {
        let mut command = handoff.spec.command().to_vec();
        if let Some(executable) = &self.executable {
            command[0] = descriptor_path(executable).display().to_string();
        }
        command
    }
}

fn open_path(
    path: &Path,
    flags: OFlags,
    action: &'static str,
) -> Result<File, SessionControllerError> {
    open(path, flags, Mode::empty())
        .map(File::from)
        .map_err(std::io::Error::from)
        .map_err(|source| SessionControllerError::Io {
            action,
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })
}

fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
