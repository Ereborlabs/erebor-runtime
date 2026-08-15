#![allow(unsafe_code)]

use std::fs::File;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use linux_raw_sys::general::clone_args;
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use snafu::ResultExt as _;

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

pub(super) struct CloneIntoCgroupFixture {
    root_pid: u32,
    root_pidfd: OwnedFd,
    child_pidfd: Option<OwnedFd>,
}

impl CloneIntoCgroupFixture {
    pub(super) fn start(cgroup_path: &Path) -> Result<Self> {
        let cgroup = File::open(cgroup_path).context(IoSnafu { path: cgroup_path })?;
        let args = clone_args {
            flags: linux_raw_sys::general::CLONE_INTO_CGROUP,
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: cgroup.as_raw_fd() as u64,
        };
        let result =
            unsafe { libc::syscall(libc::SYS_clone3, &raw const args, size_of::<clone_args>()) };
        if result == 0 {
            run_child();
        }
        if result < 0 {
            return Err(invalid_state(format!(
                "clone3(CLONE_INTO_CGROUP) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let root_pid = u32::try_from(result)
            .map_err(|error| invalid_state(format!("clone3 returned an invalid PID: {error}")))?;
        let root_pidfd = open_pidfd(root_pid)?;
        Ok(Self {
            root_pid,
            root_pidfd,
            child_pidfd: None,
        })
    }

    pub(super) const fn root_pid(&self) -> u32 {
        self.root_pid
    }

    pub(super) fn release_root(&self) -> Result<()> {
        pidfd_send_signal(&self.root_pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release CLONE_INTO_CGROUP root: {error}")))
    }

    pub(super) fn child_pid(&mut self) -> Result<Option<u32>> {
        let path = PathBuf::from(format!("/proc/{0}/task/{0}/children", self.root_pid));
        let children = match std::fs::read_to_string(&path) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(invalid_state(
                    "CLONE_INTO_CGROUP root exited before it created a child",
                ));
            }
            Err(source) => return Err(source).context(IoSnafu { path }),
        };
        let Some(raw) = children.split_ascii_whitespace().next() else {
            let mut status = 0;
            // SAFETY: root_pid is this process's child and status is writable.
            let result = unsafe {
                libc::waitpid(self.root_pid as libc::pid_t, &raw mut status, libc::WNOHANG)
            };
            if result == self.root_pid as libc::pid_t {
                let reason = if libc::WIFEXITED(status) {
                    format!("exit status {}", libc::WEXITSTATUS(status))
                } else if libc::WIFSIGNALED(status) {
                    format!("signal {}", libc::WTERMSIG(status))
                } else {
                    format!("wait status {status}")
                };
                return Err(invalid_state(format!(
                    "CLONE_INTO_CGROUP root exited before it created a child: {reason}"
                )));
            }
            return Ok(None);
        };
        let pid = raw
            .parse::<u32>()
            .map_err(|error| invalid_state(format!("invalid clone child PID `{raw}`: {error}")))?;
        if self.child_pidfd.is_none() {
            self.child_pidfd = Some(open_pidfd(pid)?);
        }
        Ok(Some(pid))
    }

    pub(super) fn moved_parent_fork_denied(&mut self) -> Result<Option<()>> {
        let mut status = 0;
        // SAFETY: root_pid is this process's child and status is writable.
        let result =
            unsafe { libc::waitpid(self.root_pid as libc::pid_t, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(invalid_state(format!(
                "wait for moved-parent root exit: {}",
                std::io::Error::last_os_error()
            )));
        }
        if result == self.root_pid as libc::pid_t {
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == libc::EACCES {
                return Ok(Some(()));
            }
            let reason = if libc::WIFEXITED(status) {
                format!("exit status {}", libc::WEXITSTATUS(status))
            } else if libc::WIFSIGNALED(status) {
                format!("signal {}", libc::WTERMSIG(status))
            } else {
                format!("wait status {status}")
            };
            return Err(invalid_state(format!(
                "moved-parent ordinary fork did not fail with EACCES: {reason}"
            )));
        }

        let path = PathBuf::from(format!("/proc/{0}/task/{0}/children", self.root_pid));
        let children = match std::fs::read_to_string(&path) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path }),
        };
        if let Some(raw) = children.split_ascii_whitespace().next() {
            let child_pid = raw.parse::<u32>().map_err(|error| {
                invalid_state(format!("invalid moved-parent child PID `{raw}`: {error}"))
            })?;
            self.child_pidfd = Some(open_pidfd(child_pid)?);
            return Err(invalid_state(
                "moved-parent ordinary fork created a child before the denial",
            ));
        }
        Ok(None)
    }

    pub(super) fn stop(&mut self) {
        if let Some(pidfd) = &self.child_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        let _result = pidfd_send_signal(&self.root_pidfd, Signal::KILL);
        let mut status = 0;
        unsafe {
            libc::waitpid(self.root_pid as libc::pid_t, &raw mut status, 0);
        }
    }
}

impl Drop for CloneIntoCgroupFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let raw = i32::try_from(pid)
        .map_err(|error| invalid_state(format!("PID {pid} is out of range: {error}")))?;
    let pid = Pid::from_raw(raw).ok_or_else(|| invalid_state("PID zero cannot have a pidfd"))?;
    pidfd_open(pid, PidfdFlags::empty())
        .map_err(|error| invalid_state(format!("pidfd_open({raw}) failed: {error}")))
}

fn invalid_state(reason: impl Into<String>) -> crate::Error {
    InvalidInputSnafu {
        path: Path::new("CLONE_INTO_CGROUP identity fixture"),
        reason: reason.into(),
    }
    .build()
}

fn run_child() -> ! {
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    let native_child = unsafe { libc::fork() };
    if native_child == 0 {
        unsafe {
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
    }
    if native_child < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(125);
        unsafe { libc::_exit(errno.clamp(1, 125)) }
    }
    unsafe {
        libc::raise(libc::SIGSTOP);
        libc::_exit(0);
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::{invalid_state, open_pidfd, CloneIntoCgroupFixture};

    #[test]
    fn clone_into_cgroup_fixture_recognizes_childless_eacces_exit() -> crate::Result<()> {
        let raw_pid = unsafe { libc::fork() };
        if raw_pid == 0 {
            unsafe { libc::_exit(libc::EACCES) }
        }
        if raw_pid < 0 {
            return Err(invalid_state(format!(
                "fork fixture status child: {}",
                std::io::Error::last_os_error()
            )));
        }
        let root_pid = u32::try_from(raw_pid)
            .map_err(|error| invalid_state(format!("fixture status PID: {error}")))?;
        let mut fixture = CloneIntoCgroupFixture {
            root_pid,
            root_pidfd: open_pidfd(root_pid)?,
            child_pidfd: None,
        };
        for _ in 0..100 {
            if fixture.moved_parent_fork_denied()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
        Err(invalid_state(
            "fixture did not observe the childless EACCES exit",
        ))
    }
}
