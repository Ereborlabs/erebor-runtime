#![allow(unsafe_code)]

use std::{
    fs::File,
    io::Read,
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::Command,
};

use linux_raw_sys::general::clone_args;
use rustix::{
    fd::OwnedFd,
    pipe::{pipe_with, PipeFlags},
    process::{pidfd_send_signal, waitpid, Pid, Signal, WaitOptions, WaitStatus},
};

use super::privileges::WorkloadPrivileges;

pub(super) struct CloneIntoCgroupChild {
    pid: Pid,
    pidfd: OwnedFd,
    observed_exit: Option<WaitStatus>,
}

impl CloneIntoCgroupChild {
    pub(super) fn spawn(
        cgroup: &File,
        command: Command,
        privileges: &WorkloadPrivileges,
    ) -> std::io::Result<Self> {
        Self::spawn_with_setup(Some(cgroup), command, || privileges.apply())
    }

    fn spawn_with_setup(
        cgroup: Option<&File>,
        mut command: Command,
        setup: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let (error_read, error_write) =
            pipe_with(PipeFlags::CLOEXEC).map_err(std::io::Error::from)?;
        let mut pidfd_slot = -1_i32;
        let args = clone_args {
            flags: u64::from(linux_raw_sys::general::CLONE_PIDFD)
                | cgroup.map_or(0, |_cgroup| linux_raw_sys::general::CLONE_INTO_CGROUP),
            pidfd: (&raw mut pidfd_slot) as u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: cgroup.map_or(0, |cgroup| cgroup.as_raw_fd() as u64),
        };
        // SAFETY: clone3 receives complete arguments with a writable pidfd
        // slot. The child takes only the prepared exec path before it exits.
        let result =
            unsafe { libc::syscall(libc::SYS_clone3, &raw const args, size_of::<clone_args>()) };
        if result == 0 {
            drop(error_read);
            let error = match setup() {
                Ok(()) => command.exec(),
                Err(error) => error,
            };
            child_exec_failed(error_write.as_raw_fd(), &error);
        }
        drop(error_write);
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let raw_pid = i32::try_from(result).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("clone3 returned an invalid pid: {error}"),
            )
        })?;
        let pid = Pid::from_raw(raw_pid).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "clone3 returned pid zero to the parent",
            )
        })?;
        if pidfd_slot < 0 {
            let _result = rustix::process::kill_process(pid, Signal::KILL);
            let _result = waitpid(Some(pid), WaitOptions::empty());
            return Err(std::io::Error::other(
                "clone3 did not return the requested pidfd",
            ));
        }
        // SAFETY: CLONE_PIDFD returned this new owned descriptor in pidfd_slot.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_slot) };
        let mut exec_error = Vec::new();
        if let Err(error) = File::from(error_read)
            .take(size_of::<i32>() as u64 + 1)
            .read_to_end(&mut exec_error)
        {
            let _result = pidfd_send_signal(&pidfd, Signal::KILL);
            let _result = waitpid(Some(pid), WaitOptions::empty());
            return Err(error);
        }
        if !exec_error.is_empty() {
            let _result = waitpid(Some(pid), WaitOptions::empty());
            let errno = exec_error
                .get(..size_of::<i32>())
                .and_then(|bytes| bytes.try_into().ok())
                .map(i32::from_ne_bytes)
                .unwrap_or(libc::EINVAL);
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        Ok(Self {
            pid,
            pidfd,
            observed_exit: None,
        })
    }

    pub(super) const fn pid(&self) -> Pid {
        self.pid
    }

    pub(super) fn try_wait(&mut self) -> std::io::Result<Option<WaitStatus>> {
        if let Some(status) = self.observed_exit {
            return Ok(Some(status));
        }
        let status = waitpid(Some(self.pid), WaitOptions::NOHANG)
            .map_err(std::io::Error::from)?
            .map(|(_pid, status)| status);
        if let Some(status) = status {
            self.observed_exit = Some(status);
        }
        Ok(status)
    }

    pub(super) fn wait(&mut self) -> std::io::Result<WaitStatus> {
        if let Some(status) = self.observed_exit {
            return Ok(status);
        }
        let status = waitpid(Some(self.pid), WaitOptions::empty())
            .map_err(std::io::Error::from)?
            .ok_or_else(|| std::io::Error::other("waitpid returned no workload status"))?
            .1;
        self.observed_exit = Some(status);
        Ok(status)
    }
}

impl Drop for CloneIntoCgroupChild {
    fn drop(&mut self) {
        if self.observed_exit.is_none() {
            let _result = pidfd_send_signal(&self.pidfd, Signal::KILL);
            let _result = waitpid(Some(self.pid), WaitOptions::empty());
        }
    }
}

fn child_exec_failed(error_fd: i32, error: &std::io::Error) -> ! {
    let errno = error.raw_os_error().unwrap_or(libc::EINVAL).to_ne_bytes();
    // SAFETY: error_fd is the write end of the private exec-status pipe, and
    // _exit avoids running inherited parent destructors in the clone child.
    unsafe {
        libc::write(error_fd, errno.as_ptr().cast(), errno.len());
        libc::_exit(125);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::CloneIntoCgroupChild;

    #[test]
    fn pidfd_clone_reaps_an_immediate_successful_exit() -> Result<(), Box<dyn std::error::Error>> {
        let mut child = match CloneIntoCgroupChild::spawn_with_setup(
            None,
            Command::new("/bin/true"),
            || Ok(()),
        ) {
            Ok(child) => child,
            Err(error) if clone3_is_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        let status = child.wait()?;
        assert_eq!(status.exit_status(), Some(0));
        Ok(())
    }

    #[test]
    fn pidfd_clone_reports_exec_failure_before_start() -> Result<(), Box<dyn std::error::Error>> {
        let error = match CloneIntoCgroupChild::spawn_with_setup(
            None,
            Command::new("/erebor-test-missing-executable"),
            || Ok(()),
        ) {
            Ok(mut child) => {
                let _status = child.wait()?;
                return Err("missing executable started".into());
            }
            Err(error) if clone3_is_unavailable(&error) => return Ok(()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        Ok(())
    }

    fn clone3_is_unavailable(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(errno)
                if errno == rustix::io::Errno::NOSYS.raw_os_error()
                    || errno == rustix::io::Errno::PERM.raw_os_error()
        )
    }
}
