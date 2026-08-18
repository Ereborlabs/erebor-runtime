#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use linux_raw_sys::general::clone_args;
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::Result;

pub(super) struct CloneIntoCgroupFixture {
    root_pid: u32,
    root_pidfd: OwnedFd,
    child_pidfd: Option<OwnedFd>,
    namespace_target: Option<Child>,
    namespace_target_pipe: Option<File>,
    native_child_effect_status: Option<File>,
}

impl CloneIntoCgroupFixture {
    pub(super) fn start(cgroup_path: &Path) -> Result<Self> {
        Self::start_with_namespace_target(cgroup_path, None, None, None)
    }

    pub(super) fn start_with_root_first_effect(cgroup_path: &Path, path: &Path) -> Result<Self> {
        Self::start_with_namespace_target(cgroup_path, None, Some(path), None)
    }

    pub(super) fn start_with_native_child_first_effect(
        cgroup_path: &Path,
        path: &Path,
    ) -> Result<Self> {
        Self::start_with_namespace_target(cgroup_path, None, None, Some(path))
    }

    pub(super) fn start_with_mount_namespace_target(cgroup_path: &Path) -> Result<Self> {
        let target = start_mount_namespace_target()?;
        Self::start_with_namespace_target(cgroup_path, Some(target), None, None)
    }

    fn start_with_namespace_target(
        cgroup_path: &Path,
        mut namespace_target: Option<Child>,
        first_effect_path: Option<&Path>,
        native_child_first_effect_path: Option<&Path>,
    ) -> Result<Self> {
        let cgroup = match File::open(cgroup_path).context(IoSnafu { path: cgroup_path }) {
            Ok(cgroup) => cgroup,
            Err(error) => {
                stop_namespace_target(&mut namespace_target);
                return Err(error);
            }
        };
        let (namespace_target_read, namespace_target_pipe) = if namespace_target.is_some() {
            match namespace_target_pipe() {
                Ok((read, write)) => (Some(read), Some(write)),
                Err(error) => {
                    stop_namespace_target(&mut namespace_target);
                    return Err(error);
                }
            }
        } else {
            (None, None)
        };
        let (native_child_effect_status, native_child_effect_status_write) =
            if native_child_first_effect_path.is_some() {
                match native_child_effect_status_pipe() {
                    Ok((read, write)) => (Some(read), Some(write)),
                    Err(error) => {
                        stop_namespace_target(&mut namespace_target);
                        return Err(error);
                    }
                }
            } else {
                (None, None)
            };
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
            run_child(
                namespace_target_read.as_ref().map(|file| file.as_raw_fd()),
                first_effect_path,
                native_child_first_effect_path,
                native_child_effect_status_write
                    .as_ref()
                    .map(|file| file.as_raw_fd()),
            );
        }
        if result < 0 {
            stop_namespace_target(&mut namespace_target);
            return Err(invalid_state(format!(
                "clone3(CLONE_INTO_CGROUP) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        drop(namespace_target_read);
        drop(native_child_effect_status_write);
        let root_pid = u32::try_from(result)
            .map_err(|error| invalid_state(format!("clone3 returned an invalid PID: {error}")))?;
        let root_pidfd = match open_pidfd(root_pid) {
            Ok(root_pidfd) => root_pidfd,
            Err(error) => {
                unsafe {
                    libc::kill(result as libc::pid_t, libc::SIGKILL);
                    libc::waitpid(result as libc::pid_t, std::ptr::null_mut(), 0);
                }
                stop_namespace_target(&mut namespace_target);
                return Err(error);
            }
        };
        Ok(Self {
            root_pid,
            root_pidfd,
            child_pidfd: None,
            namespace_target,
            namespace_target_pipe,
            native_child_effect_status,
        })
    }

    pub(super) const fn root_pid(&self) -> u32 {
        self.root_pid
    }

    pub(super) fn release_root(&self) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{}/status", self.root_pid));
        let mut stopped = false;
        for _attempt in 0..500 {
            let status = std::fs::read_to_string(&path).context(IoSnafu { path: &path })?;
            if status.lines().any(|line| line.starts_with("State:\tT")) {
                stopped = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        ensure!(
            stopped,
            InvalidInputSnafu {
                path: &path,
                reason: "CLONE_INTO_CGROUP root did not reach its stop barrier",
            }
        );
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

    pub(super) fn target_mount_namespace(&mut self) -> Result<PathBuf> {
        let target = self
            .namespace_target
            .as_mut()
            .ok_or_else(|| invalid_state("clone fixture has no mount-namespace target"))?;
        ensure!(
            target
                .try_wait()
                .context(IoSnafu {
                    path: Path::new("mount-namespace target"),
                })?
                .is_none(),
            InvalidInputSnafu {
                path: Path::new("mount-namespace target"),
                reason: "mount-namespace target exited before native entry",
            }
        );
        let path = PathBuf::from(format!("/proc/{}/ns/mnt", target.id()));
        std::fs::read_link(&path).context(IoSnafu { path: &path })
    }

    pub(super) fn release_child_into_mount_namespace(&mut self) -> Result<()> {
        let target = self
            .namespace_target
            .as_mut()
            .ok_or_else(|| invalid_state("clone fixture has no mount-namespace target"))?;
        ensure!(
            target
                .try_wait()
                .context(IoSnafu {
                    path: Path::new("mount-namespace target"),
                })?
                .is_none(),
            InvalidInputSnafu {
                path: Path::new("mount-namespace target"),
                reason: "mount-namespace target exited before native entry",
            }
        );
        let mut target_argument = [0_u8; 16];
        let target_pid = target.id().to_string();
        ensure!(
            target_pid.len() < target_argument.len(),
            InvalidInputSnafu {
                path: Path::new("mount-namespace target"),
                reason: "mount-namespace target PID does not fit the fixture protocol",
            }
        );
        target_argument[..target_pid.len()].copy_from_slice(target_pid.as_bytes());
        self.namespace_target_pipe
            .as_mut()
            .ok_or_else(|| invalid_state("clone fixture has no namespace-target pipe"))?
            .write_all(&target_argument)
            .context(IoSnafu {
                path: Path::new("mount-namespace target pipe"),
            })?;
        let child_pidfd = self
            .child_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("clone fixture has no native child pidfd"))?;
        pidfd_send_signal(child_pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release native namespace entry: {error}")))
    }

    pub(super) fn release_child_first_effect(&self) -> Result<()> {
        let child_pidfd = self
            .child_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("clone fixture has no native child pidfd"))?;
        pidfd_send_signal(child_pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release native child first effect: {error}")))
    }

    pub(super) fn native_child_first_effect_allowed(&mut self) -> Result<Option<()>> {
        let status = self
            .native_child_effect_status
            .as_mut()
            .ok_or_else(|| invalid_state("clone fixture has no native-child effect status pipe"))?;
        let mut result = [0_u8; 1];
        match status.read(&mut result) {
            Ok(1) if result[0] == 0 => Ok(Some(())),
            Ok(1) => Err(invalid_state(format!(
                "native child first effect exited with status {}",
                result[0]
            ))),
            Ok(0) => Err(invalid_state(
                "native child first effect closed without an exit status",
            )),
            Ok(_) => Err(invalid_state("native child effect status is malformed")),
            Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(source) => Err(source).context(IoSnafu {
                path: Path::new("native-child first-effect status pipe"),
            }),
        }
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

    pub(super) fn moved_root_first_effect_denied(&mut self) -> Result<Option<()>> {
        let mut status = 0;
        // SAFETY: root_pid is this process's child and status is writable.
        let result =
            unsafe { libc::waitpid(self.root_pid as libc::pid_t, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(invalid_state(format!(
                "wait for moved-root first-effect exit: {}",
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
                "moved-root first effect did not fail with EACCES: {reason}"
            )));
        }
        Ok(None)
    }

    pub(super) fn root_first_effect_allowed(&mut self) -> Result<Option<()>> {
        let mut status = 0;
        // SAFETY: root_pid is this process's child and status is writable.
        let result =
            unsafe { libc::waitpid(self.root_pid as libc::pid_t, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(invalid_state(format!(
                "wait for unmoved-root first-effect exit: {}",
                std::io::Error::last_os_error()
            )));
        }
        if result == self.root_pid as libc::pid_t {
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
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
                "unmoved-root first effect did not complete: {reason}"
            )));
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
        stop_namespace_target(&mut self.namespace_target);
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

fn namespace_target_pipe() -> Result<(File, File)> {
    let mut descriptors = [-1; 2];
    let result = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    if result != 0 {
        return Err(invalid_state(format!(
            "create namespace-target pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    let read = unsafe { File::from_raw_fd(descriptors[0]) };
    let write = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((read, write))
}

fn native_child_effect_status_pipe() -> Result<(File, File)> {
    let mut descriptors = [-1; 2];
    let result =
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if result != 0 {
        return Err(invalid_state(format!(
            "create native-child first-effect status pipe: {}",
            std::io::Error::last_os_error()
        )));
    }
    let read = unsafe { File::from_raw_fd(descriptors[0]) };
    let write = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((read, write))
}

fn start_mount_namespace_target() -> Result<Child> {
    let current = std::fs::read_link("/proc/self/ns/mnt").context(IoSnafu {
        path: Path::new("/proc/self/ns/mnt"),
    })?;
    let mut target = Command::new("/usr/bin/unshare")
        .args(["--mount", "--propagation", "private", "/bin/sleep", "300"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context(IoSnafu {
            path: Path::new("/usr/bin/unshare"),
        })?;
    let path = PathBuf::from(format!("/proc/{}/ns/mnt", target.id()));
    for _ in 0..100 {
        if let Some(status) = target.try_wait().context(IoSnafu { path: &path })? {
            return Err(invalid_state(format!(
                "mount-namespace target exited before setup: {status}"
            )));
        }
        if std::fs::read_link(&path).context(IoSnafu { path: &path })? != current {
            return Ok(target);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _result = target.kill();
    let _result = target.wait();
    Err(invalid_state(
        "mount-namespace target did not enter a distinct mount namespace",
    ))
}

fn stop_namespace_target(target: &mut Option<Child>) {
    if let Some(target) = target {
        let _result = target.kill();
        let _result = target.wait();
    }
}

fn run_child(
    namespace_target_fd: Option<i32>,
    first_effect_path: Option<&Path>,
    native_child_first_effect_path: Option<&Path>,
    native_child_effect_status_fd: Option<i32>,
) -> ! {
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    if let Some(path) = first_effect_path {
        direct_open_exit(path);
    }
    let native_child = unsafe { libc::fork() };
    if native_child == 0 {
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        if let Some(path) = native_child_first_effect_path {
            let Some(status_fd) = native_child_effect_status_fd else {
                unsafe { libc::_exit(125) }
            };
            direct_open_with_status_exit(path, status_fd);
        }
        let Some(namespace_target_fd) = namespace_target_fd else {
            unsafe { libc::_exit(0) }
        };
        let mut target = [0_u8; 16];
        let mut read = 0;
        while read < target.len() {
            let result = unsafe {
                libc::read(
                    namespace_target_fd,
                    target[read..].as_mut_ptr().cast(),
                    target.len() - read,
                )
            };
            if result <= 0 {
                unsafe { libc::_exit(126) }
            }
            read += result as usize;
        }
        unsafe {
            libc::execl(
                c"/usr/bin/nsenter".as_ptr(),
                c"nsenter".as_ptr(),
                c"-t".as_ptr(),
                target.as_ptr().cast::<libc::c_char>(),
                c"-m".as_ptr(),
                c"--".as_ptr(),
                c"/bin/sleep".as_ptr(),
                c"300".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(127);
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

fn direct_open_exit(path: &Path) -> ! {
    let path =
        CString::new(path.as_os_str().as_bytes()).unwrap_or_else(|_| unsafe { libc::_exit(126) });
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor >= 0 {
        unsafe {
            libc::close(descriptor);
            libc::_exit(0);
        }
    }
    let status = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(127);
    unsafe { libc::_exit(status) }
}

fn direct_open_with_status_exit(path: &Path, status_fd: i32) -> ! {
    let path =
        CString::new(path.as_os_str().as_bytes()).unwrap_or_else(|_| unsafe { libc::_exit(126) });
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    let status = if descriptor >= 0 {
        unsafe {
            libc::close(descriptor);
        }
        0
    } else {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(127)
    };
    let byte = [u8::try_from(status).unwrap_or(127)];
    if unsafe { libc::write(status_fd, byte.as_ptr().cast(), byte.len()) } != 1 {
        unsafe { libc::_exit(125) }
    }
    unsafe { libc::_exit(status) }
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
            namespace_target: None,
            namespace_target_pipe: None,
            native_child_effect_status: None,
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
