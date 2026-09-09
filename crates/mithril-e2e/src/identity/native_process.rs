#[cfg(test)]
mod exec_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::cell::RefCell;
#[cfg(test)]
use std::collections::BTreeSet;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use rustix::process::{pidfd_send_signal, Signal};
use snafu::{ensure, ResultExt as _};

use super::{invalid_state, open_pidfd, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::process::{process_program, wait_for_process, ProcessFixture};
use crate::Result;

const READY: &[u8] = b"native-fixture-ready\n";

pub(super) struct NativeProcessFixture {
    outer: ProcessFixture,
    stdin: Option<ChildStdin>,
    ready_stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    native_pid: Option<u32>,
    native_pidfd: Option<OwnedFd>,
    intermediate_pidfd: Option<OwnedFd>,
    namespace_init_pidfd: Option<OwnedFd>,
    parent_exit_mode: bool,
}

impl NativeProcessFixture {
    pub(super) fn start() -> Result<Self> {
        Self::start_with_parent_exit(false)
    }

    pub(super) fn start_orphaning() -> Result<Self> {
        Self::start_with_parent_exit(true)
    }

    pub(super) fn start_subreaper(repo_root: &Path) -> Result<Self> {
        let script = process_program(repo_root, "native_subreaper.py")?;
        let mut command = Command::new("python3");
        command.arg(&script);
        Self::start_command(&mut command, false, Path::new("python3"), &script)
    }

    pub(super) fn start_namespace_init_reparenting(repo_root: &Path) -> Result<Self> {
        let script = process_program(repo_root, "native_namespace_init.py")?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--pid", "--fork", "python3"])
            .arg(&script);
        Self::start_command(&mut command, false, Path::new("/usr/bin/unshare"), &script)
    }

    pub(super) fn start_pid_tid_reuse(repo_root: &Path, work: &Path) -> Result<Self> {
        let script = process_program(repo_root, "native_pid_tid_reuse.py")?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--pid", "--fork", "--mount-proc", "python3"])
            .arg(&script)
            .arg(work);
        Self::start_command(&mut command, false, Path::new("/usr/bin/unshare"), &script)
    }

    pub(super) fn start_double_forking() -> Result<Self> {
        Self::start_with_script(
            "read _; ( ( read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300 ) & wait ) & middle_pid=$!; wait \"$middle_pid\"; exec /bin/sleep 300",
            false,
        )
    }

    fn start_with_parent_exit(parent_exit_mode: bool) -> Result<Self> {
        let parent_wait = if parent_exit_mode {
            "read _"
        } else {
            "wait \"$!\""
        };
        let script = format!(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300) & {parent_wait}"
        );
        Self::start_with_script(&script, parent_exit_mode)
    }

    pub(super) fn start_with_script(script: &str, parent_exit_mode: bool) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        let script = format!("printf 'native-fixture-ready\\n'; {script}");
        command.args(["-c", &script]);
        Self::start_command(
            &mut command,
            parent_exit_mode,
            Path::new("/bin/sh"),
            Path::new("/bin/sh"),
        )
    }

    pub(super) fn start_with_failed_exec(execfail: &Path, ready: &Path) -> Result<Self> {
        let mut command = Command::new("/bin/bash");
        command
            .args([
                "-c",
                "printf 'native-fixture-ready\\n'; read _; /bin/bash -c 'read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; shopt -s execfail; exec \"$0\"; : > \"$1\"; kill -STOP \"$child_pid\"; exec /bin/sleep 300' \"$0\" \"$1\" & wait \"$!\"",
            ])
            .arg(execfail)
            .arg(ready);
        Self::start_command(
            &mut command,
            false,
            Path::new("/bin/bash"),
            Path::new("/bin/bash"),
        )
    }

    pub(super) fn start_with_post_ponr_exec(execfail: &Path) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf 'native-fixture-ready\\n'; read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec \"$0\") & wait \"$!\"",
            ])
            .arg(execfail);
        Self::start_command(
            &mut command,
            false,
            Path::new("/bin/sh"),
            Path::new("/bin/sh"),
        )
    }

    pub(super) fn start_with_leader_first_exit(
        repo_root: &Path,
        ready: &Path,
        release: &Path,
    ) -> Result<Self> {
        let script = process_program(repo_root, "native_leader_first.py")?;
        let mut command = Command::new("python3");
        command.arg(&script).arg(ready).arg(release);
        Self::start_command(&mut command, false, Path::new("python3"), &script)
    }

    pub(super) fn start_with_non_leader_exec(repo_root: &Path, ready: &Path) -> Result<Self> {
        let script = process_program(repo_root, "native_non_leader_exec.py")?;
        let mut command = Command::new("python3");
        command.arg(&script).arg(ready);
        Self::start_command(&mut command, false, Path::new("python3"), &script)
    }

    #[cfg(test)]
    pub(super) fn start_with_concurrent_thread_exec(
        repo_root: &Path,
        ready: &Path,
    ) -> Result<Self> {
        let script = process_program(repo_root, "native_concurrent_thread_exec.py")?;
        let mut command = Command::new("python3");
        command.arg(&script).arg(ready);
        Self::start_command(&mut command, false, Path::new("python3"), &script)
    }

    fn start_command(
        command: &mut Command,
        parent_exit_mode: bool,
        program: &Path,
        readiness_path: &Path,
    ) -> Result<Self> {
        let mut outer = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu { path: program })?;
        let stdin = outer
            .stdin
            .take()
            .ok_or_else(|| invalid_state("test shell has no stdin pipe"))?;
        let ready_stdout = outer
            .stdout
            .take()
            .ok_or_else(|| invalid_state("test shell has no readiness pipe"))?;
        let stderr = outer
            .stderr
            .take()
            .ok_or_else(|| invalid_state("test shell has no stderr pipe"))?;
        let mut fixture = Self {
            outer: ProcessFixture::new(outer),
            stdin: Some(stdin),
            ready_stdout: Some(ready_stdout),
            stderr: Some(stderr),
            native_pid: None,
            native_pidfd: None,
            intermediate_pidfd: None,
            namespace_init_pidfd: None,
            parent_exit_mode,
        };
        fixture.wait_for_startup(readiness_path)?;
        Ok(fixture)
    }

    pub(super) fn outer_pid(&self) -> u32 {
        self.outer.id()
    }

    pub(super) fn open_native_pidfd(&mut self, pid: u32) -> Result<()> {
        self.native_pid = Some(pid);
        self.native_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    pub(super) fn wait_for_native_child(&mut self, operation: &str) -> Result<u32> {
        let outer_pid = self.outer_pid();
        let path = PathBuf::from(format!("/proc/{outer_pid}/task/{outer_pid}/children"));
        let pid = wait_for(
            &path,
            operation,
            WAIT_LIMIT,
            || self.native_child_pid(),
            || format!("outer process {outer_pid} is running without a child"),
        )?;
        self.open_native_pidfd(pid)?;
        Ok(pid)
    }

    #[cfg(test)]
    pub(super) fn wait_for_executable(
        &self,
        native_pid: u32,
        executable: &str,
        operation: &str,
    ) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{native_pid}/comm"));
        let last = RefCell::new(String::from("<unread>"));
        wait_for(
            &path,
            operation,
            WAIT_LIMIT,
            || {
                let name = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
                *last.borrow_mut() = name.trim().to_owned();
                Ok((name.trim() == executable).then_some(()))
            },
            || {
                format!(
                    "last executable: {:?}; expected: {executable:?}",
                    last.borrow()
                )
            },
        )
    }

    pub(super) fn open_intermediate_pidfd(&mut self, pid: u32) -> Result<()> {
        self.intermediate_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    pub(super) fn open_namespace_init_pidfd(&mut self, pid: u32) -> Result<()> {
        self.namespace_init_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    pub(super) fn release_root(&mut self) -> Result<()> {
        self.write_stdin("native root release", b"root\n")
    }

    pub(super) fn release_namespace_init(&mut self) -> Result<()> {
        self.write_stdin("namespace init release", b"namespace-init\n")
    }

    pub(super) fn release_non_leader_exec(&mut self) -> Result<()> {
        self.write_stdin("non-leader exec release", b"exec\n")
    }

    #[cfg(test)]
    pub(super) fn release_concurrent_thread_exec(&mut self) -> Result<()> {
        self.write_stdin("concurrent thread exec release", b"exec\n")
    }

    pub(super) fn release_exec(&mut self, native_pid: u32) -> Result<()> {
        self.wait_for_stopped_native_child(native_pid)?;
        let pidfd = self
            .native_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("native child has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release native child exec: {error}")))
    }

    pub(super) fn release_parent_exit(&mut self) -> Result<()> {
        ensure!(
            self.parent_exit_mode,
            InvalidInputSnafu {
                path: Path::new("identity test shell"),
                reason: "native fixture does not have a parent-exit release",
            }
        );
        self.write_stdin("native parent exit release", b"parent-exit\n")
    }

    pub(super) fn release_intermediate_exit(&mut self) -> Result<()> {
        let pidfd = self
            .intermediate_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("double-fork intermediate has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::TERM)
            .map_err(|error| invalid_state(format!("release intermediate exit: {error}")))
    }

    pub(super) fn release_intermediate_start(&mut self, intermediate_pid: u32) -> Result<()> {
        self.wait_for_stopped_native_child(intermediate_pid)?;
        let pidfd = self
            .intermediate_pidfd
            .as_ref()
            .ok_or_else(|| invalid_state("PID-namespace intermediate has no pidfd"))?;
        pidfd_send_signal(pidfd, Signal::CONT)
            .map_err(|error| invalid_state(format!("release intermediate start: {error}")))
    }

    pub(super) fn intermediate_exited(&self, intermediate_pid: u32) -> Result<bool> {
        let path = PathBuf::from(format!("/proc/{intermediate_pid}/status"));
        match fs::read_to_string(&path) {
            Ok(status) => Ok(status.lines().any(|line| line.starts_with("State:\tZ"))),
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(libc::ESRCH) =>
            {
                Ok(true)
            }
            Err(source) => Err(source).context(IoSnafu { path: &path }),
        }
    }

    pub(super) fn wait_for_parent_exit(&mut self) -> Result<()> {
        let status = self.outer.wait(Path::new("identity test shell"))?;
        ensure!(
            status.success(),
            InvalidInputSnafu {
                path: Path::new("identity test shell"),
                reason: format!("native parent exited with {status}"),
            }
        );
        self.stdin.take();
        Ok(())
    }

    fn write_stdin(&mut self, operation: &'static str, bytes: &[u8]) -> Result<()> {
        self.stdin
            .as_mut()
            .ok_or_else(|| invalid_state("test shell stdin is closed"))?
            .write_all(bytes)
            .context(IoSnafu {
                path: Path::new(operation),
            })
    }

    pub(super) fn native_child_pid(&mut self) -> Result<Option<u32>> {
        if let Some(status) = self.outer.try_wait(Path::new("identity test shell"))? {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("identity test shell stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "identity test shell exited before creating its child ({status}): {}",
                stderr.trim()
            )));
        }
        self.first_child_pid(self.outer.id())
    }

    pub(super) fn non_leader_thread_tid(&mut self, ready: &Path) -> Result<Option<u32>> {
        if let Some(status) = self
            .outer
            .try_wait(Path::new("non-leader thread fixture"))?
        {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("non-leader thread fixture stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "non-leader thread fixture exited before it reported its TID ({status}): {}",
                stderr.trim()
            )));
        }
        let text = match fs::read_to_string(ready) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: ready }),
        };
        if text.trim().is_empty() {
            return Ok(None);
        }
        let tid = text.trim().parse::<u32>().map_err(|source| {
            invalid_state(format!(
                "non-leader thread fixture wrote an invalid TID `{}`: {source}",
                text.trim()
            ))
        })?;
        Ok(Some(tid))
    }

    pub(super) fn reported_tid(&mut self, ready: &Path) -> Result<Option<u32>> {
        self.non_leader_thread_tid(ready)
    }

    #[cfg(test)]
    pub(super) fn concurrent_thread_tids(&mut self, ready: &Path) -> Result<Option<[u32; 2]>> {
        if let Some(status) = self
            .outer
            .try_wait(Path::new("concurrent thread fixture"))?
        {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.stderr.take() {
                pipe.read_to_string(&mut stderr).context(IoSnafu {
                    path: Path::new("concurrent thread fixture stderr"),
                })?;
            }
            return Err(invalid_state(format!(
                "concurrent thread fixture exited before it reported its TIDs ({status}): {}",
                stderr.trim()
            )));
        }
        let text = match fs::read_to_string(ready) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: ready }),
        };
        let mut tids = text
            .split_ascii_whitespace()
            .map(|value| {
                value.parse::<u32>().map_err(|source| {
                    invalid_state(format!(
                        "concurrent thread fixture wrote an invalid TID `{value}`: {source}"
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            tids.len() == 2,
            InvalidInputSnafu {
                path: ready,
                reason: format!(
                    "concurrent thread fixture must report two distinct TIDs, got {}",
                    tids.len()
                ),
            }
        );
        let first = tids
            .pop_first()
            .ok_or_else(|| invalid_state("first concurrent thread TID is missing"))?;
        let second = tids
            .pop_first()
            .ok_or_else(|| invalid_state("second concurrent thread TID is missing"))?;
        Ok(Some([first, second]))
    }

    pub(super) fn intermediate_pid(&mut self) -> Result<Option<u32>> {
        self.native_child_pid()
    }

    pub(super) fn intermediate_native_child_pid(
        &self,
        intermediate_pid: u32,
    ) -> Result<Option<u32>> {
        self.first_child_pid(intermediate_pid)
    }

    pub(super) fn namespace_init_pid(&mut self) -> Result<Option<u32>> {
        self.native_child_pid()
    }

    pub(super) fn namespace_init_intermediate_pid(
        &self,
        namespace_init_pid: u32,
    ) -> Result<Option<u32>> {
        self.first_child_pid(namespace_init_pid)
    }

    pub(super) fn first_child_pid(&self, pid: u32) -> Result<Option<u32>> {
        let path = PathBuf::from(format!("/proc/{pid}/task/{pid}/children"));
        let children = match fs::read_to_string(&path) {
            Ok(children) => children,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };
        children
            .split_ascii_whitespace()
            .next()
            .map(|value| {
                value.parse().map_err(|error| {
                    invalid_state(format!("invalid native child PID `{value}`: {error}"))
                })
            })
            .transpose()
    }

    pub(super) fn stop(&mut self) {
        if let Some(pidfd) = &self.native_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        if let Some(pidfd) = &self.intermediate_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        if let Some(pidfd) = &self.namespace_init_pidfd {
            let _result = pidfd_send_signal(pidfd, Signal::KILL);
        }
        let _result = self.outer.stop(Path::new("identity test shell"));
        self.stdin.take();
    }

    pub(super) fn wait_for_startup(&mut self, command: &Path) -> Result<()> {
        let stdout = self
            .ready_stdout
            .as_ref()
            .ok_or_else(|| invalid_state("native fixture has no readiness pipe"))?;
        let flags = rustix::fs::fcntl_getfl(stdout)
            .map_err(|error| invalid_state(format!("read readiness pipe flags: {error}")))?;
        rustix::fs::fcntl_setfl(stdout, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| invalid_state(format!("make readiness pipe nonblocking: {error}")))?;

        let readiness_path = PathBuf::from(format!("{} readiness pipe", command.display()));
        let received = RefCell::new(Vec::new());
        {
            let stdout = self
                .ready_stdout
                .as_mut()
                .ok_or_else(|| invalid_state("native fixture readiness pipe closed early"))?;
            let stderr = &mut self.stderr;
            wait_for_process(
                &mut self.outer,
                &readiness_path,
                "the native fixture input barrier",
                WAIT_LIMIT,
                || {
                    let mut buffer = [0_u8; 64];
                    match stdout.read(&mut buffer) {
                        Ok(0) => Ok(None),
                        Ok(count) => {
                            let mut received = received.borrow_mut();
                            received.extend_from_slice(&buffer[..count]);
                            if received.as_slice() == READY {
                                Ok(Some(()))
                            } else if READY.starts_with(received.as_slice()) {
                                Ok(None)
                            } else {
                                Err(invalid_state(format!(
                                    "native fixture wrote an invalid readiness marker: {:?}",
                                    String::from_utf8_lossy(&received)
                                )))
                            }
                        }
                        Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(None),
                        Err(source) => Err(source).context(IoSnafu {
                            path: &readiness_path,
                        }),
                    }
                },
                || {
                    let mut output = String::new();
                    if let Some(mut pipe) = stderr.take() {
                        pipe.read_to_string(&mut output).context(IoSnafu {
                            path: Path::new("native fixture stderr"),
                        })?;
                    }
                    Ok(format!("stderr: {:?}", output.trim()))
                },
                || {
                    format!(
                        "received readiness bytes {:?}",
                        String::from_utf8_lossy(&received.borrow())
                    )
                },
            )?;
        }
        self.ready_stdout.take();
        Ok(())
    }

    pub(super) fn wait_for_stopped_native_child(&mut self, native_pid: u32) -> Result<()> {
        let status_path = PathBuf::from(format!("/proc/{native_pid}/status"));
        let last_state = RefCell::new(String::from("State: <unread>"));
        wait_for(
            &status_path,
            "the native child to stop before exec release",
            WAIT_LIMIT,
            || {
                let status = match fs::read_to_string(&status_path) {
                    Ok(status) => status,
                    Err(source) if source.kind() == ErrorKind::NotFound => {
                        let outer = self.outer.try_wait(Path::new("identity test shell"))?;
                        let stderr = if outer.is_some() {
                            self.stdin.take();
                            let mut stderr = String::new();
                            if let Some(mut pipe) = self.stderr.take() {
                                pipe.read_to_string(&mut stderr).context(IoSnafu {
                                    path: Path::new("identity test shell stderr"),
                                })?;
                            }
                            format!("; outer {outer:?}; stderr {}", stderr.trim())
                        } else {
                            String::from("; outer still running")
                        };
                        return Err(invalid_state(format!(
                            "native child {native_pid} exited before it stopped for exec release{stderr}"
                        )));
                    }
                    Err(source) => return Err(source).context(IoSnafu { path: &status_path }),
                };
                *last_state.borrow_mut() = status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .unwrap_or("State: <missing>")
                    .to_owned();
                Ok(status
                    .lines()
                    .any(|line| line.starts_with("State:\tT"))
                    .then_some(()))
            },
            || format!("native child {native_pid}; last {}", last_state.borrow()),
        )
    }

    pub(super) fn wait_for_native_exec_failure(&mut self) -> Result<()> {
        let path = Path::new("identity test shell");
        wait_for(
            path,
            "the native child exec to fail",
            Duration::from_secs(5),
            || {
                let Some(status) = self.outer.try_wait(path)? else {
                    return Ok(None);
                };
                self.stdin.take();
                ensure!(
                    !status.success(),
                    InvalidInputSnafu {
                        path,
                        reason: format!("native child exec unexpectedly completed with {status}"),
                    }
                );
                Ok(Some(()))
            },
            || "the identity test shell was still running".to_owned(),
        )
    }

    pub(super) fn wait_for_post_ponr_fatal(&mut self, native_pid: u32) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{native_pid}"));
        wait_for(
            &path,
            "the post-PONR exec failure to terminate its task",
            Duration::from_secs(5),
            || {
                let Some(status) = self
                    .outer
                    .try_wait(Path::new("post-PONR identity fixture"))?
                else {
                    return Ok(None);
                };
                self.stdin.take();
                ensure!(
                    !status.success() && !path.exists(),
                    InvalidInputSnafu {
                        path: &path,
                        reason: format!(
                            "post-PONR exec did not terminate its task; outer status {status}"
                        ),
                    }
                );
                Ok(Some(()))
            },
            || format!("native child {native_pid} and its outer shell were still running"),
        )
    }

    pub(super) fn wait_for_successful_exit(&mut self) -> Result<()> {
        let path = Path::new("leader-first identity fixture");
        wait_for(
            path,
            "the leader-first worker to exit",
            Duration::from_secs(5),
            || {
                let Some(status) = self.outer.try_wait(path)? else {
                    return Ok(None);
                };
                self.stdin.take();
                ensure!(
                    status.success(),
                    InvalidInputSnafu {
                        path,
                        reason: format!("leader-first fixture exited with {status}"),
                    }
                );
                Ok(Some(()))
            },
            || "the leader-first worker was still running".to_owned(),
        )
    }
}

impl Drop for NativeProcessFixture {
    fn drop(&mut self) {
        self.stop();
    }
}
