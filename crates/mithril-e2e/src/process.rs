#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Duration;

use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
use snafu::{ensure, OptionExt as _, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::Result;

const FIXTURE_DIR: &str = "crates/mithril-e2e/fixtures/process";
const LOG_LIMIT: usize = 8 * 1024;
const READY: &[u8] = b"native-fixture-ready\n";
const START_LIMIT: Duration = Duration::from_secs(30);

pub(crate) struct ProcessFixture {
    child: Child,
    path: PathBuf,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    tasks: Vec<(u32, OwnedFd)>,
    stopped: bool,
}

impl ProcessFixture {
    pub(crate) fn new(mut child: Child, path: &Path) -> Self {
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            tasks: Vec::new(),
            child,
            path: path.to_owned(),
            stopped: false,
        }
    }

    pub(crate) fn script(root: &Path, name: &str) -> Result<PathBuf> {
        let path = root.join(FIXTURE_DIR).join(name);
        ensure!(
            path.is_file(),
            InvalidInputSnafu {
                path: &path,
                reason: "the process fixture program is missing",
            }
        );
        Ok(path)
    }

    pub(crate) fn python<I, S>(root: &Path, name: &str, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let mut command = Command::new("python3");
        command.arg(&script).args(args);
        Self::start(&mut command, &script)
    }

    pub(crate) fn unshare<I, S>(root: &Path, name: &str, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let script = Self::script(root, name)?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--pid", "--fork", "python3"])
            .arg(&script)
            .args(args);
        Self::start(&mut command, &script)
    }

    pub(crate) fn start(command: &mut Command, path: &Path) -> Result<Self> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu { path })?;
        let mut fixture = Self::new(child, path);
        fixture.ready()?;
        Ok(fixture)
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn track(&mut self, id: u32) -> Result<()> {
        if self.tasks.iter().any(|(known, _)| *known == id) {
            return Ok(());
        }
        let raw = i32::try_from(id).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("the tracked PID is invalid: {source}"),
            }
            .build()
        })?;
        let pid = Pid::from_raw(raw).context(InvalidInputSnafu {
            path: &self.path,
            reason: "PID zero cannot identify a tracked process",
        })?;
        let fd = pidfd_open(pid, PidfdFlags::empty()).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("open pidfd for {id}: {source}"),
            }
            .build()
        })?;
        self.tasks.push((id, fd));
        Ok(())
    }

    pub(crate) fn signal(&self, id: u32, signal: Signal) -> Result<()> {
        let fd = self
            .tasks
            .iter()
            .find_map(|(known, fd)| (*known == id).then_some(fd))
            .context(InvalidInputSnafu {
                path: &self.path,
                reason: "the process is not tracked",
            })?;
        pidfd_send_signal(fd, signal).map_err(|source| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("signal tracked process {id}: {source}"),
            }
            .build()
        })
    }

    pub(crate) fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.stdin
            .as_mut()
            .context(InvalidInputSnafu {
                path: &self.path,
                reason: "the process stdin is closed",
            })?
            .write_all(bytes)
            .context(IoSnafu { path: &self.path })
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.child
            .try_wait()
            .context(IoSnafu { path: &self.path })
            .inspect(|status| self.stopped |= status.is_some())
    }

    pub(crate) fn wait(&mut self) -> Result<ExitStatus> {
        self.child
            .wait()
            .context(IoSnafu { path: &self.path })
            .inspect(|_status| self.stopped = true)
    }

    pub(crate) fn wait_exit(&mut self, operation: &str, limit: Duration) -> Result<ExitStatus> {
        let path = self.path.clone();
        wait_for(
            &path,
            operation,
            limit,
            || self.try_wait(),
            || "the process is still running".to_owned(),
        )
    }

    pub(crate) fn wait_pid(&mut self, path: &Path, operation: &str) -> Result<u32> {
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                *last.borrow_mut() = text.trim().to_owned();
                if text.trim().is_empty() {
                    return Ok(None);
                }
                text.trim().parse::<u32>().map(Some).map_err(|source| {
                    InvalidInputSnafu {
                        path,
                        reason: format!("the actor wrote an invalid PID: {source}"),
                    }
                    .build()
                })
            },
            || format!("last PID value: {:?}", last.borrow()),
        )
    }

    pub(crate) fn wait_pair(&mut self, path: &Path, operation: &str) -> Result<[u32; 2]> {
        let last = RefCell::new(String::from("<absent>"));
        self.wait_path(
            path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path }),
                };
                *last.borrow_mut() = text.trim().to_owned();
                let ids = text
                    .split_ascii_whitespace()
                    .map(|value| {
                        value.parse::<u32>().map_err(|source| {
                            InvalidInputSnafu {
                                path,
                                reason: format!("the actor wrote an invalid PID: {source}"),
                            }
                            .build()
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                if ids.len() < 2 {
                    return Ok(None);
                }
                ensure!(
                    ids.len() == 2 && ids[0] != ids[1],
                    InvalidInputSnafu {
                        path,
                        reason: "the actor must report two distinct PIDs",
                    }
                );
                Ok(Some([ids[0], ids[1]]))
            },
            || format!("last PID values: {:?}", last.borrow()),
        )
    }

    pub(crate) fn wait_stop(&mut self, id: u32, operation: &str) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{id}/status"));
        let last = RefCell::new(String::from("State: <absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || {
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                *last.borrow_mut() = text
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .unwrap_or("State: <missing>")
                    .to_owned();
                Ok(text
                    .lines()
                    .any(|line| line.starts_with("State:\tT"))
                    .then_some(()))
            },
            || format!("process {id}; last {}", last.borrow()),
        )
    }

    pub(crate) fn wait_gone(&mut self, id: u32, operation: &str) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{id}/status"));
        let last = RefCell::new(String::from("State: <absent>"));
        self.wait_path(
            &path,
            operation,
            START_LIMIT,
            || match fs::read_to_string(&path) {
                Ok(text) => {
                    *last.borrow_mut() = text
                        .lines()
                        .find(|line| line.starts_with("State:"))
                        .unwrap_or("State: <missing>")
                        .to_owned();
                    Ok(None)
                }
                Err(source) if source.kind() == ErrorKind::NotFound => Ok(Some(())),
                Err(source) => Err(source).context(IoSnafu { path: &path }),
            },
            || format!("process {id}; last {}", last.borrow()),
        )
    }

    pub(crate) fn wait_path<T>(
        &mut self,
        path: &Path,
        operation: &str,
        limit: Duration,
        mut inspect: impl FnMut() -> Result<Option<T>>,
        state: impl Fn() -> String,
    ) -> Result<T> {
        let state = &state;
        wait_for(
            path,
            operation,
            limit,
            || {
                if let Some(value) = inspect()? {
                    return Ok(Some(value));
                }
                if !self.stopped {
                    if let Some(status) = self.try_wait()? {
                        return InvalidInputSnafu {
                            path,
                            reason: format!(
                                "the process exited with {status} before {operation}; {}; stderr: {:?}",
                                state(),
                                self.stderr()?
                            ),
                        }
                        .fail();
                    }
                }
                Ok(None)
            },
            state,
        )
    }

    pub(crate) fn stderr(&mut self) -> Result<String> {
        let Some(stderr) = self.stderr.as_mut() else {
            return Ok("<not captured>".to_owned());
        };
        let flags = rustix::fs::fcntl_getfl(&*stderr).map_err(|error| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("read stderr pipe flags: {error}"),
            }
            .build()
        })?;
        rustix::fs::fcntl_setfl(&*stderr, flags | rustix::fs::OFlags::NONBLOCK).map_err(
            |error| {
                InvalidInputSnafu {
                    path: &self.path,
                    reason: format!("make stderr pipe nonblocking: {error}"),
                }
                .build()
            },
        )?;
        let mut output = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count]);
                    if output.len() >= LOG_LIMIT {
                        output.drain(..output.len() - LOG_LIMIT);
                    }
                }
                Err(source) if source.kind() == ErrorKind::WouldBlock => break,
                Err(source) => return Err(source).context(IoSnafu { path: &self.path }),
            }
        }
        Ok(String::from_utf8_lossy(&output).trim().to_owned())
    }

    pub(crate) fn close(&mut self) {
        self.stdin.take();
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        self.close();
        let mut failed = None;
        let ids = self.tasks.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        for (id, fd) in &self.tasks {
            match pidfd_send_signal(fd, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(source) => failed = Some(format!("kill tracked process {id}: {source}")),
            }
        }
        self.tasks.clear();
        if !self.stopped && self.try_wait()?.is_none() {
            self.child.kill().context(IoSnafu { path: &self.path })?;
            self.wait()?;
        }
        for id in ids {
            let path = PathBuf::from(format!("/proc/{id}"));
            if let Err(source) = wait_for(
                &path,
                "tracked process cleanup",
                START_LIMIT,
                || Ok((!path.exists()).then_some(())),
                || format!("tracked process {id} still exists"),
            ) {
                failed = Some(source.to_string());
            }
        }
        match failed {
            Some(reason) => InvalidInputSnafu {
                path: &self.path,
                reason,
            }
            .fail(),
            None => Ok(()),
        }
    }

    pub(crate) fn ready(&mut self) -> Result<()> {
        let mut stdout = self.stdout.take().context(InvalidInputSnafu {
            path: &self.path,
            reason: "the process stdout is not captured",
        })?;
        let flags = rustix::fs::fcntl_getfl(&stdout).map_err(|error| {
            InvalidInputSnafu {
                path: &self.path,
                reason: format!("read readiness pipe flags: {error}"),
            }
            .build()
        })?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK).map_err(
            |error| {
                InvalidInputSnafu {
                    path: &self.path,
                    reason: format!("make readiness pipe nonblocking: {error}"),
                }
                .build()
            },
        )?;

        let path = self.path.clone();
        let received = RefCell::new(Vec::new());
        self.wait_path(
            &path,
            "the process input barrier",
            START_LIMIT,
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
                            InvalidInputSnafu {
                                path: &path,
                                reason: format!(
                                    "invalid readiness marker: {:?}",
                                    String::from_utf8_lossy(&received)
                                ),
                            }
                            .fail()
                        }
                    }
                    Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(None),
                    Err(source) => Err(source).context(IoSnafu { path: &path }),
                }
            },
            || {
                format!(
                    "received readiness bytes {:?}",
                    String::from_utf8_lossy(&received.borrow())
                )
            },
        )
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        let _result = self.stop();
    }
}
