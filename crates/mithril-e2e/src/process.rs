#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Duration;

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
    stopped: bool,
}

impl ProcessFixture {
    pub(crate) fn new(mut child: Child, path: &Path) -> Self {
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
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
        let child = Command::new("python3")
            .arg(&script)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(IoSnafu { path: &script })?;
        let mut fixture = Self::new(child, &script);
        fixture.ready()?;
        Ok(fixture)
    }

    pub(crate) fn id(&self) -> u32 {
        self.child.id()
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

    #[cfg(test)]
    pub(crate) fn wait_comm(&mut self, pid: u32, name: &str, operation: &str) -> Result<()> {
        let path = PathBuf::from(format!("/proc/{pid}/comm"));
        let last = RefCell::new(String::from("<absent>"));
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
                *last.borrow_mut() = text.trim().to_owned();
                Ok((text.trim() == name).then_some(()))
            },
            || format!("last process name: {:?}; expected: {name:?}", last.borrow()),
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
        if self.stopped {
            return Ok(());
        }
        if self.try_wait()?.is_none() {
            self.child.kill().context(IoSnafu { path: &self.path })?;
            self.wait()?;
        }
        Ok(())
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
