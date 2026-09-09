use std::cell::RefCell;
use std::fs;
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use snafu::{ensure, ResultExt as _};

use super::{invalid_state, NativeProcessFixture, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::{wait_for, wait_for_process};
use crate::Result;

const READY: &[u8] = b"native-fixture-ready\n";

impl NativeProcessFixture {
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
                        Ok(0) => Err(invalid_state(
                            "native fixture closed its readiness pipe before the input barrier",
                        )),
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
                        let outer = self.outer.try_wait().context(IoSnafu {
                            path: Path::new("identity test shell"),
                        })?;
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
                let Some(status) = self.outer.try_wait().context(IoSnafu { path })? else {
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
                let Some(status) = self.outer.try_wait().context(IoSnafu {
                    path: Path::new("post-PONR identity fixture"),
                })?
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
                let Some(status) = self.outer.try_wait().context(IoSnafu { path })? else {
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
