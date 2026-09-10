use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rustix::process::{pidfd_send_signal, Signal};
use snafu::{ensure, ResultExt as _};

use super::{invalid_state, open_pidfd};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::process::ProcessFixture;
use crate::Result;

pub(super) struct NativeProcessFixture {
    outer: ProcessFixture,
    namespace_init_pidfd: Option<OwnedFd>,
}

impl NativeProcessFixture {
    pub(super) fn start() -> Result<Self> {
        Self::start_with_script(
            "read _; (read child_pid _ < /proc/self/stat; kill -STOP \"$child_pid\"; exec /bin/sleep 300) & wait \"$!\"",
        )
    }

    pub(super) fn start_pid_tid_reuse(repo_root: &Path, work: &Path) -> Result<Self> {
        let script = ProcessFixture::script(repo_root, "native_pid_tid_reuse.py")?;
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--pid", "--fork", "--mount-proc", "python3"])
            .arg(&script)
            .arg(work);
        Self::start_command(&mut command, &script)
    }

    pub(super) fn start_with_script(script: &str) -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        let script = format!("printf 'native-fixture-ready\\n'; {script}");
        command.args(["-c", &script]);
        Self::start_command(&mut command, Path::new("/bin/sh"))
    }

    fn start_command(command: &mut Command, program: &Path) -> Result<Self> {
        let outer = ProcessFixture::start(command, program)?;
        Ok(Self::from_outer(outer))
    }

    fn from_outer(outer: ProcessFixture) -> Self {
        Self {
            outer,
            namespace_init_pidfd: None,
        }
    }

    pub(super) fn outer_pid(&self) -> u32 {
        self.outer.id()
    }

    pub(super) fn open_namespace_init_pidfd(&mut self, pid: u32) -> Result<()> {
        self.namespace_init_pidfd = Some(open_pidfd(pid)?);
        Ok(())
    }

    pub(super) fn release_root(&mut self) -> Result<()> {
        self.write_stdin("native root release", b"root\n")
    }

    fn write_stdin(&mut self, _operation: &'static str, bytes: &[u8]) -> Result<()> {
        self.outer.send(bytes)
    }

    pub(super) fn native_child_pid(&mut self) -> Result<Option<u32>> {
        if let Some(status) = self.outer.try_wait()? {
            let stderr = self.outer.stderr()?;
            return Err(invalid_state(format!(
                "identity test shell exited before creating its child ({status}): {}",
                stderr
            )));
        }
        self.first_child_pid(self.outer.id())
    }

    pub(super) fn namespace_init_pid(&mut self) -> Result<Option<u32>> {
        self.native_child_pid()
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

    pub(super) fn stop(&mut self) -> Result<()> {
        for pidfd in self.namespace_init_pidfd.iter() {
            match pidfd_send_signal(pidfd, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => {
                    return Err(invalid_state(format!(
                        "stop native process fixture: {error}"
                    )))
                }
            }
        }
        self.outer.stop()
    }

    pub(super) fn wait_for_successful_exit(&mut self) -> Result<()> {
        let path = Path::new("leader-first identity fixture");
        wait_for(
            path,
            "the leader-first worker to exit",
            Duration::from_secs(5),
            || {
                let Some(status) = self.outer.try_wait()? else {
                    return Ok(None);
                };
                self.outer.close();
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
        let _result = self.stop();
    }
}
