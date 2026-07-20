use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    error::{SessionRunnerLaunchSnafu, SessionRunnerProtocolSnafu},
    RuntimeError, SessionRunnerKind,
};
use snafu::ResultExt;

#[derive(Clone)]
pub(super) struct DockerCommand {
    path: PathBuf,
    timeout: Duration,
    maximum_output_bytes: usize,
}

impl DockerCommand {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 64 * 1024,
        }
    }

    pub(super) fn run(&self, arguments: &[&str]) -> Result<Output, RuntimeError> {
        let mut child = Command::new(&self.path)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(SessionRunnerLaunchSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                program: self.path.display().to_string(),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| self.protocol("stdout pipe missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| self.protocol("stderr pipe missing"))?;
        let maximum = self.maximum_output_bytes;
        let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, maximum));
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait().context(SessionRunnerLaunchSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                program: self.path.display().to_string(),
            })? {
                break status;
            }
            if Instant::now() >= deadline {
                let _result = child.kill();
                let _result = child.wait();
                let _stdout = stdout_reader.join();
                let _stderr = stderr_reader.join();
                return Err(self.protocol("Docker command exceeded its execution deadline"));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = join_reader(stdout_reader, &self.path)?;
        let stderr = join_reader(stderr_reader, &self.path)?;
        if !status.success() {
            return Err(self.protocol(String::from_utf8_lossy(&stderr).trim()));
        }
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn protocol(&self, reason: impl Into<String>) -> RuntimeError {
        SessionRunnerProtocolSnafu {
            runner: SessionRunnerKind::Docker.as_str().to_owned(),
            reason: reason.into(),
        }
        .build()
    }
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::with_capacity(maximum.min(8192));
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes = reader.read(&mut buffer)?;
        if bytes == 0 {
            return Ok(retained);
        }
        let remaining = maximum.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..bytes.min(remaining)]);
    }
}

fn join_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    path: &Path,
) -> Result<Vec<u8>, RuntimeError> {
    reader
        .join()
        .map_err(|_panic| {
            SessionRunnerProtocolSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from("Docker output reader panicked"),
            }
            .build()
        })?
        .context(SessionRunnerLaunchSnafu {
            runner: SessionRunnerKind::Docker.as_str().to_owned(),
            program: path.display().to_string(),
        })
}
