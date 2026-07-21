use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use erebor_runtime_core::ActiveSessionSignal;

use crate::{runners::docker::DockerControllerHandoff, SessionControllerError, StreamKind};

use super::{
    output::HelperOutput,
    workload::{pump_output, OutputFailureMonitor, WorkloadExit},
};

pub(crate) struct DockerWorkload {
    docker: DockerCommand,
    container_id: String,
    logs: Child,
    output_pumps: Vec<thread::JoinHandle<()>>,
    output_failures: OutputFailureMonitor,
}

impl DockerWorkload {
    pub(crate) fn start(
        handoff: &DockerControllerHandoff,
        output: &HelperOutput,
    ) -> Result<Self, SessionControllerError> {
        let image = handoff.spec.container_image().ok_or_else(|| {
            SessionControllerError::InvalidHandoff {
                reason: String::from("Docker session has no immutable image identity"),
                location: snafu::Location::default(),
            }
        })?;
        let image_id = format!("sha256:{}", image.sha256());
        let docker = DockerCommand::new(handoff.docker_path.clone());
        let inspected = docker.run(["image", "inspect", "--format", "{{.Id}}", &image_id])?;
        if text(&inspected) != image_id {
            return Err(SessionControllerError::InvalidHandoff {
                reason: String::from("Docker image is not available under its admitted digest"),
                location: snafu::Location::default(),
            });
        }
        let mut arguments = vec![
            String::from("run"),
            String::from("--detach"),
            String::from("--pull=never"),
            String::from("--network=none"),
            String::from("--read-only"),
            String::from("--security-opt"),
            String::from("no-new-privileges"),
            String::from("--cap-drop"),
            String::from("ALL"),
            String::from("--user"),
            format!(
                "{}:{}",
                handoff.spec.owner().uid(),
                handoff.spec.owner().gid()
            ),
            String::from("--ulimit"),
            format!(
                "nofile={0}:{0}",
                handoff.spec.workload_privileges().maximum_open_files()
            ),
            String::from("--ulimit"),
            format!(
                "nproc={0}:{0}",
                handoff.spec.workload_privileges().maximum_processes()
            ),
            String::from("--ulimit"),
            format!(
                "core={0}:{0}",
                handoff.spec.workload_privileges().maximum_core_bytes()
            ),
            String::from("--label"),
            format!(
                "dev.erebor.session_id={}",
                handoff.spec.session_id().as_str()
            ),
        ];
        for group in handoff.spec.workload_privileges().supplementary_groups() {
            arguments.push(String::from("--group-add"));
            arguments.push(group.to_string());
        }
        if let Some(session_slice) = &handoff.systemd_session_slice {
            arguments.push(String::from("--cgroup-parent"));
            arguments.push(session_slice.clone());
        }
        for (key, value) in handoff.spec.environment() {
            arguments.push(String::from("--env"));
            arguments.push(format!("{key}={value}"));
        }
        if let Some(workspace) = &handoff.prepared_workspace {
            arguments.push(String::from("--mount"));
            arguments.push(format!(
                "type=bind,src={},dst=/workspace",
                workspace.display()
            ));
            arguments.push(String::from("--workdir"));
            arguments.push(String::from("/workspace"));
        }
        let (program, command_arguments) =
            handoff.spec.command().split_first().ok_or_else(|| {
                SessionControllerError::InvalidHandoff {
                    reason: String::from("Docker session has no admitted command"),
                    location: snafu::Location::default(),
                }
            })?;
        arguments.push(String::from("--entrypoint"));
        arguments.push(program.clone());
        arguments.push(image_id);
        arguments.extend(command_arguments.iter().cloned());
        let started = docker.run(arguments.iter().map(String::as_str))?;
        let container_id = text(&started);
        if container_id.len() != 64 || !container_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SessionControllerError::Command {
                program: handoff.docker_path.display().to_string(),
                reason: String::from("Docker returned an invalid container id"),
                location: snafu::Location::default(),
            });
        }
        let mut logs = Command::new(&handoff.docker_path)
            .args(["logs", "--follow", &container_id])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| SessionControllerError::Io {
                action: "starting Docker log follower",
                path: handoff.docker_path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        let mut output_pumps = Vec::new();
        let (output_failures, failure_sender) = OutputFailureMonitor::new();
        if let Some(stdout) = logs.stdout.take() {
            output_pumps.push(pump_output(
                stdout,
                Arc::clone(&output.stdout),
                StreamKind::Stdout.as_str(),
                failure_sender.clone(),
            ));
        }
        if let Some(stderr) = logs.stderr.take() {
            output_pumps.push(pump_output(
                stderr,
                Arc::clone(&output.stderr),
                StreamKind::Stderr.as_str(),
                failure_sender,
            ));
        }
        Ok(Self {
            docker,
            container_id,
            logs,
            output_pumps,
            output_failures,
        })
    }

    pub(crate) fn stable_identity(&self) -> &str {
        &self.container_id
    }

    pub(crate) fn take_output_failure(&self) -> Option<SessionControllerError> {
        self.output_failures.take_failure()
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<WorkloadExit>, SessionControllerError> {
        let output = self.docker.run([
            "container",
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.ExitCode}}",
            &self.container_id,
        ])?;
        let value = text(&output);
        let Some((running, exit_code)) = value.split_once(' ') else {
            return self.docker.error("Docker inspect returned malformed state");
        };
        if running == "true" {
            Ok(None)
        } else {
            let exit_code =
                exit_code
                    .parse::<i32>()
                    .map_err(|_error| SessionControllerError::Command {
                        program: self.docker.path.display().to_string(),
                        reason: String::from("Docker inspect returned an invalid exit code"),
                        location: snafu::Location::default(),
                    })?;
            let _status = self.logs.wait();
            self.join_output_pumps()?;
            Ok(Some(WorkloadExit {
                exit_code: Some(exit_code),
                signal: None,
            }))
        }
    }

    pub(crate) fn stop(&mut self, grace: Duration) -> Result<WorkloadExit, SessionControllerError> {
        let seconds = grace.as_secs().max(1).to_string();
        self.docker
            .run(["stop", "--time", &seconds, &self.container_id])?;
        self.wait()
    }

    pub(crate) fn kill(
        &mut self,
        signal: ActiveSessionSignal,
    ) -> Result<WorkloadExit, SessionControllerError> {
        let signal = match signal {
            ActiveSessionSignal::Terminate => "TERM",
            ActiveSessionSignal::Kill => "KILL",
            ActiveSessionSignal::Interrupt => "INT",
        };
        self.docker
            .run(["kill", "--signal", signal, &self.container_id])?;
        self.wait()
    }

    fn wait(&mut self) -> Result<WorkloadExit, SessionControllerError> {
        let output = self.docker.run(["wait", &self.container_id])?;
        let exit_code =
            text(&output)
                .parse::<i32>()
                .map_err(|_error| SessionControllerError::Command {
                    program: self.docker.path.display().to_string(),
                    reason: String::from("Docker wait returned an invalid exit code"),
                    location: snafu::Location::default(),
                })?;
        let _status = self.logs.wait();
        self.join_output_pumps()?;
        Ok(WorkloadExit {
            exit_code: Some(exit_code),
            signal: None,
        })
    }

    fn join_output_pumps(&mut self) -> Result<(), SessionControllerError> {
        for pump in self.output_pumps.drain(..) {
            pump.join()
                .map_err(|_panic| SessionControllerError::InvalidHandoff {
                    reason: String::from("Docker workload output pump panicked"),
                    location: snafu::Location::default(),
                })?;
        }
        Ok(())
    }
}

impl Drop for DockerWorkload {
    fn drop(&mut self) {
        if self.try_wait().ok().flatten().is_none() {
            let _result = self
                .docker
                .run(["kill", "--signal", "KILL", &self.container_id]);
        }
        let _result = self.logs.kill();
        let _result = self.logs.wait();
        for pump in self.output_pumps.drain(..) {
            let _result = pump.join();
        }
    }
}

#[derive(Clone)]
struct DockerCommand {
    path: PathBuf,
    timeout: Duration,
    maximum_output_bytes: usize,
}

impl DockerCommand {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 64 * 1024,
        }
    }

    fn run<'a>(
        &self,
        arguments: impl IntoIterator<Item = &'a str>,
    ) -> Result<Output, SessionControllerError> {
        let mut child = Command::new(&self.path)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| SessionControllerError::Io {
                action: "starting bounded Docker command",
                path: self.path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| self.command_error("stdout pipe missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| self.command_error("stderr pipe missing"))?;
        let maximum = self.maximum_output_bytes;
        let stdout_reader = thread::spawn(move || read_bounded(stdout, maximum));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, maximum));
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|source| SessionControllerError::Io {
                    action: "observing bounded Docker command",
                    path: self.path.clone(),
                    source,
                    location: snafu::Location::default(),
                })?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _result = child.kill();
                let _result = child.wait();
                let _stdout = stdout_reader.join();
                let _stderr = stderr_reader.join();
                return self.error("Docker command exceeded its execution deadline");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = join_reader(stdout_reader, &self.path)?;
        let stderr = join_reader(stderr_reader, &self.path)?;
        let output = Output {
            status,
            stdout,
            stderr,
        };
        if output.status.success() {
            Ok(output)
        } else {
            self.error(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }

    fn command_error(&self, reason: impl Into<String>) -> SessionControllerError {
        SessionControllerError::Command {
            program: self.path.display().to_string(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }

    fn error<T>(&self, reason: impl Into<String>) -> Result<T, SessionControllerError> {
        Err(self.command_error(reason))
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
) -> Result<Vec<u8>, SessionControllerError> {
    reader
        .join()
        .map_err(|_panic| SessionControllerError::Command {
            program: path.display().to_string(),
            reason: String::from("Docker output reader panicked"),
            location: snafu::Location::default(),
        })?
        .map_err(|source| SessionControllerError::Io {
            action: "reading bounded Docker command output",
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}
