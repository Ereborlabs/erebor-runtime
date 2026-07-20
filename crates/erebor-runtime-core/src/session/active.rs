use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::Duration,
};

pub(super) mod docker_command;

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use self::docker_command::DockerCommand;
use crate::{
    error::{SessionRunnerLaunchSnafu, SessionRunnerProtocolSnafu, SessionRunnerUnavailableSnafu},
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal, OutputEndpoints,
    RunnerBinding, RunnerCapabilityDocument, RuntimeError, SessionRunnerKind, SessionSpec,
};

pub const SESSION_HELPER_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHelperLaunchConfig {
    helper_path: PathBuf,
    process_guard_path: PathBuf,
    docker_path: PathBuf,
    systemd_run_path: PathBuf,
    use_systemd_scope: bool,
}

impl Default for SessionHelperLaunchConfig {
    fn default() -> Self {
        Self {
            helper_path: PathBuf::from("/usr/libexec/erebor/erebor-session-helper"),
            process_guard_path: PathBuf::from("/usr/libexec/erebor/erebor-linux-process-guard"),
            docker_path: PathBuf::from("/usr/bin/docker"),
            systemd_run_path: PathBuf::from("/usr/bin/systemd-run"),
            use_systemd_scope: true,
        }
    }
}

impl SessionHelperLaunchConfig {
    #[must_use]
    pub fn new(
        helper_path: PathBuf,
        process_guard_path: PathBuf,
        docker_path: PathBuf,
        systemd_run_path: PathBuf,
        use_systemd_scope: bool,
    ) -> Self {
        Self {
            helper_path,
            process_guard_path,
            docker_path,
            systemd_run_path,
            use_systemd_scope,
        }
    }

    pub(crate) fn inspect_runner(&self, runner: SessionRunnerKind) -> Result<(), RuntimeError> {
        require_executable(runner, &self.helper_path, "private session helper")?;
        if self.use_systemd_scope {
            require_executable(runner, &self.systemd_run_path, "systemd-run")?;
        }
        match runner {
            SessionRunnerKind::LinuxHost => {
                require_executable(runner, &self.process_guard_path, "Linux process guard")
            }
            SessionRunnerKind::Docker => {
                require_executable(runner, &self.docker_path, "Docker CLI")?;
                let output = DockerCommand::new(self.docker_path.clone()).run(&[
                    "version",
                    "--format",
                    "{{.Client.Version}}",
                ])?;
                if output.stdout.is_empty() {
                    return SessionRunnerUnavailableSnafu {
                        runner: runner.as_str().to_owned(),
                        reason: String::from("Docker CLI returned no client version"),
                    }
                    .fail();
                }
                Ok(())
            }
        }
    }

    pub(crate) const fn uses_systemd_scope(&self) -> bool {
        self.use_systemd_scope
    }

    pub(crate) fn validate_docker_image(&self, spec: &SessionSpec) -> Result<(), RuntimeError> {
        self.inspect_runner(SessionRunnerKind::Docker)?;
        let image = spec.container_image().ok_or_else(|| {
            SessionRunnerProtocolSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from("Docker session has no immutable image identity"),
            }
            .build()
        })?;
        let image_id = format!("sha256:{}", image.sha256());
        let output = DockerCommand::new(self.docker_path.clone()).run(&[
            "image",
            "inspect",
            "--format",
            "{{json .}}",
            &image_id,
        ])?;
        let inspected: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|_error| {
                SessionRunnerUnavailableSnafu {
                    runner: SessionRunnerKind::Docker.as_str().to_owned(),
                    reason: String::from("Docker returned malformed image inspection data"),
                }
                .build()
            })?;
        let observed_id = inspected.get("Id").and_then(serde_json::Value::as_str);
        let volumes = inspected
            .pointer("/Config/Volumes")
            .filter(|value| !value.is_null());
        let has_declared_volumes = volumes
            .and_then(serde_json::Value::as_object)
            .is_some_and(|volumes| !volumes.is_empty());
        if observed_id == Some(image_id.as_str()) && !has_declared_volumes {
            Ok(())
        } else {
            SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from(
                    "Docker image is unavailable under its admitted digest or declares implicit volumes",
                ),
            }
            .fail()
        }
    }

    pub(crate) fn start(
        &self,
        runner: SessionRunnerKind,
        spec: &SessionSpec,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        self.inspect_runner(runner)?;
        let unit = format!("erebor-session-{}.scope", spec.session_id().as_str());
        let session_slice = format!("erebor-session-{}.slice", spec.session_id().as_str());
        let handoff = SessionHelperHandoff {
            protocol_version: SESSION_HELPER_PROTOCOL_VERSION,
            spec: spec.clone(),
            stdout_path: output.stdout().to_path_buf(),
            stderr_path: output.stderr().to_path_buf(),
            events_path: output.events().to_path_buf(),
            evidence_path: output.evidence().to_path_buf(),
            journal_path: output.continuity().to_path_buf(),
            runtime_environment: output.runtime_environment().to_vec(),
            prepared_workspace: output.prepared_workspace().map(Path::to_path_buf),
            prepared_executable: output.prepared_executable().map(Path::to_path_buf),
            process_guard_path: self.process_guard_path.clone(),
            docker_path: self.docker_path.clone(),
            systemd_scope_unit: self.use_systemd_scope.then_some(unit.clone()),
            systemd_session_slice: self.use_systemd_scope.then_some(session_slice.clone()),
        };
        let mut command = if self.use_systemd_scope {
            let mut command = Command::new(&self.systemd_run_path);
            command.args([
                "--scope",
                "--quiet",
                "--collect",
                "--unit",
                &unit,
                "--slice",
                &session_slice,
                "--property",
                "KillMode=control-group",
                "--property",
                "Delegate=yes",
            ]);
            command.arg(&self.helper_path);
            command
        } else {
            Command::new(&self.helper_path)
        };
        let diagnostics_path = output
            .events()
            .parent()
            .unwrap_or_else(|| output.events())
            .join("helper-diagnostics.log");
        let diagnostics = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&diagnostics_path)
            .context(SessionRunnerLaunchSnafu {
                runner: runner.as_str().to_owned(),
                program: diagnostics_path.display().to_string(),
            })?;
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(diagnostics));
        let mut child = command.spawn().context(SessionRunnerLaunchSnafu {
            runner: runner.as_str().to_owned(),
            program: if self.use_systemd_scope {
                self.systemd_run_path.display().to_string()
            } else {
                self.helper_path.display().to_string()
            },
        })?;
        let mut input = child.stdin.take().ok_or_else(|| {
            SessionRunnerProtocolSnafu {
                runner: runner.as_str().to_owned(),
                reason: String::from("helper stdin was not created"),
            }
            .build()
        })?;
        let output_pipe = child.stdout.take().ok_or_else(|| {
            SessionRunnerProtocolSnafu {
                runner: runner.as_str().to_owned(),
                reason: String::from("helper stdout was not created"),
            }
            .build()
        })?;
        write_json_line(&mut input, runner, &handoff)?;
        let mut output_reader = BufReader::new(output_pipe);
        let started: SessionHelperEvent = read_json_line(&mut output_reader, runner)?;
        let SessionHelperEvent::Started {
            stable_identity,
            helper_pid,
        } = started
        else {
            return SessionRunnerProtocolSnafu {
                runner: runner.as_str().to_owned(),
                reason: format!("expected started event, received {started:?}"),
            }
            .fail();
        };
        let helper_start = process_start_time(helper_pid).unwrap_or(0);
        let stable_identity =
            format!("{stable_identity};helper_pid={helper_pid};helper_start={helper_start}");
        Ok(Box::new(HelperActiveSession {
            runner,
            stable_identity,
            capability,
            child,
            input,
            output: output_reader,
            observed_exit: None,
        }))
    }

    pub(crate) fn recover(
        &self,
        runner: SessionRunnerKind,
        spec: &SessionSpec,
        binding: &RunnerBinding,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        self.inspect_runner(runner)?;
        if binding.runner() != runner
            || binding.implementation_id() != capability.implementation_id()
        {
            return SessionRunnerProtocolSnafu {
                runner: runner.as_str().to_owned(),
                reason: String::from("saved runner binding does not match this implementation"),
            }
            .fail();
        }
        match runner {
            SessionRunnerKind::LinuxHost => {
                RecoveredLinuxSession::new(binding.stable_identity(), capability)
                    .map(|session| Box::new(session) as Box<dyn ActiveSession>)
            }
            SessionRunnerKind::Docker => RecoveredDockerSession::new(
                &self.docker_path,
                spec,
                binding.stable_identity(),
                output,
                capability,
            )
            .map(|session| Box::new(session) as Box<dyn ActiveSession>),
        }
    }

    pub(crate) fn remove(
        &self,
        runner: SessionRunnerKind,
        binding: Option<&RunnerBinding>,
    ) -> Result<(), RuntimeError> {
        if runner != SessionRunnerKind::Docker {
            return Ok(());
        }
        let Some(binding) = binding else {
            return Ok(());
        };
        let container_id = binding
            .stable_identity()
            .split(';')
            .next()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::Docker))?;
        DockerCommand::new(self.docker_path.clone())
            .run(&["container", "rm", container_id])
            .map(|_output| ())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionHelperHandoff {
    pub protocol_version: u32,
    pub spec: SessionSpec,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub events_path: PathBuf,
    pub evidence_path: PathBuf,
    pub journal_path: PathBuf,
    pub runtime_environment: Vec<(String, String)>,
    pub prepared_workspace: Option<PathBuf>,
    pub prepared_executable: Option<PathBuf>,
    pub process_guard_path: PathBuf,
    pub docker_path: PathBuf,
    pub systemd_scope_unit: Option<String>,
    pub systemd_session_slice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum SessionHelperCommand {
    Stop { grace_period_ms: u64 },
    Kill { signal: ActiveSessionSignal },
    Health,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SessionHelperEvent {
    Started {
        stable_identity: String,
        helper_pid: u32,
    },
    Health {
        running: bool,
    },
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Failed {
        reason: String,
    },
}

struct HelperActiveSession {
    runner: SessionRunnerKind,
    stable_identity: String,
    capability: RunnerCapabilityDocument,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    observed_exit: Option<ActiveSessionExit>,
}

struct RecoveredLinuxSession {
    stable_identity: String,
    capability: RunnerCapabilityDocument,
    process_group: rustix::process::Pid,
    process_start: u64,
    helper_pid: u32,
    helper_start: u64,
}

impl RecoveredLinuxSession {
    fn new(
        stable_identity: &str,
        capability: RunnerCapabilityDocument,
    ) -> Result<Self, RuntimeError> {
        let workload = stable_identity.split(';').next().unwrap_or_default();
        let mut fields = workload.split(':');
        if fields.next() != Some("linux") {
            return invalid_recovery_identity(SessionRunnerKind::LinuxHost);
        }
        let process_group = fields
            .next()
            .and_then(|value| value.strip_prefix("pid="))
            .and_then(|value| value.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::LinuxHost))?;
        let process_start = fields
            .next()
            .and_then(|value| value.strip_prefix("start="))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::LinuxHost))?;
        let (helper_pid, helper_start) = helper_process_identity(stable_identity)
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::LinuxHost))?;
        let session = Self {
            stable_identity: stable_identity.to_owned(),
            capability,
            process_group,
            process_start,
            helper_pid,
            helper_start,
        };
        if !session.identity_is_live() {
            return SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::LinuxHost.as_str().to_owned(),
                reason: String::from("saved process identity is no longer live"),
            }
            .fail();
        }
        Ok(session)
    }

    fn identity_is_live(&self) -> bool {
        process_start_time(self.process_group.as_raw_nonzero().get() as u32)
            == Some(self.process_start)
            && process_start_time(self.helper_pid) == Some(self.helper_start)
    }

    fn signal(&self, signal: rustix::process::Signal) -> Result<(), RuntimeError> {
        match rustix::process::kill_process_group(self.process_group, signal) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::SRCH) if !self.identity_is_live() => Ok(()),
            Err(error) => Err(RuntimeError::SessionRunnerProtocol {
                runner: SessionRunnerKind::LinuxHost.as_str().to_owned(),
                reason: error.to_string(),
                location: snafu::Location::default(),
            }),
        }
    }

    fn wait_until_gone(&self) -> ActiveSessionExit {
        while self.identity_is_live() {
            std::thread::sleep(Duration::from_millis(20));
        }
        ActiveSessionExit::new(None, None)
    }
}

impl ActiveSession for RecoveredLinuxSession {
    fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    fn capability_snapshot(&self) -> &RunnerCapabilityDocument {
        &self.capability
    }

    fn wait(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        Ok(self.wait_until_gone())
    }

    fn stop(&mut self, grace_period: Duration) -> Result<ActiveSessionExit, RuntimeError> {
        self.signal(rustix::process::Signal::TERM)?;
        let deadline = std::time::Instant::now() + grace_period;
        while self.identity_is_live() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.identity_is_live() {
            self.signal(rustix::process::Signal::KILL)?;
        }
        Ok(self.wait_until_gone())
    }

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError> {
        let signal = match signal {
            ActiveSessionSignal::Terminate => rustix::process::Signal::TERM,
            ActiveSessionSignal::Kill => rustix::process::Signal::KILL,
            ActiveSessionSignal::Interrupt => rustix::process::Signal::INT,
        };
        self.signal(signal)?;
        Ok(self.wait_until_gone())
    }

    fn health(&mut self) -> Result<ActiveSessionHealth, RuntimeError> {
        Ok(if self.identity_is_live() {
            ActiveSessionHealth::Running
        } else {
            ActiveSessionHealth::Exited
        })
    }
}

struct RecoveredDockerSession {
    docker: DockerCommand,
    stable_identity: String,
    capability: RunnerCapabilityDocument,
    expected: DockerContainerExpectation,
    helper_pid: u32,
    helper_start: u64,
}

impl RecoveredDockerSession {
    fn new(
        docker_path: &Path,
        spec: &SessionSpec,
        stable_identity: &str,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Self, RuntimeError> {
        let container_id = stable_identity
            .split(';')
            .next()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::Docker))?
            .to_owned();
        let (helper_pid, helper_start) = helper_process_identity(stable_identity)
            .ok_or_else(|| recovery_identity_error(SessionRunnerKind::Docker))?;
        let expected = DockerContainerExpectation {
            container_id,
            image_id: spec
                .container_image()
                .map(|image| format!("sha256:{}", image.sha256()))
                .ok_or_else(|| recovery_identity_error(SessionRunnerKind::Docker))?,
            session_id: spec.session_id().as_str().to_owned(),
            user: format!("{}:{}", spec.owner().uid(), spec.owner().gid()),
            cgroup_parent: if capability.admission_constraint("containment")
                == Some("systemd-session-slice-v1")
            {
                format!("erebor-session-{}.slice", spec.session_id().as_str())
            } else {
                String::new()
            },
            workspace: output
                .prepared_workspace()
                .ok_or_else(|| recovery_identity_error(SessionRunnerKind::Docker))?
                .to_path_buf(),
            command: spec.command().to_vec(),
            groups: spec
                .workload_privileges()
                .supplementary_groups()
                .iter()
                .map(u32::to_string)
                .collect(),
            maximum_open_files: limit_value(spec.workload_privileges().maximum_open_files())?,
            maximum_processes: limit_value(spec.workload_privileges().maximum_processes())?,
            maximum_core_bytes: limit_value(spec.workload_privileges().maximum_core_bytes())?,
        };
        let session = Self {
            docker: DockerCommand::new(docker_path.to_path_buf()),
            stable_identity: stable_identity.to_owned(),
            capability,
            expected,
            helper_pid,
            helper_start,
        };
        if session.inspect_state()?.0 && !session.helper_is_live() {
            return SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from(
                    "saved Docker workload is live without its admitted continuity helper",
                ),
            }
            .fail();
        }
        Ok(session)
    }

    fn command(&self, arguments: &[&str]) -> Result<String, RuntimeError> {
        let output = self.docker.run(arguments)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn inspect_state(&self) -> Result<(bool, i32), RuntimeError> {
        let value = self.command(&[
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            &self.expected.container_id,
        ])?;
        let observed: DockerContainerInspection = serde_json::from_str(&value)
            .map_err(|_error| recovery_identity_error(SessionRunnerKind::Docker))?;
        if !observed.matches(&self.expected) {
            return SessionRunnerProtocolSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from(
                    "saved Docker identity no longer matches its admitted session",
                ),
            }
            .fail();
        }
        Ok((observed.state.running, observed.state.exit_code))
    }

    fn helper_is_live(&self) -> bool {
        process_start_time(self.helper_pid) == Some(self.helper_start)
    }

    fn wait_for_exit(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        let exit_code = self
            .command(&["wait", &self.expected.container_id])?
            .parse()
            .map_err(|_error| recovery_identity_error(SessionRunnerKind::Docker))?;
        Ok(ActiveSessionExit::new(Some(exit_code), None))
    }
}

#[derive(Clone)]
struct DockerContainerExpectation {
    container_id: String,
    image_id: String,
    session_id: String,
    user: String,
    cgroup_parent: String,
    workspace: PathBuf,
    command: Vec<String>,
    groups: Vec<String>,
    maximum_open_files: i64,
    maximum_processes: i64,
    maximum_core_bytes: i64,
}

#[derive(Deserialize)]
struct DockerContainerInspection {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Config")]
    config: DockerContainerConfig,
    #[serde(rename = "State")]
    state: DockerContainerState,
    #[serde(rename = "HostConfig")]
    host_config: DockerHostConfig,
    #[serde(rename = "Mounts")]
    mounts: Vec<DockerMount>,
}

impl DockerContainerInspection {
    fn matches(&self, expected: &DockerContainerExpectation) -> bool {
        let Some((program, arguments)) = expected.command.split_first() else {
            return false;
        };
        self.id == expected.container_id
            && self.image == expected.image_id
            && self.config.user == expected.user
            && self.config.working_directory == "/workspace"
            && self.config.entrypoint.len() == 1
            && self.config.entrypoint.first() == Some(program)
            && self.config.command.as_deref().unwrap_or_default() == arguments
            && self.host_config.cgroup_parent == expected.cgroup_parent
            && self.host_config.read_only_root
            && self.host_config.network_mode == "none"
            && self
                .host_config
                .security_options
                .iter()
                .any(|option| option.starts_with("no-new-privileges"))
            && self.host_config.dropped_capabilities == ["ALL"]
            && self
                .host_config
                .additional_groups
                .as_deref()
                .unwrap_or_default()
                == expected.groups
            && self
                .host_config
                .has_limit("nofile", expected.maximum_open_files)
            && self
                .host_config
                .has_limit("nproc", expected.maximum_processes)
            && self
                .host_config
                .has_limit("core", expected.maximum_core_bytes)
            && self.mounts.iter().any(|mount| {
                mount.source == expected.workspace
                    && mount.destination == Path::new("/workspace")
                    && mount.read_write
            })
            && self
                .config
                .labels
                .get("dev.erebor.session_id")
                .map(String::as_str)
                == Some(expected.session_id.as_str())
    }
}

#[derive(Deserialize)]
struct DockerHostConfig {
    #[serde(rename = "CgroupParent")]
    cgroup_parent: String,
    #[serde(rename = "ReadonlyRootfs")]
    read_only_root: bool,
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "SecurityOpt")]
    security_options: Vec<String>,
    #[serde(rename = "CapDrop")]
    dropped_capabilities: Vec<String>,
    #[serde(rename = "GroupAdd")]
    additional_groups: Option<Vec<String>>,
    #[serde(rename = "Ulimits")]
    limits: Vec<DockerResourceLimit>,
}

impl DockerHostConfig {
    fn has_limit(&self, name: &str, expected: i64) -> bool {
        self.limits
            .iter()
            .any(|limit| limit.name == name && limit.soft == expected && limit.hard == expected)
    }
}

#[derive(Deserialize)]
struct DockerResourceLimit {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Soft")]
    soft: i64,
    #[serde(rename = "Hard")]
    hard: i64,
}

#[derive(Deserialize)]
struct DockerMount {
    #[serde(rename = "Source")]
    source: PathBuf,
    #[serde(rename = "Destination")]
    destination: PathBuf,
    #[serde(rename = "RW")]
    read_write: bool,
}

#[derive(Deserialize)]
struct DockerContainerConfig {
    #[serde(rename = "User")]
    user: String,
    #[serde(rename = "WorkingDir")]
    working_directory: String,
    #[serde(rename = "Entrypoint")]
    entrypoint: Vec<String>,
    #[serde(rename = "Cmd")]
    command: Option<Vec<String>>,
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct DockerContainerState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "ExitCode")]
    exit_code: i32,
}

impl ActiveSession for RecoveredDockerSession {
    fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    fn capability_snapshot(&self) -> &RunnerCapabilityDocument {
        &self.capability
    }

    fn wait(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        self.wait_for_exit()
    }

    fn stop(&mut self, grace_period: Duration) -> Result<ActiveSessionExit, RuntimeError> {
        let grace = grace_period.as_secs().max(1).to_string();
        self.command(&["stop", "--time", &grace, &self.expected.container_id])?;
        self.wait_for_exit()
    }

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError> {
        let signal = match signal {
            ActiveSessionSignal::Terminate => "TERM",
            ActiveSessionSignal::Kill => "KILL",
            ActiveSessionSignal::Interrupt => "INT",
        };
        self.command(&["kill", "--signal", signal, &self.expected.container_id])?;
        self.wait_for_exit()
    }

    fn health(&mut self) -> Result<ActiveSessionHealth, RuntimeError> {
        let running = self.inspect_state()?.0;
        if running && !self.helper_is_live() {
            return SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from(
                    "Docker continuity helper disappeared while the container remained active",
                ),
            }
            .fail();
        }
        Ok(if running {
            ActiveSessionHealth::Running
        } else {
            ActiveSessionHealth::Exited
        })
    }
}

impl HelperActiveSession {
    fn command(
        &mut self,
        command: &SessionHelperCommand,
    ) -> Result<SessionHelperEvent, RuntimeError> {
        write_json_line(&mut self.input, self.runner, command)?;
        read_json_line(&mut self.output, self.runner)
    }

    fn wait_for_exit(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        if let Some(exit) = self.observed_exit.clone() {
            return Ok(exit);
        }
        loop {
            match read_json_line(&mut self.output, self.runner)? {
                SessionHelperEvent::Exited { exit_code, signal } => {
                    return self.observe_exit(exit_code, signal);
                }
                SessionHelperEvent::Failed { reason } => {
                    return self.observe_failure(reason);
                }
                SessionHelperEvent::Started { .. } | SessionHelperEvent::Health { .. } => {}
            }
        }
    }

    fn observe_exit(
        &mut self,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<ActiveSessionExit, RuntimeError> {
        let exit = ActiveSessionExit::new(exit_code, signal);
        self.observed_exit = Some(exit.clone());
        let _status = self.child.wait().context(SessionRunnerLaunchSnafu {
            runner: self.runner.as_str().to_owned(),
            program: String::from("erebor-session-helper"),
        })?;
        Ok(exit)
    }

    fn observe_failure(&mut self, reason: String) -> Result<ActiveSessionExit, RuntimeError> {
        let exit = ActiveSessionExit::failed(Some(125), None, reason);
        self.observed_exit = Some(exit.clone());
        let _status = self.child.wait().context(SessionRunnerLaunchSnafu {
            runner: self.runner.as_str().to_owned(),
            program: String::from("erebor-session-helper"),
        })?;
        Ok(exit)
    }
}

impl ActiveSession for HelperActiveSession {
    fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    fn capability_snapshot(&self) -> &RunnerCapabilityDocument {
        &self.capability
    }

    fn wait(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        self.wait_for_exit()
    }

    fn stop(&mut self, grace_period: Duration) -> Result<ActiveSessionExit, RuntimeError> {
        let grace_period_ms = u64::try_from(grace_period.as_millis()).unwrap_or(u64::MAX);
        let event = self.command(&SessionHelperCommand::Stop { grace_period_ms })?;
        match event {
            SessionHelperEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)
            }
            SessionHelperEvent::Failed { reason } => self.observe_failure(reason),
            SessionHelperEvent::Started { .. } | SessionHelperEvent::Health { .. } => {
                self.wait_for_exit()
            }
        }
    }

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError> {
        let event = self.command(&SessionHelperCommand::Kill { signal })?;
        match event {
            SessionHelperEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)
            }
            SessionHelperEvent::Failed { reason } => self.observe_failure(reason),
            SessionHelperEvent::Started { .. } | SessionHelperEvent::Health { .. } => {
                self.wait_for_exit()
            }
        }
    }

    fn health(&mut self) -> Result<ActiveSessionHealth, RuntimeError> {
        if self.observed_exit.is_some() {
            return Ok(ActiveSessionHealth::Exited);
        }
        if self
            .child
            .try_wait()
            .context(SessionRunnerLaunchSnafu {
                runner: self.runner.as_str().to_owned(),
                program: String::from("erebor-session-helper"),
            })?
            .is_some()
        {
            return Ok(ActiveSessionHealth::Exited);
        }
        match self.command(&SessionHelperCommand::Health)? {
            SessionHelperEvent::Health { running: true } => Ok(ActiveSessionHealth::Running),
            SessionHelperEvent::Health { running: false } => Ok(ActiveSessionHealth::Exited),
            SessionHelperEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)?;
                Ok(ActiveSessionHealth::Exited)
            }
            SessionHelperEvent::Failed { reason } => {
                self.observe_failure(reason)?;
                Ok(ActiveSessionHealth::Exited)
            }
            SessionHelperEvent::Started { .. } => Ok(ActiveSessionHealth::Starting),
        }
    }
}

fn require_executable(
    runner: SessionRunnerKind,
    path: &Path,
    description: &str,
) -> Result<(), RuntimeError> {
    let available = fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    if available {
        Ok(())
    } else {
        SessionRunnerUnavailableSnafu {
            runner: runner.as_str().to_owned(),
            reason: format!("{description} `{}` is not executable", path.display()),
        }
        .fail()
    }
}

fn invalid_recovery_identity<T>(runner: SessionRunnerKind) -> Result<T, RuntimeError> {
    Err(recovery_identity_error(runner))
}

fn recovery_identity_error(runner: SessionRunnerKind) -> RuntimeError {
    RuntimeError::SessionRunnerProtocol {
        runner: runner.as_str().to_owned(),
        reason: String::from("saved stable identity is malformed"),
        location: snafu::Location::default(),
    }
}

fn limit_value(value: u64) -> Result<i64, RuntimeError> {
    i64::try_from(value).map_err(|_error| recovery_identity_error(SessionRunnerKind::Docker))
}

fn helper_process_identity(stable_identity: &str) -> Option<(u32, u64)> {
    let mut helper_pid = None;
    let mut helper_start = None;
    for field in stable_identity.split(';').skip(1) {
        if let Some(value) = field.strip_prefix("helper_pid=") {
            helper_pid = value.parse().ok();
        } else if let Some(value) = field.strip_prefix("helper_start=") {
            helper_start = value.parse().ok();
        }
    }
    Some((helper_pid?, helper_start?))
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    after_name
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

fn write_json_line(
    writer: &mut impl Write,
    runner: SessionRunnerKind,
    value: &impl Serialize,
) -> Result<(), RuntimeError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: error.to_string(),
        }
        .build()
    })?;
    writer.write_all(b"\n").map_err(|error| {
        SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: error.to_string(),
        }
        .build()
    })?;
    writer.flush().map_err(|error| {
        SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: error.to_string(),
        }
        .build()
    })
}

fn read_json_line<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
    runner: SessionRunnerKind,
) -> Result<T, RuntimeError> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).map_err(|error| {
        SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: error.to_string(),
        }
        .build()
    })?;
    if bytes == 0 {
        return SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: String::from("helper closed its control stream"),
        }
        .fail();
    }
    serde_json::from_str(&line).map_err(|error| {
        SessionRunnerProtocolSnafu {
            runner: runner.as_str().to_owned(),
            reason: error.to_string(),
        }
        .build()
    })
}

#[cfg(test)]
mod tests;
