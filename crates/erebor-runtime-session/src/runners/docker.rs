use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use erebor_runtime_core::{
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal,
    ActiveSessionSignalKind, DaemonFailureMode, FilesystemProjection, ImmutableIdentity,
    OutputEndpoints, RunnerBinding, RunnerCapabilityDocument, RunnerId, RunnerRecovery,
    RuntimeError, SessionSpec, WorkloadPrivilegePlan,
};
use serde::{Deserialize, Serialize};

use super::{
    RunnerAdmissionContext, RunnerDriver, RunnerExecutionAdmission, RunnerInstallConfig,
    RunnerPreparation,
};
use crate::SessionManagerError;

const RUNNER_ID: &str = "docker";
const IMPLEMENTATION_ID: &str = "erebor-docker-cli";
const CONTROLLER_PROGRAM: &str = "docker-session-controller";
const DOCKER_PROGRAM: &str = "docker";
const SYSTEMD_RUN_PROGRAM: &str = "systemd-run";
const DEFAULT_CONTROLLER_PATH: &str = "/usr/libexec/erebor/erebor-docker-session-controller";
const DEFAULT_DOCKER_PATH: &str = "/usr/bin/docker";
const DEFAULT_SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
pub(crate) const DOCKER_CONTROLLER_PROTOCOL_VERSION: u32 = 1;
const DOCKER_RECOVERY_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub(crate) struct DockerRunnerDriver {
    id: RunnerId,
    controller_path: PathBuf,
    docker_path: PathBuf,
    systemd_run_path: PathBuf,
    use_systemd_scope: bool,
}

impl DockerRunnerDriver {
    pub(crate) fn from_install_config(config: &RunnerInstallConfig) -> Result<Self, RuntimeError> {
        Ok(Self {
            id: RunnerId::new(RUNNER_ID).map_err(|error| {
                RuntimeError::SessionRunnerUnavailable {
                    runner: String::from(RUNNER_ID),
                    reason: error.to_string(),
                    location: snafu::Location::default(),
                }
            })?,
            controller_path: config.program(CONTROLLER_PROGRAM, Path::new(DEFAULT_CONTROLLER_PATH)),
            docker_path: config.program(DOCKER_PROGRAM, Path::new(DEFAULT_DOCKER_PATH)),
            systemd_run_path: config
                .program(SYSTEMD_RUN_PROGRAM, Path::new(DEFAULT_SYSTEMD_RUN_PATH)),
            use_systemd_scope: config.use_systemd_scope(),
        })
    }

    fn require_installed(&self) -> Result<(), RuntimeError> {
        require_executable(
            &self.id,
            &self.controller_path,
            "private Docker session controller",
        )?;
        require_executable(&self.id, &self.docker_path, "Docker CLI")?;
        if self.use_systemd_scope {
            require_executable(&self.id, &self.systemd_run_path, "systemd-run")?;
        }
        let output = DockerCommand::new(self.docker_path.clone()).run(&[
            "version",
            "--format",
            "{{.Client.Version}}",
        ])?;
        if output.stdout.is_empty() {
            return Err(self.unavailable("Docker CLI returned no client version"));
        }
        Ok(())
    }

    fn capability(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        RunnerCapabilityDocument::new(
            self.id.clone(),
            IMPLEMENTATION_ID,
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            true,
            false,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
                ActiveSessionSignalKind::Interrupt,
            ]),
            false,
            true,
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue]),
            BTreeMap::from([
                (
                    String::from("controller"),
                    String::from("docker-output-and-failure-continuity-v1"),
                ),
                (
                    String::from("image"),
                    String::from("local-content-digest-only"),
                ),
                (String::from("pull"), String::from("never")),
                (
                    String::from("containment"),
                    if self.use_systemd_scope {
                        String::from("systemd-session-slice-v1")
                    } else {
                        String::from("direct-docker-controller-v1")
                    },
                ),
                (
                    String::from("privilege-plan"),
                    String::from("docker-user-ulimit-capdrop-v1"),
                ),
                (
                    String::from("umask"),
                    String::from("oci-runtime-default-0022"),
                ),
            ]),
        )
        .map_err(|error| self.unavailable(error.to_string()))
    }

    fn validate_image(&self, image: &ImmutableIdentity) -> Result<(), RuntimeError> {
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
                self.unavailable("Docker returned malformed image inspection data")
            })?;
        let observed_id = inspected.get("Id").and_then(serde_json::Value::as_str);
        let declared_volumes = inspected
            .pointer("/Config/Volumes")
            .filter(|value| !value.is_null())
            .and_then(serde_json::Value::as_object)
            .is_some_and(|volumes| !volumes.is_empty());
        if observed_id == Some(image_id.as_str()) && !declared_volumes {
            Ok(())
        } else {
            Err(self.unavailable(
                "Docker image is unavailable under its admitted digest or declares implicit volumes",
            ))
        }
    }

    fn launch(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let unit = format!("erebor-session-{}.scope", spec.session_id().as_str());
        let session_slice = format!("erebor-session-{}.slice", spec.session_id().as_str());
        let handoff = DockerControllerHandoff {
            protocol_version: DOCKER_CONTROLLER_PROTOCOL_VERSION,
            spec: spec.clone(),
            stdout_path: output.stdout().to_path_buf(),
            stderr_path: output.stderr().to_path_buf(),
            events_path: output.events().to_path_buf(),
            evidence_path: output.evidence().to_path_buf(),
            journal_path: output.continuity().to_path_buf(),
            prepared_workspace: output.prepared_workspace().map(Path::to_path_buf),
            docker_path: self.docker_path.clone(),
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
            command.arg(&self.controller_path);
            command
        } else {
            Command::new(&self.controller_path)
        };
        let diagnostics_path = output
            .events()
            .parent()
            .unwrap_or_else(|| output.events())
            .join("docker-controller-diagnostics.log");
        let diagnostics = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&diagnostics_path)
            .map_err(|error| self.launch_error(&diagnostics_path, error))?;
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(diagnostics));
        let mut child = command.spawn().map_err(|error| {
            self.launch_error(
                if self.use_systemd_scope {
                    &self.systemd_run_path
                } else {
                    &self.controller_path
                },
                error,
            )
        })?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| self.protocol("controller stdin missing"))?;
        let output_pipe = child
            .stdout
            .take()
            .ok_or_else(|| self.protocol("controller stdout missing"))?;
        write_json_line(&mut input, &self.id, &handoff)?;
        let mut output_reader = BufReader::new(output_pipe);
        let started: DockerControllerEvent = read_json_line(&mut output_reader, &self.id)?;
        let DockerControllerEvent::Started {
            container_id,
            controller_pid,
        } = started
        else {
            return Err(self.protocol(format!("expected started event, received {started:?}")));
        };
        let recovery = encode_recovery(&DockerRecovery {
            container_id,
            controller_pid,
            controller_start: process_start_time(controller_pid).unwrap_or(0),
        })?;
        Ok(Box::new(DockerControllerSession {
            recovery,
            capability,
            child,
            input,
            output: output_reader,
            observed_exit: None,
            id: self.id.clone(),
        }))
    }

    fn unavailable(&self, reason: impl Into<String>) -> RuntimeError {
        RuntimeError::SessionRunnerUnavailable {
            runner: self.id.as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }

    fn protocol(&self, reason: impl Into<String>) -> RuntimeError {
        RuntimeError::SessionRunnerProtocol {
            runner: self.id.as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }

    fn launch_error(&self, path: &Path, source: std::io::Error) -> RuntimeError {
        RuntimeError::SessionRunnerLaunch {
            runner: self.id.as_str().to_owned(),
            program: path.display().to_string(),
            source,
            location: snafu::Location::default(),
        }
    }
}

impl RunnerDriver for DockerRunnerDriver {
    fn id(&self) -> &RunnerId {
        &self.id
    }

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        if !cfg!(target_os = "linux") {
            return Err(self.unavailable(
                "the current Docker output/failure continuity controller requires Linux",
            ));
        }
        self.require_installed()?;
        self.capability()
    }

    fn admit(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
    ) -> Result<RunnerExecutionAdmission, SessionManagerError> {
        let digest = context.container_image_digest().ok_or_else(|| {
            context.invalid("Docker admission requires an immutable container image digest")
        })?;
        let image = ImmutableIdentity::new("container-image", digest)
            .map_err(|source| context.invalid(source.to_string()))?;
        self.validate_image(&image)
            .map_err(|source| SessionManagerError::Runner {
                source,
                location: snafu::Location::default(),
            })?;
        let workload_privileges = WorkloadPrivilegePlan::new(Vec::new(), 0o022, 1024, 512, 0)
            .map_err(|source| context.invalid(source.to_string()))?;
        let filesystem_projections = vec![FilesystemProjection::new(
            context.workspace().clone(),
            PathBuf::from("/workspace"),
            false,
        )
        .map_err(|source| context.invalid(source.to_string()))?];
        Ok(RunnerExecutionAdmission {
            workspace: context.workspace().clone(),
            workload_privileges,
            executable: None,
            container_image: Some(image),
            filesystem_projections,
            endpoint_projections: Vec::new(),
        })
    }

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError> {
        if spec.runner_capability().runner() != &self.id
            || spec.executable().is_some()
            || spec.workload_privileges().umask() != 0o022
        {
            return Err(self.protocol(
                "Docker admission requires its runner ID, no host executable, and umask 0022",
            ));
        }
        let image = spec
            .container_image()
            .ok_or_else(|| self.protocol("Docker session has no immutable image identity"))?;
        self.validate_image(image)
    }

    fn prepare(
        &self,
        spec: &SessionSpec,
        resources: &RunnerPreparation<'_>,
    ) -> Result<OutputEndpoints, SessionManagerError> {
        resources.prepare_execution(spec)
    }

    fn start(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        self.require_installed()?;
        self.launch(spec, output, self.capability()?)
    }

    fn recover(
        &self,
        spec: &SessionSpec,
        binding: &RunnerBinding,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        if binding.runner() != &self.id || binding.implementation_id() != IMPLEMENTATION_ID {
            return Err(self.protocol("saved runner binding does not match this implementation"));
        }
        Ok(Box::new(RecoveredDockerSession::new(
            &self.docker_path,
            spec,
            binding.recovery(),
            output,
            capability,
            self.id.clone(),
        )?))
    }

    fn remove(
        &self,
        _spec: &SessionSpec,
        binding: Option<&RunnerBinding>,
    ) -> Result<(), RuntimeError> {
        let Some(binding) = binding else {
            return Ok(());
        };
        let recovery = decode_recovery(binding.recovery(), &self.id)?;
        DockerCommand::new(self.docker_path.clone()).run(&[
            "container",
            "rm",
            &recovery.container_id,
        ])?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DockerControllerHandoff {
    pub(crate) protocol_version: u32,
    pub(crate) spec: SessionSpec,
    pub(crate) stdout_path: PathBuf,
    pub(crate) stderr_path: PathBuf,
    pub(crate) events_path: PathBuf,
    pub(crate) evidence_path: PathBuf,
    pub(crate) journal_path: PathBuf,
    pub(crate) prepared_workspace: Option<PathBuf>,
    pub(crate) docker_path: PathBuf,
    pub(crate) systemd_session_slice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(crate) enum DockerControllerCommand {
    Stop { grace_period_ms: u64 },
    Kill { signal: ActiveSessionSignal },
    Health,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum DockerControllerEvent {
    Started {
        container_id: String,
        controller_pid: u32,
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

#[derive(Debug, Deserialize, Serialize)]
struct DockerRecovery {
    container_id: String,
    controller_pid: u32,
    controller_start: u64,
}

struct DockerControllerSession {
    recovery: RunnerRecovery,
    capability: RunnerCapabilityDocument,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    observed_exit: Option<ActiveSessionExit>,
    id: RunnerId,
}

impl DockerControllerSession {
    fn command(
        &mut self,
        command: &DockerControllerCommand,
    ) -> Result<DockerControllerEvent, RuntimeError> {
        write_json_line(&mut self.input, &self.id, command)?;
        read_json_line(&mut self.output, &self.id)
    }

    fn wait_for_exit(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        if let Some(exit) = self.observed_exit.clone() {
            return Ok(exit);
        }
        loop {
            match read_json_line(&mut self.output, &self.id)? {
                DockerControllerEvent::Exited { exit_code, signal } => {
                    return self.observe_exit(exit_code, signal);
                }
                DockerControllerEvent::Failed { reason } => return self.observe_failure(reason),
                DockerControllerEvent::Started { .. } | DockerControllerEvent::Health { .. } => {}
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
        self.child
            .wait()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: self.id.as_str().to_owned(),
                program: String::from("erebor-docker-session-controller"),
                source,
                location: snafu::Location::default(),
            })?;
        Ok(exit)
    }

    fn observe_failure(&mut self, reason: String) -> Result<ActiveSessionExit, RuntimeError> {
        let exit = ActiveSessionExit::failed(Some(125), None, reason);
        self.observed_exit = Some(exit.clone());
        self.child
            .wait()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: self.id.as_str().to_owned(),
                program: String::from("erebor-docker-session-controller"),
                source,
                location: snafu::Location::default(),
            })?;
        Ok(exit)
    }

    fn exit_from_event(
        &mut self,
        event: DockerControllerEvent,
    ) -> Result<ActiveSessionExit, RuntimeError> {
        match event {
            DockerControllerEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)
            }
            DockerControllerEvent::Failed { reason } => self.observe_failure(reason),
            DockerControllerEvent::Started { .. } | DockerControllerEvent::Health { .. } => {
                self.wait_for_exit()
            }
        }
    }
}

impl ActiveSession for DockerControllerSession {
    fn recovery(&self) -> &RunnerRecovery {
        &self.recovery
    }

    fn capability_snapshot(&self) -> &RunnerCapabilityDocument {
        &self.capability
    }

    fn wait(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        self.wait_for_exit()
    }

    fn stop(&mut self, grace_period: Duration) -> Result<ActiveSessionExit, RuntimeError> {
        let grace_period_ms = u64::try_from(grace_period.as_millis()).unwrap_or(u64::MAX);
        let event = self.command(&DockerControllerCommand::Stop { grace_period_ms })?;
        self.exit_from_event(event)
    }

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError> {
        let event = self.command(&DockerControllerCommand::Kill { signal })?;
        self.exit_from_event(event)
    }

    fn health(&mut self) -> Result<ActiveSessionHealth, RuntimeError> {
        if self.observed_exit.is_some() {
            return Ok(ActiveSessionHealth::Exited);
        }
        if self
            .child
            .try_wait()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: self.id.as_str().to_owned(),
                program: String::from("erebor-docker-session-controller"),
                source,
                location: snafu::Location::default(),
            })?
            .is_some()
        {
            return Ok(ActiveSessionHealth::Exited);
        }
        match self.command(&DockerControllerCommand::Health)? {
            DockerControllerEvent::Health { running: true } => Ok(ActiveSessionHealth::Running),
            DockerControllerEvent::Health { running: false } => Ok(ActiveSessionHealth::Exited),
            DockerControllerEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)?;
                Ok(ActiveSessionHealth::Exited)
            }
            DockerControllerEvent::Failed { reason } => {
                self.observe_failure(reason)?;
                Ok(ActiveSessionHealth::Exited)
            }
            DockerControllerEvent::Started { .. } => Ok(ActiveSessionHealth::Starting),
        }
    }
}

struct RecoveredDockerSession {
    docker: DockerCommand,
    recovery: RunnerRecovery,
    capability: RunnerCapabilityDocument,
    expected: DockerContainerExpectation,
    controller_pid: u32,
    controller_start: u64,
    id: RunnerId,
}

impl RecoveredDockerSession {
    fn new(
        docker_path: &Path,
        spec: &SessionSpec,
        recovery: &RunnerRecovery,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
        id: RunnerId,
    ) -> Result<Self, RuntimeError> {
        let parsed = decode_recovery(recovery, &id)?;
        let expected =
            DockerContainerExpectation::new(spec, output, capability.clone(), parsed.container_id)?;
        let session = Self {
            docker: DockerCommand::new(docker_path.to_path_buf()),
            recovery: recovery.clone(),
            capability,
            expected,
            controller_pid: parsed.controller_pid,
            controller_start: parsed.controller_start,
            id,
        };
        if session.inspect_state()?.0 && !session.controller_is_live() {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: session.id.as_str().to_owned(),
                reason: String::from(
                    "saved Docker workload is live without its admitted continuity controller",
                ),
                location: snafu::Location::default(),
            });
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
        let observed: DockerContainerInspection =
            serde_json::from_str(&value).map_err(|_error| recovery_error(&self.id))?;
        if !observed.matches(&self.expected) {
            return Err(RuntimeError::SessionRunnerProtocol {
                runner: self.id.as_str().to_owned(),
                reason: String::from(
                    "saved Docker identity no longer matches its admitted session",
                ),
                location: snafu::Location::default(),
            });
        }
        Ok((observed.state.running, observed.state.exit_code))
    }

    fn controller_is_live(&self) -> bool {
        process_start_time(self.controller_pid) == Some(self.controller_start)
    }

    fn wait_for_exit(&self) -> Result<ActiveSessionExit, RuntimeError> {
        let exit_code = self
            .command(&["wait", &self.expected.container_id])?
            .parse()
            .map_err(|_error| recovery_error(&self.id))?;
        Ok(ActiveSessionExit::new(Some(exit_code), None))
    }
}

impl ActiveSession for RecoveredDockerSession {
    fn recovery(&self) -> &RunnerRecovery {
        &self.recovery
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
        if running && !self.controller_is_live() {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: self.id.as_str().to_owned(),
                reason: String::from(
                    "Docker continuity controller disappeared while the container remained active",
                ),
                location: snafu::Location::default(),
            });
        }
        Ok(if running {
            ActiveSessionHealth::Running
        } else {
            ActiveSessionHealth::Exited
        })
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

impl DockerContainerExpectation {
    fn new(
        spec: &SessionSpec,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
        container_id: String,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            container_id,
            image_id: spec
                .container_image()
                .map(|image| format!("sha256:{}", image.sha256()))
                .ok_or_else(|| recovery_error(capability.runner()))?,
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
                .ok_or_else(|| recovery_error(capability.runner()))?
                .to_path_buf(),
            command: spec.command().to_vec(),
            groups: spec
                .workload_privileges()
                .supplementary_groups()
                .iter()
                .map(u32::to_string)
                .collect(),
            maximum_open_files: limit_value(
                spec.workload_privileges().maximum_open_files(),
                capability.runner(),
            )?,
            maximum_processes: limit_value(
                spec.workload_privileges().maximum_processes(),
                capability.runner(),
            )?,
            maximum_core_bytes: limit_value(
                spec.workload_privileges().maximum_core_bytes(),
                capability.runner(),
            )?,
        })
    }
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

    fn run(&self, arguments: &[&str]) -> Result<Output, RuntimeError> {
        let mut child = Command::new(&self.path)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: String::from(RUNNER_ID),
                program: self.path.display().to_string(),
                source,
                location: snafu::Location::default(),
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
            if let Some(status) =
                child
                    .try_wait()
                    .map_err(|source| RuntimeError::SessionRunnerLaunch {
                        runner: String::from(RUNNER_ID),
                        program: self.path.display().to_string(),
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
        RuntimeError::SessionRunnerProtocol {
            runner: String::from(RUNNER_ID),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }
}

fn encode_recovery(value: &DockerRecovery) -> Result<RunnerRecovery, RuntimeError> {
    let payload =
        serde_json::to_string(value).map_err(|error| RuntimeError::SessionRunnerProtocol {
            runner: String::from(RUNNER_ID),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })?;
    RunnerRecovery::new(DOCKER_RECOVERY_FORMAT_VERSION, payload).map_err(|error| {
        RuntimeError::SessionRunnerProtocol {
            runner: String::from(RUNNER_ID),
            reason: error.to_string(),
            location: snafu::Location::default(),
        }
    })
}

fn decode_recovery(
    recovery: &RunnerRecovery,
    id: &RunnerId,
) -> Result<DockerRecovery, RuntimeError> {
    if recovery.format_version() != DOCKER_RECOVERY_FORMAT_VERSION {
        return Err(recovery_error(id));
    }
    let value: DockerRecovery =
        serde_json::from_str(recovery.payload()).map_err(|_error| recovery_error(id))?;
    if value.container_id.len() != 64
        || !value
            .container_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(recovery_error(id));
    }
    Ok(value)
}

fn recovery_error(id: &RunnerId) -> RuntimeError {
    RuntimeError::SessionRunnerProtocol {
        runner: id.as_str().to_owned(),
        reason: String::from("saved Docker recovery value is malformed"),
        location: snafu::Location::default(),
    }
}

fn limit_value(value: u64, id: &RunnerId) -> Result<i64, RuntimeError> {
    i64::try_from(value).map_err(|_error| recovery_error(id))
}

fn require_executable(id: &RunnerId, path: &Path, description: &str) -> Result<(), RuntimeError> {
    let available = fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    if available {
        Ok(())
    } else {
        Err(RuntimeError::SessionRunnerUnavailable {
            runner: id.as_str().to_owned(),
            reason: format!("{description} `{}` is not executable", path.display()),
            location: snafu::Location::default(),
        })
    }
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
    id: &RunnerId,
    value: &impl Serialize,
) -> Result<(), RuntimeError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        RuntimeError::SessionRunnerProtocol {
            runner: id.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        }
    })?;
    writer
        .write_all(b"\n")
        .map_err(|error| RuntimeError::SessionRunnerProtocol {
            runner: id.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })?;
    writer
        .flush()
        .map_err(|error| RuntimeError::SessionRunnerProtocol {
            runner: id.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })
}

fn read_json_line<T: for<'de> Deserialize<'de>>(
    reader: &mut impl BufRead,
    id: &RunnerId,
) -> Result<T, RuntimeError> {
    let mut line = String::new();
    let bytes =
        reader
            .read_line(&mut line)
            .map_err(|error| RuntimeError::SessionRunnerProtocol {
                runner: id.as_str().to_owned(),
                reason: error.to_string(),
                location: snafu::Location::default(),
            })?;
    if bytes == 0 {
        return Err(RuntimeError::SessionRunnerProtocol {
            runner: id.as_str().to_owned(),
            reason: String::from("Docker controller closed its control stream"),
            location: snafu::Location::default(),
        });
    }
    serde_json::from_str(&line).map_err(|error| RuntimeError::SessionRunnerProtocol {
        runner: id.as_str().to_owned(),
        reason: error.to_string(),
        location: snafu::Location::default(),
    })
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
        .map_err(|_panic| RuntimeError::SessionRunnerProtocol {
            runner: String::from(RUNNER_ID),
            reason: String::from("Docker output reader panicked"),
            location: snafu::Location::default(),
        })?
        .map_err(|source| RuntimeError::SessionRunnerLaunch {
            runner: String::from(RUNNER_ID),
            program: path.display().to_string(),
            source,
            location: snafu::Location::default(),
        })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use super::{
        decode_recovery, encode_recovery, DockerRecovery, DockerRunnerDriver, CONTROLLER_PROGRAM,
        DEFAULT_CONTROLLER_PATH, RUNNER_ID,
    };
    use crate::RunnerInstallConfig;
    use erebor_runtime_core::RunnerId;

    #[test]
    fn docker_driver_owns_its_installation_program_names_and_defaults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let default = DockerRunnerDriver::from_install_config(&RunnerInstallConfig::default())?;
        assert_eq!(
            default.controller_path,
            PathBuf::from(DEFAULT_CONTROLLER_PATH)
        );

        let override_path = PathBuf::from("/opt/erebor/docker-controller");
        let configured = DockerRunnerDriver::from_install_config(&RunnerInstallConfig::new(
            BTreeMap::from([(String::from(CONTROLLER_PROGRAM), override_path.clone())]),
            false,
        ))?;
        assert_eq!(configured.controller_path, override_path);
        assert!(!configured.use_systemd_scope);
        Ok(())
    }

    #[test]
    fn docker_driver_round_trips_its_opaque_versioned_recovery_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = DockerRecovery {
            container_id: "a".repeat(64),
            controller_pid: 51,
            controller_start: 101,
        };
        let encoded = encode_recovery(&expected)?;
        let decoded = decode_recovery(&encoded, &RunnerId::new(RUNNER_ID)?)?;

        assert_eq!(decoded.container_id, expected.container_id);
        assert_eq!(decoded.controller_pid, expected.controller_pid);
        assert_eq!(decoded.controller_start, expected.controller_start);
        Ok(())
    }
}
