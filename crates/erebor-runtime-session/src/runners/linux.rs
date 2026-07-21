use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::Duration,
};

use erebor_runtime_core::{
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal,
    ActiveSessionSignalKind, DaemonFailureMode, EndpointProjection, FilesystemProjection,
    OutputEndpoints, RunnerBinding, RunnerCapabilityDocument, RunnerId, RunnerRecovery,
    RuntimeError, SafePathKind, SessionSpec, WorkloadPrivilegePlan,
};
use serde::{Deserialize, Serialize};

use super::{RunnerAdmissionContext, RunnerDriver, RunnerExecutionAdmission};
use crate::SessionManagerError;

const RUNNER_ID: &str = "linux-host";
const IMPLEMENTATION_ID: &str = "erebor-linux-host";
pub(crate) const LINUX_CONTROLLER_PROTOCOL_VERSION: u32 = 1;
const LINUX_RECOVERY_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub(crate) struct LinuxRunnerDriver {
    id: RunnerId,
    controller_path: PathBuf,
    process_guard_path: PathBuf,
    systemd_run_path: PathBuf,
    use_systemd_scope: bool,
}

impl LinuxRunnerDriver {
    pub(crate) fn new(
        controller_path: PathBuf,
        process_guard_path: PathBuf,
        systemd_run_path: PathBuf,
        use_systemd_scope: bool,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            id: RunnerId::new(RUNNER_ID).map_err(|error| {
                RuntimeError::SessionRunnerUnavailable {
                    runner: String::from(RUNNER_ID),
                    reason: error.to_string(),
                    location: snafu::Location::default(),
                }
            })?,
            controller_path,
            process_guard_path,
            systemd_run_path,
            use_systemd_scope,
        })
    }

    fn require_installed(&self) -> Result<(), RuntimeError> {
        require_executable(
            &self.id,
            &self.controller_path,
            "private Linux session controller",
        )?;
        require_executable(&self.id, &self.process_guard_path, "Linux process guard")?;
        if self.use_systemd_scope {
            require_executable(&self.id, &self.systemd_run_path, "systemd-run")?;
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
            true,
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
                    String::from("linux-inherited-control-lease-v1"),
                ),
                (
                    String::from("containment"),
                    if self.use_systemd_scope {
                        String::from("systemd-session-slice-v1")
                    } else {
                        String::from("direct-linux-controller-v1")
                    },
                ),
                (
                    String::from("privilege-plan"),
                    String::from("process-guard-rlimit-umask-groups-v1"),
                ),
            ]),
        )
        .map_err(|error| RuntimeError::SessionRunnerUnavailable {
            runner: self.id.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })
    }

    fn launch(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let unit = format!("erebor-session-{}.scope", spec.session_id().as_str());
        let session_slice = format!("erebor-session-{}.slice", spec.session_id().as_str());
        let handoff = LinuxControllerHandoff {
            protocol_version: LINUX_CONTROLLER_PROTOCOL_VERSION,
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
            command.arg(&self.controller_path);
            command
        } else {
            Command::new(&self.controller_path)
        };
        let diagnostics_path = output
            .events()
            .parent()
            .unwrap_or_else(|| output.events())
            .join("linux-controller-diagnostics.log");
        let diagnostics = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&diagnostics_path)
            .map_err(|source| self.launch_error(&diagnostics_path, source))?;
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(diagnostics));
        let launch_path = if self.use_systemd_scope {
            &self.systemd_run_path
        } else {
            &self.controller_path
        };
        let mut child = command
            .spawn()
            .map_err(|source| self.launch_error(launch_path, source))?;
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
        let started: LinuxControllerEvent = read_json_line(&mut output_reader, &self.id)?;
        let LinuxControllerEvent::Started {
            workload_identity,
            controller_pid,
        } = started
        else {
            return Err(self.protocol(format!("expected started event, received {started:?}")));
        };
        let recovery = LinuxRecovery {
            workload_identity,
            controller_pid,
            controller_start: process_start_time(controller_pid).unwrap_or(0),
        };
        Ok(Box::new(LinuxControllerSession {
            recovery: encode_recovery(&recovery)?,
            capability,
            child,
            input,
            output: output_reader,
            observed_exit: None,
            id: self.id.clone(),
        }))
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

impl RunnerDriver for LinuxRunnerDriver {
    fn id(&self) -> &RunnerId {
        &self.id
    }

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: self.id.as_str().to_owned(),
                reason: String::from(
                    "physical Linux interception is supported only on x86_64 Linux",
                ),
                location: snafu::Location::default(),
            });
        }
        self.require_installed()?;
        self.capability()
    }

    fn admit(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
    ) -> Result<RunnerExecutionAdmission, SessionManagerError> {
        if context.container_image_digest().is_some() {
            return Err(context.invalid("Linux-host admission does not accept a container image"));
        }
        let program = context.command().first().ok_or_else(|| {
            context.invalid("Linux-host admission requires an executable command")
        })?;
        let executable = context.resolve_path(Path::new(program), SafePathKind::Executable)?;
        let workload_privileges = WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 512, 0)
            .map_err(|source| context.invalid(source.to_string()))?;
        let filesystem_projections = vec![FilesystemProjection::new(
            context.workspace().clone(),
            PathBuf::from("/workspace"),
            false,
        )
        .map_err(|source| context.invalid(source.to_string()))?];
        let endpoint_projections = vec![EndpointProjection::new(
            "runtime-guard",
            context.runtime_guard_host_path().to_path_buf(),
            PathBuf::from("/run/erebor/runtime-interception.sock"),
        )
        .map_err(|source| context.invalid(source.to_string()))?];
        Ok(RunnerExecutionAdmission {
            workspace: context.workspace().clone(),
            workload_privileges,
            executable: Some(executable),
            container_image: None,
            filesystem_projections,
            endpoint_projections,
        })
    }

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError> {
        if spec.runner_capability().runner() == &self.id
            && spec.executable().is_some()
            && spec.container_image().is_none()
            && spec.workload_privileges().umask() == 0o077
        {
            Ok(())
        } else {
            Err(self.protocol(
                "Linux-host admission requires its runner ID, executable, no image, and umask 0077",
            ))
        }
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
        _spec: &SessionSpec,
        binding: &RunnerBinding,
        _output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        if binding.runner() != &self.id || binding.implementation_id() != IMPLEMENTATION_ID {
            return Err(self.protocol("saved runner binding does not match this implementation"));
        }
        Ok(Box::new(RecoveredLinuxSession::new(
            binding.recovery(),
            capability,
            self.id.clone(),
        )?))
    }

    fn remove(
        &self,
        _spec: &SessionSpec,
        _binding: Option<&RunnerBinding>,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LinuxControllerHandoff {
    pub(crate) protocol_version: u32,
    pub(crate) spec: SessionSpec,
    pub(crate) stdout_path: PathBuf,
    pub(crate) stderr_path: PathBuf,
    pub(crate) events_path: PathBuf,
    pub(crate) evidence_path: PathBuf,
    pub(crate) journal_path: PathBuf,
    pub(crate) runtime_environment: Vec<(String, String)>,
    pub(crate) prepared_workspace: Option<PathBuf>,
    pub(crate) prepared_executable: Option<PathBuf>,
    pub(crate) process_guard_path: PathBuf,
    pub(crate) systemd_scope_unit: Option<String>,
    pub(crate) systemd_session_slice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(crate) enum LinuxControllerCommand {
    Stop { grace_period_ms: u64 },
    Kill { signal: ActiveSessionSignal },
    Health,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum LinuxControllerEvent {
    Started {
        workload_identity: String,
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
struct LinuxRecovery {
    workload_identity: String,
    controller_pid: u32,
    controller_start: u64,
}

struct LinuxControllerSession {
    recovery: RunnerRecovery,
    capability: RunnerCapabilityDocument,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    observed_exit: Option<ActiveSessionExit>,
    id: RunnerId,
}

impl LinuxControllerSession {
    fn command(
        &mut self,
        command: &LinuxControllerCommand,
    ) -> Result<LinuxControllerEvent, RuntimeError> {
        write_json_line(&mut self.input, &self.id, command)?;
        read_json_line(&mut self.output, &self.id)
    }

    fn wait_for_exit(&mut self) -> Result<ActiveSessionExit, RuntimeError> {
        if let Some(exit) = self.observed_exit.clone() {
            return Ok(exit);
        }
        loop {
            match read_json_line(&mut self.output, &self.id)? {
                LinuxControllerEvent::Exited { exit_code, signal } => {
                    return self.observe_exit(exit_code, signal);
                }
                LinuxControllerEvent::Failed { reason } => return self.observe_failure(reason),
                LinuxControllerEvent::Started { .. } | LinuxControllerEvent::Health { .. } => {}
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
                program: String::from("erebor-linux-session-controller"),
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
                program: String::from("erebor-linux-session-controller"),
                source,
                location: snafu::Location::default(),
            })?;
        Ok(exit)
    }
}

impl ActiveSession for LinuxControllerSession {
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
        let event = self.command(&LinuxControllerCommand::Stop { grace_period_ms })?;
        self.exit_from_event(event)
    }

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError> {
        let event = self.command(&LinuxControllerCommand::Kill { signal })?;
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
                program: String::from("erebor-linux-session-controller"),
                source,
                location: snafu::Location::default(),
            })?
            .is_some()
        {
            return Ok(ActiveSessionHealth::Exited);
        }
        match self.command(&LinuxControllerCommand::Health)? {
            LinuxControllerEvent::Health { running: true } => Ok(ActiveSessionHealth::Running),
            LinuxControllerEvent::Health { running: false } => Ok(ActiveSessionHealth::Exited),
            LinuxControllerEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)?;
                Ok(ActiveSessionHealth::Exited)
            }
            LinuxControllerEvent::Failed { reason } => {
                self.observe_failure(reason)?;
                Ok(ActiveSessionHealth::Exited)
            }
            LinuxControllerEvent::Started { .. } => Ok(ActiveSessionHealth::Starting),
        }
    }
}

impl LinuxControllerSession {
    fn exit_from_event(
        &mut self,
        event: LinuxControllerEvent,
    ) -> Result<ActiveSessionExit, RuntimeError> {
        match event {
            LinuxControllerEvent::Exited { exit_code, signal } => {
                self.observe_exit(exit_code, signal)
            }
            LinuxControllerEvent::Failed { reason } => self.observe_failure(reason),
            LinuxControllerEvent::Started { .. } | LinuxControllerEvent::Health { .. } => {
                self.wait_for_exit()
            }
        }
    }
}

struct RecoveredLinuxSession {
    recovery: RunnerRecovery,
    capability: RunnerCapabilityDocument,
    process_group: rustix::process::Pid,
    process_start: u64,
    controller_pid: u32,
    controller_start: u64,
    id: RunnerId,
}

impl RecoveredLinuxSession {
    fn new(
        recovery: &RunnerRecovery,
        capability: RunnerCapabilityDocument,
        id: RunnerId,
    ) -> Result<Self, RuntimeError> {
        let parsed = decode_recovery(recovery, &id)?;
        let mut fields = parsed.workload_identity.split(':');
        if fields.next() != Some("linux") {
            return Err(recovery_error(&id));
        }
        let process_group = fields
            .next()
            .and_then(|value| value.strip_prefix("pid="))
            .and_then(|value| value.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| recovery_error(&id))?;
        let process_start = fields
            .next()
            .and_then(|value| value.strip_prefix("start="))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| recovery_error(&id))?;
        let session = Self {
            recovery: recovery.clone(),
            capability,
            process_group,
            process_start,
            controller_pid: parsed.controller_pid,
            controller_start: parsed.controller_start,
            id,
        };
        if !session.identity_is_live() {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: session.id.as_str().to_owned(),
                reason: String::from("saved Linux process/controller identity is no longer live"),
                location: snafu::Location::default(),
            });
        }
        Ok(session)
    }

    fn identity_is_live(&self) -> bool {
        process_start_time(self.process_group.as_raw_nonzero().get() as u32)
            == Some(self.process_start)
            && process_start_time(self.controller_pid) == Some(self.controller_start)
    }

    fn signal(&self, signal: rustix::process::Signal) -> Result<(), RuntimeError> {
        match rustix::process::kill_process_group(self.process_group, signal) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::SRCH) if !self.identity_is_live() => Ok(()),
            Err(error) => Err(RuntimeError::SessionRunnerProtocol {
                runner: self.id.as_str().to_owned(),
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
    fn recovery(&self) -> &RunnerRecovery {
        &self.recovery
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

fn encode_recovery(value: &LinuxRecovery) -> Result<RunnerRecovery, RuntimeError> {
    let payload =
        serde_json::to_string(value).map_err(|error| RuntimeError::SessionRunnerProtocol {
            runner: String::from(RUNNER_ID),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })?;
    RunnerRecovery::new(LINUX_RECOVERY_FORMAT_VERSION, payload).map_err(|error| {
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
) -> Result<LinuxRecovery, RuntimeError> {
    if recovery.format_version() != LINUX_RECOVERY_FORMAT_VERSION {
        return Err(recovery_error(id));
    }
    serde_json::from_str(recovery.payload()).map_err(|_error| recovery_error(id))
}

fn recovery_error(id: &RunnerId) -> RuntimeError {
    RuntimeError::SessionRunnerProtocol {
        runner: id.as_str().to_owned(),
        reason: String::from("saved Linux recovery value is malformed"),
        location: snafu::Location::default(),
    }
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
            reason: String::from("Linux controller closed its control stream"),
            location: snafu::Location::default(),
        });
    }
    serde_json::from_str(&line).map_err(|error| RuntimeError::SessionRunnerProtocol {
        runner: id.as_str().to_owned(),
        reason: error.to_string(),
        location: snafu::Location::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_recovery, encode_recovery, LinuxRecovery, RUNNER_ID};
    use erebor_runtime_core::RunnerId;

    #[test]
    fn linux_driver_round_trips_its_opaque_versioned_recovery_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = LinuxRecovery {
            workload_identity: String::from("linux:pid=42:start=99"),
            controller_pid: 41,
            controller_start: 98,
        };
        let encoded = encode_recovery(&expected)?;
        let decoded = decode_recovery(&encoded, &RunnerId::new(RUNNER_ID)?)?;

        assert_eq!(decoded.workload_identity, expected.workload_identity);
        assert_eq!(decoded.controller_pid, expected.controller_pid);
        assert_eq!(decoded.controller_start, expected.controller_start);
        Ok(())
    }
}
