use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::Duration,
};

use erebor_runtime_core::{
    ActiveSession, ActiveSessionExit, ActiveSessionHealth, ActiveSessionSignal,
    ActiveSessionSignalKind, DaemonFailureMode, OutputEndpoints, PreparedFilesystemProjection,
    RunnerBinding, RunnerCapabilityDocument, RunnerId, RunnerRecovery, RuntimeError,
    SafePathBinding, ScriptInterpreterBinding, SessionSpec, TerminalSize, WorkloadPrivilegePlan,
};
use serde::{Deserialize, Serialize};

use super::{
    HeldRunnerSession, HeldWorkloadBoundary, RunnerAdmissionContext, RunnerDriver,
    RunnerExecutionAdmission, RunnerInstallConfig, RunnerPreparation,
};
use crate::SessionManagerError;

const RUNNER_ID: &str = "linux-host";
const IMPLEMENTATION_ID: &str = "erebor-linux-host";
const CONTROLLER_PROGRAM: &str = "linux-session-controller";
const SYSTEMD_RUN_PROGRAM: &str = "systemd-run";
const DEFAULT_CONTROLLER_PATH: &str = "/usr/libexec/erebor/erebor-linux-session-controller";
const DEFAULT_SYSTEMD_RUN_PATH: &str = "/usr/bin/systemd-run";
const LINUX_RECOVERY_FORMAT_VERSION_V1: u32 = 1;
const LINUX_RECOVERY_FORMAT_VERSION_V2: u32 = 2;
const DEFAULT_SANITIZED_EXECUTABLE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const MAX_SCRIPT_INTERPRETER_CHAIN: usize = 4;
const MAX_SCRIPT_HEADER_BYTES: u64 = 4096;
const MAX_CONTROLLER_DIAGNOSTIC_CHARS: usize = 4096;
const CONTROLLER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

struct LinuxExecutableAdmission {
    executable: SafePathBinding,
    script_interpreters: Vec<ScriptInterpreterBinding>,
}

#[derive(Clone, Debug)]
pub(crate) struct LinuxRunnerDriver {
    id: RunnerId,
    controller_path: PathBuf,
    systemd_run_path: PathBuf,
    use_systemd_scope: bool,
    physical_interception: bool,
}

impl LinuxRunnerDriver {
    pub(crate) fn from_install_config(config: &RunnerInstallConfig) -> Result<Self, RuntimeError> {
        if config.physical_interception() && !config.use_systemd_scope() {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: String::from(RUNNER_ID),
                reason: String::from(
                    "physical interception requires delegated systemd containment",
                ),
                location: snafu::Location::default(),
            });
        }
        Ok(Self {
            id: RunnerId::new(RUNNER_ID).map_err(|error| {
                RuntimeError::SessionRunnerUnavailable {
                    runner: String::from(RUNNER_ID),
                    reason: error.to_string(),
                    location: snafu::Location::default(),
                }
            })?,
            controller_path: config.program(CONTROLLER_PROGRAM, Path::new(DEFAULT_CONTROLLER_PATH)),
            systemd_run_path: config
                .program(SYSTEMD_RUN_PROGRAM, Path::new(DEFAULT_SYSTEMD_RUN_PATH)),
            use_systemd_scope: config.use_systemd_scope(),
            physical_interception: config.physical_interception(),
        })
    }

    fn require_installed(&self) -> Result<(), RuntimeError> {
        require_executable(
            &self.id,
            &self.controller_path,
            "private Linux session controller",
        )?;
        if self.use_systemd_scope {
            require_executable(&self.id, &self.systemd_run_path, "systemd-run")?;
        }
        Ok(())
    }

    fn capability(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        let daemon_failure_modes = if self.physical_interception {
            BTreeSet::from([DaemonFailureMode::Terminate])
        } else {
            BTreeSet::from([DaemonFailureMode::Terminate, DaemonFailureMode::Continue])
        };
        RunnerCapabilityDocument::new(
            self.id.clone(),
            IMPLEMENTATION_ID,
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            true,
            self.physical_interception,
            BTreeSet::from([String::from("stdout"), String::from("stderr")]),
            BTreeSet::from([
                ActiveSessionSignalKind::Terminate,
                ActiveSessionSignalKind::Kill,
                ActiveSessionSignalKind::Interrupt,
            ]),
            true,
            true,
            daemon_failure_modes,
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
                    String::from("controller-rlimit-umask-groups-v1"),
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
        let mut controller = self.spawn_controller(spec, output, false)?;
        let started: LinuxControllerEvent = read_json_line(
            controller
                .output
                .as_mut()
                .ok_or_else(|| self.protocol("controller stdout missing"))?,
            &self.id,
        )
        .map_err(|error| {
            self.startup_error_with_diagnostics(error, &controller.diagnostics_path)
        })?;
        let LinuxControllerEvent::Started {
            workload_identity,
            controller_pid,
        } = started
        else {
            return Err(self.protocol(format!("expected started event, received {started:?}")));
        };
        self.active_session(
            controller,
            capability,
            workload_identity,
            controller_pid,
            None,
        )
    }

    fn launch_held(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
        capability: RunnerCapabilityDocument,
    ) -> Result<Box<dyn HeldRunnerSession>, RuntimeError> {
        let mut controller = self.spawn_controller(spec, output, true)?;
        let prepared: LinuxControllerEvent = read_json_line(
            controller
                .output
                .as_mut()
                .ok_or_else(|| self.protocol("controller stdout missing"))?,
            &self.id,
        )
        .map_err(|error| {
            self.startup_error_with_diagnostics(error, &controller.diagnostics_path)
        })?;
        let LinuxControllerEvent::Prepared {
            boundary,
            controller_pid,
        } = prepared
        else {
            return Err(self.protocol(format!("expected prepared event, received {prepared:?}")));
        };
        Ok(Box::new(LinuxHeldControllerSession {
            boundary,
            controller_pid,
            capability,
            controller: Some(controller),
            id: self.id.clone(),
        }))
    }

    fn spawn_controller(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
        physical_interception: bool,
    ) -> Result<LinuxControllerProcess, RuntimeError> {
        let unit = format!("erebor-session-{}.scope", spec.session_id().as_str());
        let session_slice = format!("erebor-session-{}.slice", spec.session_id().as_str());
        let handoff = LinuxControllerHandoff {
            spec: spec.clone(),
            stdout_path: output.stdout().to_path_buf(),
            stderr_path: output.stderr().to_path_buf(),
            events_path: output.events().to_path_buf(),
            evidence_path: output.evidence().to_path_buf(),
            journal_path: output.continuity().to_path_buf(),
            runtime_environment: output.runtime_environment().to_vec(),
            prepared_workspace: output.prepared_workspace().map(Path::to_path_buf),
            prepared_executable: output.prepared_executable().map(Path::to_path_buf),
            prepared_interpreters: output.prepared_interpreters().to_vec(),
            prepared_filesystem_projections: output.prepared_filesystem_projections().to_vec(),
            prepared_private_state_projection: output.prepared_private_state_projection().cloned(),
            systemd_scope_unit: self.use_systemd_scope.then_some(unit.clone()),
            systemd_session_slice: self.use_systemd_scope.then_some(session_slice.clone()),
            physical_interception,
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
        let child = command
            .spawn()
            .map_err(|source| self.launch_error(launch_path, source))?;
        let mut controller = LinuxControllerProcess {
            child: Some(child),
            input: None,
            output: None,
            diagnostics_path,
        };
        let child = controller
            .child
            .as_mut()
            .ok_or_else(|| self.protocol("controller process missing after spawn"))?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| self.protocol("controller stdin missing"))?;
        let output_pipe = child
            .stdout
            .take()
            .ok_or_else(|| self.protocol("controller stdout missing"))?;
        write_json_line(&mut input, &self.id, &handoff).map_err(|error| {
            self.startup_error_with_diagnostics(error, &controller.diagnostics_path)
        })?;
        controller.input = Some(input);
        controller.output = Some(BufReader::new(output_pipe));
        Ok(controller)
    }

    fn active_session(
        &self,
        controller: LinuxControllerProcess,
        capability: RunnerCapabilityDocument,
        workload_identity: String,
        controller_pid: u32,
        cgroup: Option<LinuxCgroupRecovery>,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let cgroup_path = cgroup.as_ref().map(|cgroup| cgroup.path.clone());
        let recovery = LinuxRecovery {
            workload_identity,
            controller_pid,
            controller_start: process_start_time(controller_pid).unwrap_or(0),
            cgroup,
        };
        let recovery = encode_recovery(&recovery)?;
        let (child, input, output) = controller
            .into_parts()
            .ok_or_else(|| self.protocol("controller startup ownership is incomplete"))?;
        Ok(Box::new(LinuxControllerSession {
            recovery,
            capability,
            child,
            input,
            output,
            observed_exit: None,
            cgroup_path,
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

    fn startup_error_with_diagnostics(
        &self,
        error: RuntimeError,
        diagnostics_path: &Path,
    ) -> RuntimeError {
        let Some(diagnostics) = Self::diagnostics_tail(diagnostics_path) else {
            return error;
        };
        let RuntimeError::SessionRunnerProtocol { reason, .. } = error else {
            return error;
        };
        self.protocol(format!("{reason}; controller diagnostics: {diagnostics}"))
    }

    fn diagnostics_tail(path: &Path) -> Option<String> {
        let diagnostics = fs::read(path).ok()?;
        let text = String::from_utf8_lossy(&diagnostics);
        let tail = text
            .chars()
            .rev()
            .take(MAX_CONTROLLER_DIAGNOSTIC_CHARS)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        let tail = tail.trim();
        (!tail.is_empty()).then(|| tail.replace('\n', " "))
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

    fn capability_document(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
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
        let executable = self.resolve_executable(context, program)?;
        let workload_privileges = WorkloadPrivilegePlan::new(Vec::new(), 0o077, 1024, 16_384, 0)
            .map_err(|source| context.invalid(source.to_string()))?;
        // The held workspace descriptor is the workload current directory. It
        // is not a separate namespace projection, so do not claim a `/workspace`
        // mount that the controller never created.
        let filesystem_projections = Vec::new();
        let endpoint_projections = Vec::new();
        Ok(RunnerExecutionAdmission {
            workspace: context.workspace().clone(),
            workload_privileges,
            executable: Some(executable.executable),
            script_interpreters: executable.script_interpreters,
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

    fn prepare(
        &self,
        spec: &SessionSpec,
        resources: &RunnerPreparation<'_>,
    ) -> Result<OutputEndpoints, SessionManagerError> {
        let output = resources.prepare_execution(spec)?;
        resources.start_session_services(spec, output)
    }

    fn start(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        self.require_installed()?;
        self.launch(spec, output, self.capability()?)
    }

    fn start_held(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn HeldRunnerSession>, RuntimeError> {
        self.require_installed()?;
        if !self.physical_interception || !self.use_systemd_scope {
            return Err(self.protocol(
                "held Linux workload activation requires physical systemd interception",
            ));
        }
        self.launch_held(spec, output, self.capability()?)
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
        if decode_recovery(binding.recovery(), &self.id)?
            .cgroup
            .is_some()
        {
            return Err(RuntimeError::SessionRunnerUnavailable {
                runner: self.id.as_str().to_owned(),
                reason: String::from(
                    "intercepted Linux session recovery requires workload-owner adoption",
                ),
                location: snafu::Location::default(),
            });
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

impl LinuxRunnerDriver {
    fn resolve_executable(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
        program: &str,
    ) -> Result<LinuxExecutableAdmission, SessionManagerError> {
        let requested = Path::new(program);
        if requested.is_absolute() {
            return self.resolve_executable_path(context, requested);
        }
        if program.contains('/') || program.is_empty() {
            return Err(context
                .invalid("Linux-host executable must be an absolute path or a bare command name"));
        }
        let search_path = context
            .executable_search_path()
            .unwrap_or(DEFAULT_SANITIZED_EXECUTABLE_PATH);
        let directories = search_path
            .split(':')
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        if directories.is_empty() || directories.iter().any(|path| !Self::sanitized_path(path)) {
            return Err(context
                .invalid("Linux-host PATH must contain only normalized absolute directories"));
        }
        for directory in directories {
            let candidate = directory.join(program);
            if let Ok(admission) = self.resolve_executable_path(context, &candidate) {
                return Ok(admission);
            }
        }
        Err(context.invalid(format!(
            "Linux-host executable `{program}` was not found in the caller PATH"
        )))
    }

    fn resolve_executable_path(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
        path: &Path,
    ) -> Result<LinuxExecutableAdmission, SessionManagerError> {
        let (executable, header) =
            context.resolve_executable_prefix(path, MAX_SCRIPT_HEADER_BYTES)?;
        let script_interpreters =
            self.resolve_script_interpreters(context, executable.clone(), header)?;
        Ok(LinuxExecutableAdmission {
            executable,
            script_interpreters,
        })
    }

    fn resolve_script_interpreters(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
        executable: SafePathBinding,
        mut header: Vec<u8>,
    ) -> Result<Vec<ScriptInterpreterBinding>, SessionManagerError> {
        let mut interpreters = Vec::new();
        let mut seen = BTreeSet::from([executable.requested_path().to_path_buf()]);
        if header.starts_with(b"#!")
            && header.len() == MAX_SCRIPT_HEADER_BYTES as usize
            && !header.contains(&b'\n')
        {
            return Err(context.invalid("script shebang exceeds the supported header bound"));
        }
        while let Some((interpreter, arguments)) = Self::script_interpreter(&header)? {
            if interpreters.len() == MAX_SCRIPT_INTERPRETER_CHAIN {
                return Err(context.invalid("script interpreter chain exceeds the supported depth"));
            }
            let interpreter = self.resolve_executable(context, &interpreter)?;
            if !seen.insert(interpreter.executable.requested_path().to_path_buf()) {
                return Err(context.invalid("script interpreter chain contains a cycle"));
            }
            header = context
                .resolve_executable_prefix(
                    interpreter.executable.requested_path(),
                    MAX_SCRIPT_HEADER_BYTES,
                )?
                .1;
            if header.starts_with(b"#!")
                && header.len() == MAX_SCRIPT_HEADER_BYTES as usize
                && !header.contains(&b'\n')
            {
                return Err(context.invalid("script shebang exceeds the supported header bound"));
            }
            interpreters.push(
                ScriptInterpreterBinding::new(interpreter.executable, arguments)
                    .map_err(|source| context.invalid(source.to_string()))?,
            );
        }
        Ok(interpreters)
    }

    fn script_interpreter(
        header: &[u8],
    ) -> Result<Option<(String, Vec<String>)>, SessionManagerError> {
        let Some(line) = header
            .strip_prefix(b"#!")
            .and_then(|source| source.split(|byte| *byte == b'\n').next())
        else {
            return Ok(None);
        };
        let source =
            std::str::from_utf8(line).map_err(|error| SessionManagerError::InvalidOperation {
                session_id: String::from("linux-host-admission"),
                reason: format!("script shebang is not UTF-8: {error}"),
                location: snafu::Location::default(),
            })?;
        let source = source.trim();
        let (program, remainder) = source
            .split_once(char::is_whitespace)
            .map_or((source, ""), |(program, remainder)| {
                (program, remainder.trim())
            });
        if program.is_empty() {
            return Err(SessionManagerError::InvalidOperation {
                session_id: String::from("linux-host-admission"),
                reason: String::from("script shebang has no interpreter"),
                location: snafu::Location::default(),
            });
        }
        if program == "/usr/bin/env" || program == "/bin/env" {
            if remainder.is_empty()
                || remainder.contains(char::is_whitespace)
                || remainder.starts_with('-')
                || remainder.contains('=')
            {
                return Err(SessionManagerError::InvalidOperation {
                    session_id: String::from("linux-host-admission"),
                    reason: String::from(
                        "script uses an unsupported env-based interpreter selection",
                    ),
                    location: snafu::Location::default(),
                });
            }
            return Ok(Some((String::from(remainder), Vec::new())));
        }
        if !Path::new(program).is_absolute() {
            return Err(SessionManagerError::InvalidOperation {
                session_id: String::from("linux-host-admission"),
                reason: String::from("script shebang interpreter must be absolute"),
                location: snafu::Location::default(),
            });
        }
        Ok(Some((
            String::from(program),
            (!remainder.is_empty())
                .then_some(String::from(remainder))
                .into_iter()
                .collect(),
        )))
    }

    fn sanitized_path(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxControllerHandoff {
    pub(crate) spec: SessionSpec,
    pub(crate) stdout_path: PathBuf,
    pub(crate) stderr_path: PathBuf,
    pub(crate) events_path: PathBuf,
    pub(crate) evidence_path: PathBuf,
    pub(crate) journal_path: PathBuf,
    pub(crate) runtime_environment: Vec<(String, String)>,
    pub(crate) prepared_workspace: Option<PathBuf>,
    pub(crate) prepared_executable: Option<PathBuf>,
    pub(crate) prepared_interpreters: Vec<PathBuf>,
    pub(crate) prepared_filesystem_projections: Vec<PreparedFilesystemProjection>,
    pub(crate) prepared_private_state_projection:
        Option<erebor_runtime_core::PreparedPrivateStateProjection>,
    pub(crate) systemd_scope_unit: Option<String>,
    pub(crate) systemd_session_slice: Option<String>,
    pub(crate) physical_interception: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(crate) enum LinuxControllerCommand {
    Release,
    Cancel,
    Stop { grace_period_ms: u64 },
    Kill { signal: ActiveSessionSignal },
    Input { data: Vec<u8> },
    Resize { rows: u16, columns: u16 },
    CloseInput,
    Health,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum LinuxControllerEvent {
    Prepared {
        boundary: HeldWorkloadBoundary,
        controller_pid: u32,
    },
    Started {
        workload_identity: String,
        controller_pid: u32,
    },
    Health {
        running: bool,
    },
    InputAccepted {
        accepted_bytes: u32,
    },
    Resized {
        rows: u16,
        columns: u16,
    },
    InputClosed,
    Exited {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug)]
struct LinuxRecovery {
    workload_identity: String,
    controller_pid: u32,
    controller_start: u64,
    cgroup: Option<LinuxCgroupRecovery>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxCgroupRecovery {
    path: PathBuf,
    id: u64,
    controller_id: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxRecoveryV1 {
    workload_identity: String,
    controller_pid: u32,
    controller_start: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxRecoveryV2 {
    workload_identity: String,
    controller_pid: u32,
    controller_start: u64,
    cgroup: LinuxCgroupRecovery,
}

struct LinuxControllerProcess {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<BufReader<ChildStdout>>,
    diagnostics_path: PathBuf,
}

impl LinuxControllerProcess {
    fn terminate(&mut self) {
        self.input.take();
        self.wait_or_kill();
    }

    fn cancel_prepared(&mut self, id: &RunnerId) {
        if let Some(input) = self.input.as_mut() {
            let _result = write_json_line(input, id, &LinuxControllerCommand::Cancel);
        }
        self.input.take();
        self.wait_or_kill();
    }

    fn wait_or_kill(&mut self) {
        let deadline = std::time::Instant::now() + CONTROLLER_CLEANUP_TIMEOUT;
        while std::time::Instant::now() < deadline {
            let Some(child) = self.child.as_mut() else {
                return;
            };
            match child.try_wait() {
                Ok(Some(_status)) => {
                    self.child.take();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_error) => break,
            }
        }
        if let Some(mut child) = self.child.take() {
            let _result = child.kill();
            let _result = child.wait();
        }
    }

    fn into_parts(mut self) -> Option<(Child, ChildStdin, BufReader<ChildStdout>)> {
        Some((self.child.take()?, self.input.take()?, self.output.take()?))
    }
}

impl Drop for LinuxControllerProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct LinuxHeldControllerSession {
    boundary: HeldWorkloadBoundary,
    controller_pid: u32,
    capability: RunnerCapabilityDocument,
    controller: Option<LinuxControllerProcess>,
    id: RunnerId,
}

impl LinuxHeldControllerSession {
    fn protocol(&self, reason: impl Into<String>) -> RuntimeError {
        RuntimeError::SessionRunnerProtocol {
            runner: self.id.as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }

    fn terminate_released(&self, controller: &mut LinuxControllerProcess) {
        if let Some(input) = controller.input.as_mut() {
            let _result = write_json_line(
                input,
                &self.id,
                &LinuxControllerCommand::Kill {
                    signal: ActiveSessionSignal::Kill,
                },
            );
        }
        controller.terminate();
    }
}

impl HeldRunnerSession for LinuxHeldControllerSession {
    fn boundary(&self) -> &HeldWorkloadBoundary {
        &self.boundary
    }

    fn release(mut self: Box<Self>) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let mut controller = self
            .controller
            .take()
            .ok_or_else(|| self.protocol("held Linux controller is unavailable"))?;
        if let Err(error) = write_json_line(
            controller
                .input
                .as_mut()
                .ok_or_else(|| self.protocol("held Linux controller stdin is unavailable"))?,
            &self.id,
            &LinuxControllerCommand::Release,
        ) {
            self.terminate_released(&mut controller);
            return Err(error);
        }
        let started: LinuxControllerEvent = match read_json_line(
            controller
                .output
                .as_mut()
                .ok_or_else(|| self.protocol("held Linux controller stdout is unavailable"))?,
            &self.id,
        ) {
            Ok(event) => event,
            Err(error) => {
                self.terminate_released(&mut controller);
                return Err(error);
            }
        };
        let LinuxControllerEvent::Started {
            workload_identity,
            controller_pid,
        } = started
        else {
            self.terminate_released(&mut controller);
            return Err(self.protocol(format!(
                "expected started event after release, received {started:?}"
            )));
        };
        if controller_pid != self.controller_pid {
            self.terminate_released(&mut controller);
            return Err(self.protocol("Linux controller identity changed during held activation"));
        }
        let cgroup = match &self.boundary {
            HeldWorkloadBoundary::LinuxCgroup {
                path,
                id,
                controller_id,
            } => LinuxCgroupRecovery {
                path: path.clone(),
                id: *id,
                controller_id: *controller_id,
            },
        };
        let recovery = LinuxRecovery {
            workload_identity,
            controller_pid,
            controller_start: process_start_time(controller_pid).unwrap_or(0),
            cgroup: Some(cgroup),
        };
        let cgroup_path = recovery.cgroup.as_ref().map(|cgroup| cgroup.path.clone());
        let recovery = match encode_recovery(&recovery) {
            Ok(recovery) => recovery,
            Err(error) => {
                self.terminate_released(&mut controller);
                return Err(error);
            }
        };
        let (child, input, output) = controller
            .into_parts()
            .ok_or_else(|| self.protocol("released Linux controller ownership is incomplete"))?;
        Ok(Box::new(LinuxControllerSession {
            recovery,
            capability: self.capability.clone(),
            child,
            input,
            output,
            observed_exit: None,
            cgroup_path,
            id: self.id.clone(),
        }))
    }
}

impl Drop for LinuxHeldControllerSession {
    fn drop(&mut self) {
        if let Some(controller) = self.controller.as_mut() {
            controller.cancel_prepared(&self.id);
        }
    }
}

struct LinuxControllerSession {
    recovery: RunnerRecovery,
    capability: RunnerCapabilityDocument,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    observed_exit: Option<ActiveSessionExit>,
    cgroup_path: Option<PathBuf>,
    id: RunnerId,
}

impl LinuxControllerSession {
    fn protocol(&self, reason: impl Into<String>) -> RuntimeError {
        RuntimeError::SessionRunnerProtocol {
            runner: self.id.as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }

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
                LinuxControllerEvent::Prepared { .. }
                | LinuxControllerEvent::Started { .. }
                | LinuxControllerEvent::Health { .. }
                | LinuxControllerEvent::InputAccepted { .. }
                | LinuxControllerEvent::Resized { .. }
                | LinuxControllerEvent::InputClosed => {}
            }
        }
    }

    fn observe_exit(
        &mut self,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<ActiveSessionExit, RuntimeError> {
        let exit = ActiveSessionExit::new(exit_code, signal);
        self.child
            .wait()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: self.id.as_str().to_owned(),
                program: String::from("erebor-linux-session-controller"),
                source,
                location: snafu::Location::default(),
            })?;
        self.observed_exit = Some(exit.clone());
        Ok(exit)
    }

    fn observe_failure(&mut self, reason: String) -> Result<ActiveSessionExit, RuntimeError> {
        let exit = ActiveSessionExit::failed(Some(125), None, reason);
        self.child
            .wait()
            .map_err(|source| RuntimeError::SessionRunnerLaunch {
                runner: self.id.as_str().to_owned(),
                program: String::from("erebor-linux-session-controller"),
                source,
                location: snafu::Location::default(),
            })?;
        self.observed_exit = Some(exit.clone());
        Ok(exit)
    }
}

impl Drop for LinuxControllerSession {
    fn drop(&mut self) {
        if self.observed_exit.is_none() && self.cgroup_path.is_some() {
            let _result = write_json_line(
                &mut self.input,
                &self.id,
                &LinuxControllerCommand::Kill {
                    signal: ActiveSessionSignal::Kill,
                },
            );
            let deadline = std::time::Instant::now() + CONTROLLER_CLEANUP_TIMEOUT;
            while std::time::Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_status)) => return,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_error) => break,
                }
            }
            let _result = self.child.kill();
            let _result = self.child.wait();
        }
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

    fn write_input(&mut self, data: &[u8]) -> Result<(), RuntimeError> {
        let accepted_bytes = u32::try_from(data.len()).map_err(|_error| {
            self.protocol("interactive input exceeds the Linux controller protocol limit")
        })?;
        match self.command(&LinuxControllerCommand::Input {
            data: data.to_vec(),
        })? {
            LinuxControllerEvent::InputAccepted {
                accepted_bytes: observed,
            } if observed == accepted_bytes => Ok(()),
            event => Err(self.protocol(format!(
                "expected interactive-input acknowledgement, received {event:?}"
            ))),
        }
    }

    fn resize_terminal(&mut self, size: TerminalSize) -> Result<(), RuntimeError> {
        match self.command(&LinuxControllerCommand::Resize {
            rows: size.rows(),
            columns: size.columns(),
        })? {
            LinuxControllerEvent::Resized { rows, columns }
                if rows == size.rows() && columns == size.columns() =>
            {
                Ok(())
            }
            event => Err(self.protocol(format!(
                "expected terminal-resize acknowledgement, received {event:?}"
            ))),
        }
    }

    fn close_input(&mut self) -> Result<(), RuntimeError> {
        match self.command(&LinuxControllerCommand::CloseInput)? {
            LinuxControllerEvent::InputClosed => Ok(()),
            event => Err(self.protocol(format!(
                "expected structured-input EOF acknowledgement, received {event:?}"
            ))),
        }
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
            LinuxControllerEvent::Prepared { .. }
            | LinuxControllerEvent::Started { .. }
            | LinuxControllerEvent::InputAccepted { .. }
            | LinuxControllerEvent::Resized { .. }
            | LinuxControllerEvent::InputClosed => Ok(ActiveSessionHealth::Starting),
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
            LinuxControllerEvent::Prepared { .. }
            | LinuxControllerEvent::Started { .. }
            | LinuxControllerEvent::Health { .. }
            | LinuxControllerEvent::InputAccepted { .. }
            | LinuxControllerEvent::Resized { .. }
            | LinuxControllerEvent::InputClosed => self.wait_for_exit(),
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
    let (format_version, payload) = match &value.cgroup {
        None => (
            LINUX_RECOVERY_FORMAT_VERSION_V1,
            serde_json::to_string(&LinuxRecoveryV1 {
                workload_identity: value.workload_identity.clone(),
                controller_pid: value.controller_pid,
                controller_start: value.controller_start,
            }),
        ),
        Some(cgroup) => (
            LINUX_RECOVERY_FORMAT_VERSION_V2,
            serde_json::to_string(&LinuxRecoveryV2 {
                workload_identity: value.workload_identity.clone(),
                controller_pid: value.controller_pid,
                controller_start: value.controller_start,
                cgroup: cgroup.clone(),
            }),
        ),
    };
    let payload = payload.map_err(|error| RuntimeError::SessionRunnerProtocol {
        runner: String::from(RUNNER_ID),
        reason: error.to_string(),
        location: snafu::Location::default(),
    })?;
    RunnerRecovery::new(format_version, payload).map_err(|error| {
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
    match recovery.format_version() {
        LINUX_RECOVERY_FORMAT_VERSION_V1 => {
            let value: LinuxRecoveryV1 =
                serde_json::from_str(recovery.payload()).map_err(|_error| recovery_error(id))?;
            Ok(LinuxRecovery {
                workload_identity: value.workload_identity,
                controller_pid: value.controller_pid,
                controller_start: value.controller_start,
                cgroup: None,
            })
        }
        LINUX_RECOVERY_FORMAT_VERSION_V2 => {
            let value: LinuxRecoveryV2 =
                serde_json::from_str(recovery.payload()).map_err(|_error| recovery_error(id))?;
            Ok(LinuxRecovery {
                workload_identity: value.workload_identity,
                controller_pid: value.controller_pid,
                controller_start: value.controller_start,
                cgroup: Some(value.cgroup),
            })
        }
        _ => Err(recovery_error(id)),
    }
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
    use std::{
        collections::BTreeMap,
        fs::File,
        path::{Path, PathBuf},
        sync::Arc,
    };

    use super::{
        decode_recovery, encode_recovery, LinuxControllerCommand, LinuxControllerEvent,
        LinuxRecovery, LinuxRunnerDriver, CONTROLLER_PROGRAM, DEFAULT_CONTROLLER_PATH,
        LINUX_RECOVERY_FORMAT_VERSION_V1, LINUX_RECOVERY_FORMAT_VERSION_V2,
        MAX_CONTROLLER_DIAGNOSTIC_CHARS, RUNNER_ID,
    };
    use crate::{
        HeldWorkloadBoundary, ResolvedSessionPath, RunnerAdmissionRequest, RunnerInstallConfig,
        RunnerRegistry, SessionPathResolver, SessionPathResolverError,
    };
    use erebor_runtime_core::{
        RunnerId, RunnerRecovery, RuntimeError, SafePathBinding, SafePathKind, SessionOwner,
    };

    struct ScriptResolver;

    impl SessionPathResolver for ScriptResolver {
        fn resolve(
            &self,
            _uid: u32,
            _gid: u32,
            path: &Path,
            kind: SafePathKind,
        ) -> Result<ResolvedSessionPath, SessionPathResolverError> {
            let file =
                File::open(path).map_err(|error| Box::new(error) as SessionPathResolverError)?;
            let binding = SafePathBinding::new(path.to_path_buf(), 1, 1, 1, 1000, 1000, kind)
                .and_then(|binding| match kind {
                    SafePathKind::Executable => binding.with_content_sha256("a".repeat(64)),
                    SafePathKind::Directory | SafePathKind::File => Ok(binding),
                })
                .map_err(|error| Box::new(error) as SessionPathResolverError)?;
            Ok(ResolvedSessionPath::new(file, binding))
        }
    }

    #[test]
    fn linux_driver_owns_its_installation_program_names_and_defaults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let default = LinuxRunnerDriver::from_install_config(&RunnerInstallConfig::default())?;
        assert_eq!(
            default.controller_path,
            PathBuf::from(DEFAULT_CONTROLLER_PATH)
        );
        assert!(!default.use_systemd_scope);

        let override_path = PathBuf::from("/opt/erebor/linux-controller");
        let configured = LinuxRunnerDriver::from_install_config(&RunnerInstallConfig::new(
            BTreeMap::from([(String::from(CONTROLLER_PROGRAM), override_path.clone())]),
            false,
            false,
        ))?;
        assert_eq!(configured.controller_path, override_path);
        assert!(!configured.use_systemd_scope);
        Ok(())
    }

    #[test]
    fn linux_driver_rejects_physical_interception_without_systemd() {
        let result = LinuxRunnerDriver::from_install_config(&RunnerInstallConfig::new(
            BTreeMap::new(),
            false,
            true,
        ));

        assert!(matches!(
            result,
            Err(RuntimeError::SessionRunnerUnavailable { .. })
        ));
    }

    #[test]
    fn physical_interception_advertises_only_terminating_daemon_loss(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let driver = LinuxRunnerDriver::from_install_config(&RunnerInstallConfig::new(
            BTreeMap::new(),
            true,
            true,
        ))?;
        let capability = driver.capability()?;

        assert!(capability.supports_failure_mode(erebor_runtime_core::DaemonFailureMode::Terminate));
        assert!(!capability.supports_failure_mode(erebor_runtime_core::DaemonFailureMode::Continue));
        Ok(())
    }

    #[test]
    fn held_controller_protocol_has_distinct_prepare_and_release_messages(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let boundary = HeldWorkloadBoundary::LinuxCgroup {
            path: PathBuf::from("/sys/fs/cgroup/session/workload"),
            id: 42,
            controller_id: 41,
        };
        let event = LinuxControllerEvent::Prepared {
            boundary: boundary.clone(),
            controller_pid: 99,
        };

        let encoded_event = serde_json::to_string(&event)?;
        let decoded_event: LinuxControllerEvent = serde_json::from_str(&encoded_event)?;
        let LinuxControllerEvent::Prepared {
            boundary: decoded_boundary,
            controller_pid,
        } = decoded_event
        else {
            return Err("prepared event changed variant".into());
        };
        assert_eq!(decoded_boundary, boundary);
        assert_eq!(controller_pid, 99);
        assert_eq!(
            serde_json::to_string(&LinuxControllerCommand::Release)?,
            r#"{"command":"release"}"#
        );
        Ok(())
    }

    #[test]
    fn linux_driver_round_trips_its_opaque_versioned_recovery_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = LinuxRecovery {
            workload_identity: String::from("linux:pid=42:start=99"),
            controller_pid: 41,
            controller_start: 98,
            cgroup: None,
        };
        let encoded = encode_recovery(&expected)?;
        assert_eq!(encoded.format_version(), LINUX_RECOVERY_FORMAT_VERSION_V1);
        let decoded = decode_recovery(&encoded, &RunnerId::new(RUNNER_ID)?)?;

        assert_eq!(decoded.workload_identity, expected.workload_identity);
        assert_eq!(decoded.controller_pid, expected.controller_pid);
        assert_eq!(decoded.controller_start, expected.controller_start);
        Ok(())
    }

    #[test]
    fn linux_driver_retains_the_intercepted_cgroup_recovery_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = LinuxRecovery {
            workload_identity: String::from("linux:pid=42:start=99"),
            controller_pid: 41,
            controller_start: 98,
            cgroup: Some(super::LinuxCgroupRecovery {
                path: PathBuf::from("/sys/fs/cgroup/session/workload"),
                id: 42,
                controller_id: 41,
            }),
        };

        let encoded = encode_recovery(&expected)?;
        assert_eq!(encoded.format_version(), LINUX_RECOVERY_FORMAT_VERSION_V2);
        let decoded = decode_recovery(&encoded, &RunnerId::new(RUNNER_ID)?)?;
        let cgroup = decoded.cgroup.ok_or("cgroup recovery was not retained")?;
        assert_eq!(cgroup.path, Path::new("/sys/fs/cgroup/session/workload"));
        assert_eq!(cgroup.id, 42);
        assert_eq!(cgroup.controller_id, 41);
        Ok(())
    }

    #[test]
    fn legacy_recovery_rejects_interception_fields() -> Result<(), Box<dyn std::error::Error>> {
        let recovery = RunnerRecovery::new(
            LINUX_RECOVERY_FORMAT_VERSION_V1,
            r#"{"workload_identity":"linux:pid=42:start=99","controller_pid":41,"controller_start":98,"cgroup":{"path":"/sys/fs/cgroup/session/workload","id":42,"controller_id":41}}"#,
        )?;

        assert!(decode_recovery(&recovery, &RunnerId::new(RUNNER_ID)?).is_err());
        Ok(())
    }

    #[test]
    fn executable_path_rejects_relative_or_traversal_entries() {
        assert!(LinuxRunnerDriver::sanitized_path(&PathBuf::from(
            "/usr/bin"
        )));
        assert!(!LinuxRunnerDriver::sanitized_path(&PathBuf::from("bin")));
        assert!(!LinuxRunnerDriver::sanitized_path(&PathBuf::from(
            "/usr/../bin"
        )));
        assert!(!LinuxRunnerDriver::sanitized_path(&PathBuf::from("")));
    }

    #[test]
    fn linux_admission_pins_a_script_interpreter_and_its_shebang_argument(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let script = root.path().join("agent-script");
        std::fs::write(&script, b"#!/bin/sh -eu\necho governed\n")?;
        let owner = SessionOwner::new(1000, 1000);
        let command = vec![script.display().to_string(), String::from("argument")];
        let registry = RunnerRegistry::new([Arc::new(LinuxRunnerDriver::from_install_config(
            &RunnerInstallConfig::default(),
        )?) as Arc<dyn super::RunnerDriver>]);
        let admission = registry.admit(
            &RunnerId::new(RUNNER_ID)?,
            RunnerAdmissionRequest::new(
                "session-script",
                &owner,
                &command,
                None,
                root.path(),
                None,
            ),
            &ScriptResolver,
        )?;
        assert_eq!(admission.workload_privileges.maximum_processes(), 16_384);
        assert_eq!(admission.script_interpreters.len(), 1);
        let interpreter = &admission.script_interpreters[0];
        assert_eq!(
            interpreter.executable().requested_path(),
            Path::new("/bin/sh")
        );
        assert_eq!(interpreter.arguments(), &[String::from("-eu")]);
        Ok(())
    }

    #[test]
    fn script_shebang_rejects_ambient_env_options() {
        assert!(LinuxRunnerDriver::script_interpreter(b"#!/usr/bin/env -S python -I\n").is_err());
    }

    #[test]
    fn controller_diagnostics_tail_is_bounded_and_single_line(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let diagnostics = root.path().join("linux-controller-diagnostics.log");
        let prefix = "x".repeat(MAX_CONTROLLER_DIAGNOSTIC_CHARS);
        std::fs::write(&diagnostics, format!("{prefix}\nmount namespace failed\n"))?;

        let tail = LinuxRunnerDriver::diagnostics_tail(&diagnostics)
            .ok_or("expected controller diagnostics tail")?;

        assert!(tail.ends_with("mount namespace failed"));
        assert!(!tail.contains('\n'));
        assert!(tail.chars().count() <= MAX_CONTROLLER_DIAGNOSTIC_CHARS);

        let startup_diagnostics = root.path().join("startup.log");
        std::fs::write(&startup_diagnostics, "mount namespace failed\n")?;
        let driver = LinuxRunnerDriver::from_install_config(&RunnerInstallConfig::default())?;
        let error = driver.startup_error_with_diagnostics(
            RuntimeError::SessionRunnerProtocol {
                runner: String::from(RUNNER_ID),
                reason: String::from("Broken pipe"),
                location: snafu::Location::default(),
            },
            &startup_diagnostics,
        );
        assert!(error
            .to_string()
            .contains("Broken pipe; controller diagnostics: mount namespace failed"));
        Ok(())
    }
}
