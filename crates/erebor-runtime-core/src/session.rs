use std::{io, path::PathBuf, thread, time::Duration};

mod admission;
mod docker;
mod lifecycle;
mod linux_host;

use crate::error::UnsupportedSessionRunnerOperationSnafu;
use crate::{
    DockerSessionCommandOptions, LinuxHostSessionCommandOptions, RuntimeError, SessionAdoptPlan,
    SessionRunPlan, SessionRunnerKind,
};
pub use admission::{
    ActiveSessionSignalKind, DaemonFailureMode, EndpointProjection, EvidenceRequirement,
    FilesystemProjection, ImmutableIdentity, OutputPlan, OutputStreamRequirements, RunRequest,
    RunnerBinding, RunnerCapabilityDocument, RunnerId, RunnerRecovery, SafePathBinding,
    SafePathKind, SessionAdmission, SessionOwner, SessionSpec, WorkloadPrivilegePlan,
    RUNNER_CAPABILITY_SCHEMA_VERSION, RUNNER_RECOVERY_SCHEMA_VERSION, SESSION_SPEC_SCHEMA_VERSION,
};
use docker::DockerSessionOutputMode;
pub use docker::DockerSessionRunner;
pub use lifecycle::SessionLifecycleState;
use linux_host::LinuxHostSessionOutputMode;
pub use linux_host::LinuxHostSessionRunner;

const LINUX_HOST_TEXT_BUSY_RETRIES: usize = 5;
const LINUX_HOST_TEXT_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);

trait ForegroundSessionRunner {
    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputEndpoints {
    stdout: PathBuf,
    stderr: PathBuf,
    events: PathBuf,
    evidence: PathBuf,
    continuity: PathBuf,
    runtime_environment: Vec<(String, String)>,
    prepared_workspace: Option<PathBuf>,
    prepared_executable: Option<PathBuf>,
}

impl OutputEndpoints {
    #[must_use]
    pub fn new(
        stdout: PathBuf,
        stderr: PathBuf,
        events: PathBuf,
        evidence: PathBuf,
        continuity: PathBuf,
    ) -> Self {
        Self {
            stdout,
            stderr,
            events,
            evidence,
            continuity,
            runtime_environment: Vec::new(),
            prepared_workspace: None,
            prepared_executable: None,
        }
    }

    #[must_use]
    pub fn with_runtime_environment(mut self, environment: Vec<(String, String)>) -> Self {
        self.runtime_environment = environment;
        self
    }

    #[must_use]
    pub fn with_prepared_execution(
        mut self,
        workspace: PathBuf,
        executable: Option<PathBuf>,
    ) -> Self {
        self.prepared_workspace = Some(workspace);
        self.prepared_executable = executable;
        self
    }

    #[must_use]
    pub fn stdout(&self) -> &std::path::Path {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &std::path::Path {
        &self.stderr
    }

    #[must_use]
    pub fn events(&self) -> &std::path::Path {
        &self.events
    }

    #[must_use]
    pub fn evidence(&self) -> &std::path::Path {
        &self.evidence
    }

    #[must_use]
    pub fn continuity(&self) -> &std::path::Path {
        &self.continuity
    }

    #[must_use]
    pub fn runtime_environment(&self) -> &[(String, String)] {
        &self.runtime_environment
    }

    #[must_use]
    pub fn prepared_workspace(&self) -> Option<&std::path::Path> {
        self.prepared_workspace.as_deref()
    }

    #[must_use]
    pub fn prepared_executable(&self) -> Option<&std::path::Path> {
        self.prepared_executable.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveSessionHealth {
    Starting,
    Running,
    Exited,
    ControlLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveSessionSignal {
    Terminate,
    Kill,
    Interrupt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSessionExit {
    exit_code: Option<i32>,
    signal: Option<i32>,
    failure: Option<String>,
}

impl ActiveSessionExit {
    #[must_use]
    pub const fn new(exit_code: Option<i32>, signal: Option<i32>) -> Self {
        Self {
            exit_code,
            signal,
            failure: None,
        }
    }

    #[must_use]
    pub fn failed(exit_code: Option<i32>, signal: Option<i32>, reason: impl Into<String>) -> Self {
        Self {
            exit_code,
            signal,
            failure: Some(reason.into()),
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[must_use]
    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }

    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

pub trait ActiveSession: Send {
    fn recovery(&self) -> &RunnerRecovery;

    fn capability_snapshot(&self) -> &RunnerCapabilityDocument;

    fn wait(&mut self) -> Result<ActiveSessionExit, RuntimeError>;

    fn stop(&mut self, grace_period: Duration) -> Result<ActiveSessionExit, RuntimeError>;

    fn kill(&mut self, signal: ActiveSessionSignal) -> Result<ActiveSessionExit, RuntimeError>;

    fn health(&mut self) -> Result<ActiveSessionHealth, RuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunOutcome {
    runner: SessionRunnerKind,
    exit_code: Option<i32>,
}

impl SessionRunOutcome {
    #[must_use]
    pub const fn new(runner: SessionRunnerKind, exit_code: Option<i32>) -> Self {
        Self { runner, exit_code }
    }

    #[must_use]
    pub const fn runner(&self) -> SessionRunnerKind {
        self.runner
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

pub struct SessionRunnerLauncher;

impl SessionRunnerLauncher {
    pub fn run(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => DockerSessionRunner.run(plan, environment),
            SessionRunnerKind::LinuxHost => LinuxHostSessionRunner.run(plan, environment),
        }
    }

    pub fn run_with_docker_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &DockerSessionCommandOptions,
    ) -> Result<SessionRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => DockerSessionRunner
                .run_with_options(plan, environment, options, DockerSessionOutputMode::Inherit)
                .map(|outcome| outcome.run),
            SessionRunnerKind::LinuxHost => {
                let _ = options;
                LinuxHostSessionRunner.run(plan, environment)
            }
        }
    }

    pub fn run_capture_with_docker_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &DockerSessionCommandOptions,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => DockerSessionRunner.run_with_options(
                plan,
                environment,
                options,
                DockerSessionOutputMode::Capture,
            ),
            SessionRunnerKind::LinuxHost => {
                let _ = options;
                LinuxHostSessionRunner.run_with_options(
                    plan,
                    environment,
                    &LinuxHostSessionCommandOptions::default(),
                    LinuxHostSessionOutputMode::Capture,
                )
            }
        }
    }

    pub fn run_with_linux_host_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => DockerSessionRunner.run(plan, environment),
            SessionRunnerKind::LinuxHost => LinuxHostSessionRunner
                .run_with_options(
                    plan,
                    environment,
                    options,
                    LinuxHostSessionOutputMode::Inherit,
                )
                .map(|outcome| outcome.run),
        }
    }

    pub fn run_capture_with_linux_host_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => {
                let _ = options;
                DockerSessionRunner.run_with_options(
                    plan,
                    environment,
                    &DockerSessionCommandOptions::default(),
                    DockerSessionOutputMode::Capture,
                )
            }
            SessionRunnerKind::LinuxHost => LinuxHostSessionRunner.run_with_options(
                plan,
                environment,
                options,
                LinuxHostSessionOutputMode::Capture,
            ),
        }
    }

    pub fn adopt_with_linux_host_options(
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => UnsupportedSessionRunnerOperationSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                operation: String::from("adopt"),
            }
            .fail(),
            SessionRunnerKind::LinuxHost => LinuxHostSessionRunner
                .adopt_with_options(
                    plan,
                    environment,
                    options,
                    LinuxHostSessionOutputMode::Inherit,
                )
                .map(|outcome| outcome.run),
        }
    }

    pub fn adopt_capture_with_linux_host_options(
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => UnsupportedSessionRunnerOperationSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                operation: String::from("adopt"),
            }
            .fail(),
            SessionRunnerKind::LinuxHost => LinuxHostSessionRunner.adopt_with_options(
                plan,
                environment,
                options,
                LinuxHostSessionOutputMode::Capture,
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCapturedRunOutcome {
    pub(super) run: SessionRunOutcome,
    stdout: String,
    stderr: String,
}

impl SessionCapturedRunOutcome {
    #[must_use]
    pub fn new(run: SessionRunOutcome, stdout: String, stderr: String) -> Self {
        Self {
            run,
            stdout,
            stderr,
        }
    }

    #[must_use]
    pub const fn run(&self) -> &SessionRunOutcome {
        &self.run
    }

    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

pub(super) struct LinuxHostTextBusyRetry;

impl LinuxHostTextBusyRetry {
    pub(super) fn run<T>(mut launch: impl FnMut() -> Result<T, io::Error>) -> Result<T, io::Error> {
        let mut retries = 0;
        loop {
            match launch() {
                Err(error)
                    if error.kind() == io::ErrorKind::ExecutableFileBusy
                        && retries < LINUX_HOST_TEXT_BUSY_RETRIES =>
                {
                    retries += 1;
                    thread::sleep(LINUX_HOST_TEXT_BUSY_RETRY_DELAY);
                }
                result => return result,
            }
        }
    }
}
