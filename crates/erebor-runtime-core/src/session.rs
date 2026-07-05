use std::{io, thread, time::Duration};

mod docker;
mod linux_host;

use crate::error::UnsupportedSessionRunnerOperationSnafu;
use crate::{
    DockerSessionCommandOptions, LinuxHostSessionCommandOptions, RuntimeError, SessionAdoptPlan,
    SessionRunPlan, SessionRunnerKind,
};
use docker::DockerSessionOutputMode;
pub use docker::DockerSessionRunner;
use linux_host::LinuxHostSessionOutputMode;
pub use linux_host::LinuxHostSessionRunner;

const LINUX_HOST_TEXT_BUSY_RETRIES: usize = 5;
const LINUX_HOST_TEXT_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);

pub trait SessionRunner {
    fn kind(&self) -> SessionRunnerKind;

    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError>;
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
