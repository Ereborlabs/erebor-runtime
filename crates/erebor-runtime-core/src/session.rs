use std::process::Command as ProcessCommand;

use tracing::info;

use crate::{
    DockerSessionCommandOptions, DockerSessionCommandPlan, RuntimeError, SessionRunPlan,
    SessionRunnerKind,
};

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
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DockerSessionRunner;

impl SessionRunner for DockerSessionRunner {
    fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::Docker
    }

    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        let launch =
            DockerSessionCommandPlan::from_session_run_plan_with_environment(plan, environment);
        info!(
            session = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            image = %plan.runner().docker().image(),
            tty = plan.tty(),
            "launching Docker/OCI session runner"
        );

        let status = ProcessCommand::new(launch.program())
            .args(launch.args())
            .status()
            .map_err(|source| {
                RuntimeError::session_runner_launch(
                    self.kind().as_str(),
                    launch.program().to_owned(),
                    source,
                )
            })?;

        if status.success() {
            Ok(SessionRunOutcome::new(self.kind(), status.code()))
        } else {
            Err(RuntimeError::session_runner_exit(
                self.kind().as_str(),
                status.code(),
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCapturedRunOutcome {
    run: SessionRunOutcome,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DockerSessionOutputMode {
    Inherit,
    Capture,
}

impl DockerSessionRunner {
    fn run_with_options(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &DockerSessionCommandOptions,
        output_mode: DockerSessionOutputMode,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        let launch = DockerSessionCommandPlan::from_session_run_plan_with_environment_and_options(
            plan,
            environment,
            options,
        );
        info!(
            session = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            image = %plan.runner().docker().image(),
            tty = plan.tty(),
            guarded = true,
            "launching Docker/OCI session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());

        match output_mode {
            DockerSessionOutputMode::Inherit => {
                let status = command.status().map_err(|source| {
                    RuntimeError::session_runner_launch(
                        self.kind().as_str(),
                        launch.program().to_owned(),
                        source,
                    )
                })?;

                if status.success() {
                    Ok(SessionCapturedRunOutcome::new(
                        SessionRunOutcome::new(self.kind(), status.code()),
                        String::new(),
                        String::new(),
                    ))
                } else {
                    Err(RuntimeError::session_runner_exit(
                        self.kind().as_str(),
                        status.code(),
                    ))
                }
            }
            DockerSessionOutputMode::Capture => {
                let output = command.output().map_err(|source| {
                    RuntimeError::session_runner_launch(
                        self.kind().as_str(),
                        launch.program().to_owned(),
                        source,
                    )
                })?;
                Ok(SessionCapturedRunOutcome::new(
                    SessionRunOutcome::new(self.kind(), output.status.code()),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ))
            }
        }
    }
}

impl SessionRunnerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
        }
    }
}
