use std::process::Command as ProcessCommand;

use tracing::info;

use crate::{DockerSessionCommandPlan, RuntimeError, SessionRunPlan, SessionRunnerKind};

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

impl SessionRunnerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
        }
    }
}
