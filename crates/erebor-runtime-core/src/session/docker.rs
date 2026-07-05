use std::process::Command as ProcessCommand;

use erebor_runtime_telemetry::info;
use snafu::ResultExt;

use crate::error::{SessionRunnerExitSnafu, SessionRunnerLaunchSnafu};
use crate::{
    DockerSessionCommandOptions, DockerSessionCommandPlan, RuntimeError, SessionRunPlan,
    SessionRunnerKind,
};

use super::{LinuxHostTextBusyRetry, SessionCapturedRunOutcome, SessionRunOutcome, SessionRunner};

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
            session_id = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            runner = %self.kind().as_str(),
            image = %plan.runner().docker().image(),
            tty = plan.tty(),
            "launching Docker/OCI session runner"
        );

        let status = ProcessCommand::new(launch.program())
            .args(launch.args())
            .status()
            .context(SessionRunnerLaunchSnafu {
                runner: self.kind().as_str().to_owned(),
                program: launch.program().to_owned(),
            })?;

        if status.success() {
            Ok(SessionRunOutcome::new(self.kind(), status.code()))
        } else {
            SessionRunnerExitSnafu {
                runner: self.kind().as_str().to_owned(),
                code: status.code(),
            }
            .fail()
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DockerSessionOutputMode {
    Inherit,
    Capture,
}

impl DockerSessionRunner {
    pub(super) fn run_with_options(
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
            session_id = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            runner = %self.kind().as_str(),
            image = %plan.runner().docker().image(),
            tty = plan.tty(),
            guarded = true,
            "launching Docker/OCI session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());

        match output_mode {
            DockerSessionOutputMode::Inherit => {
                let status = LinuxHostTextBusyRetry::run(|| command.status()).context(
                    SessionRunnerLaunchSnafu {
                        runner: self.kind().as_str().to_owned(),
                        program: launch.program().to_owned(),
                    },
                )?;

                if status.success() {
                    Ok(SessionCapturedRunOutcome::new(
                        SessionRunOutcome::new(self.kind(), status.code()),
                        String::new(),
                        String::new(),
                    ))
                } else {
                    SessionRunnerExitSnafu {
                        runner: self.kind().as_str().to_owned(),
                        code: status.code(),
                    }
                    .fail()
                }
            }
            DockerSessionOutputMode::Capture => {
                let output = LinuxHostTextBusyRetry::run(|| command.output()).context(
                    SessionRunnerLaunchSnafu {
                        runner: self.kind().as_str().to_owned(),
                        program: launch.program().to_owned(),
                    },
                )?;
                Ok(SessionCapturedRunOutcome::new(
                    SessionRunOutcome::new(self.kind(), output.status.code()),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ))
            }
        }
    }
}
