use std::process::Command as ProcessCommand;

use erebor_runtime_telemetry::info;
use snafu::ResultExt;

use crate::error::{SessionRunnerExitSnafu, SessionRunnerLaunchSnafu};
use crate::{
    LinuxHostSessionCommandOptions, LinuxHostSessionCommandPlan, RuntimeError, SessionAdoptPlan,
    SessionRunPlan, SessionRunnerKind,
};

use super::{
    ForegroundSessionRunner, LinuxHostTextBusyRetry, SessionCapturedRunOutcome, SessionRunOutcome,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionRunner;

impl LinuxHostSessionRunner {
    #[must_use]
    pub const fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::LinuxHost
    }
}

impl ForegroundSessionRunner for LinuxHostSessionRunner {
    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        self.run_with_options(
            plan,
            environment,
            &LinuxHostSessionCommandOptions::default(),
            LinuxHostSessionOutputMode::Inherit,
        )
        .map(|outcome| outcome.run)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxHostSessionOutputMode {
    Inherit,
    Capture,
}

impl LinuxHostSessionRunner {
    pub(super) fn run_with_options(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
        output_mode: LinuxHostSessionOutputMode,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        let launch =
            LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
                plan,
                environment,
                options,
            );
        info!(
            session_id = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            runner = %self.kind().as_str(),
            program = %launch.program(),
            tty = plan.tty(),
            "launching Linux host session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());
        for key in launch.removed_environment() {
            command.env_remove(key);
        }
        command.envs(launch.environment().iter().cloned());
        if let Some(current_dir) = launch.current_dir() {
            command.current_dir(current_dir);
        }

        match output_mode {
            LinuxHostSessionOutputMode::Inherit => {
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
            LinuxHostSessionOutputMode::Capture => {
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

    pub(super) fn adopt_with_options(
        &self,
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
        output_mode: LinuxHostSessionOutputMode,
    ) -> Result<SessionCapturedRunOutcome, RuntimeError> {
        let launch =
            LinuxHostSessionCommandPlan::from_session_adopt_plan_with_environment_and_options(
                plan,
                environment,
                options,
            );
        info!(
            session_id = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            runner = %self.kind().as_str(),
            pid = plan.pid(),
            program = %launch.program(),
            "adopting process into Linux host session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());
        for key in launch.removed_environment() {
            command.env_remove(key);
        }
        command.envs(launch.environment().iter().cloned());
        if let Some(current_dir) = launch.current_dir() {
            command.current_dir(current_dir);
        }

        match output_mode {
            LinuxHostSessionOutputMode::Inherit => {
                let status = command.status().context(SessionRunnerLaunchSnafu {
                    runner: self.kind().as_str().to_owned(),
                    program: launch.program().to_owned(),
                })?;

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
            LinuxHostSessionOutputMode::Capture => {
                let output = command.output().context(SessionRunnerLaunchSnafu {
                    runner: self.kind().as_str().to_owned(),
                    program: launch.program().to_owned(),
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
