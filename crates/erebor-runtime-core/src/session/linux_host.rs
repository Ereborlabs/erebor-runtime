use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command as ProcessCommand,
};

use erebor_runtime_telemetry::info;
use snafu::ResultExt;

use crate::error::{SessionRunnerExitSnafu, SessionRunnerLaunchSnafu};
use crate::{
    LinuxHostSessionCommandOptions, LinuxHostSessionCommandPlan, RuntimeError, SessionAdoptPlan,
    SessionRunPlan, SessionRunnerKind,
};

use super::{
    ActiveSession, ActiveSessionSignalKind, DaemonFailureMode, ForegroundSessionRunner,
    LinuxHostTextBusyRetry, OutputEndpoints, RunnerCapabilityDocument, SessionCapturedRunOutcome,
    SessionHelperLaunchConfig, SessionRunOutcome, SessionRunner, SessionSpec,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionRunner {
    helper: SessionHelperLaunchConfig,
}

impl LinuxHostSessionRunner {
    #[must_use]
    pub const fn new(helper: SessionHelperLaunchConfig) -> Self {
        Self { helper }
    }

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

impl SessionRunner for LinuxHostSessionRunner {
    fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::LinuxHost
    }

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return crate::error::SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::LinuxHost.as_str().to_owned(),
                reason: String::from(
                    "physical Linux interception is supported only on x86_64 Linux",
                ),
            }
            .fail();
        }
        self.helper.inspect_runner(SessionRunnerKind::LinuxHost)?;
        RunnerCapabilityDocument::new(
            SessionRunnerKind::LinuxHost,
            "erebor-linux-host",
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
                    String::from("helper"),
                    String::from("inherited-control-lease-v1"),
                ),
                (
                    String::from("containment"),
                    if self.helper.uses_systemd_scope() {
                        String::from("systemd-session-slice-v1")
                    } else {
                        String::from("direct-helper-v1")
                    },
                ),
                (
                    String::from("privilege-plan"),
                    String::from("process-guard-rlimit-umask-groups-v1"),
                ),
            ]),
        )
        .map_err(|error| crate::RuntimeError::SessionRunnerUnavailable {
            runner: SessionRunnerKind::LinuxHost.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })
    }

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError> {
        if spec.executable().is_some()
            && spec.container_image().is_none()
            && spec.workload_privileges().umask() <= 0o777
        {
            Ok(())
        } else {
            crate::error::SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::LinuxHost.as_str().to_owned(),
                reason: String::from(
                    "Linux-host admission requires an executable and forbids a container image",
                ),
            }
            .fail()
        }
    }

    fn start(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        self.helper
            .start(SessionRunnerKind::LinuxHost, spec, output, capability)
    }

    fn recover(
        &self,
        spec: &SessionSpec,
        binding: &crate::RunnerBinding,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        self.helper.recover(
            SessionRunnerKind::LinuxHost,
            spec,
            binding,
            output,
            capability,
        )
    }

    fn remove(
        &self,
        _spec: &SessionSpec,
        binding: Option<&crate::RunnerBinding>,
    ) -> Result<(), RuntimeError> {
        self.helper.remove(SessionRunnerKind::LinuxHost, binding)
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
