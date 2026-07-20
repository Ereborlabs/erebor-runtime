use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command as ProcessCommand,
};

use erebor_runtime_telemetry::info;
use snafu::ResultExt;

use crate::error::{SessionRunnerExitSnafu, SessionRunnerLaunchSnafu};
use crate::{
    DockerSessionCommandOptions, DockerSessionCommandPlan, RuntimeError, SessionRunPlan,
    SessionRunnerKind,
};

use super::{
    ActiveSession, ActiveSessionSignalKind, DaemonFailureMode, ForegroundSessionRunner,
    LinuxHostTextBusyRetry, OutputEndpoints, RunnerCapabilityDocument, SessionCapturedRunOutcome,
    SessionHelperLaunchConfig, SessionRunOutcome, SessionRunner, SessionSpec,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerSessionRunner {
    helper: SessionHelperLaunchConfig,
}

impl DockerSessionRunner {
    #[must_use]
    pub const fn new(helper: SessionHelperLaunchConfig) -> Self {
        Self { helper }
    }

    #[must_use]
    pub const fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::Docker
    }
}

impl ForegroundSessionRunner for DockerSessionRunner {
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

impl SessionRunner for DockerSessionRunner {
    fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::Docker
    }

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError> {
        if !cfg!(target_os = "linux") {
            return crate::error::SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from("the Phase 2 Docker continuity helper requires Linux"),
            }
            .fail();
        }
        self.helper.inspect_runner(SessionRunnerKind::Docker)?;
        RunnerCapabilityDocument::new(
            SessionRunnerKind::Docker,
            "erebor-docker-cli",
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
                    String::from("image"),
                    String::from("local-content-digest-only"),
                ),
                (String::from("pull"), String::from("never")),
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
                    String::from("docker-user-ulimit-capdrop-v1"),
                ),
                (
                    String::from("umask"),
                    String::from("oci-runtime-default-0022"),
                ),
            ]),
        )
        .map_err(|error| crate::RuntimeError::SessionRunnerUnavailable {
            runner: SessionRunnerKind::Docker.as_str().to_owned(),
            reason: error.to_string(),
            location: snafu::Location::default(),
        })
    }

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError> {
        if spec.workload_privileges().umask() != 0o022 {
            return crate::error::SessionRunnerUnavailableSnafu {
                runner: SessionRunnerKind::Docker.as_str().to_owned(),
                reason: String::from("Docker admission requires the pinned OCI runtime umask 0022"),
            }
            .fail();
        }
        self.helper.validate_docker_image(spec)
    }

    fn start(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        self.helper
            .start(SessionRunnerKind::Docker, spec, output, capability)
    }

    fn recover(
        &self,
        spec: &SessionSpec,
        binding: &crate::RunnerBinding,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError> {
        let capability = self.inspect()?;
        self.helper
            .recover(SessionRunnerKind::Docker, spec, binding, output, capability)
    }

    fn remove(
        &self,
        _spec: &SessionSpec,
        binding: Option<&crate::RunnerBinding>,
    ) -> Result<(), RuntimeError> {
        self.helper.remove(SessionRunnerKind::Docker, binding)
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
