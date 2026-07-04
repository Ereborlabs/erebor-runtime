use std::{io, process::Command as ProcessCommand, thread, time::Duration};

use snafu::ResultExt;
use tracing::info;

use crate::error::{
    SessionRunnerExitSnafu, SessionRunnerLaunchSnafu, UnsupportedSessionRunnerOperationSnafu,
};
use crate::{
    DockerSessionCommandOptions, DockerSessionCommandPlan, LinuxHostSessionCommandOptions,
    LinuxHostSessionCommandPlan, RuntimeError, SessionAdoptPlan, SessionRunPlan, SessionRunnerKind,
};

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
                let status = retry_linux_host_text_busy(|| command.status()).context(
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
                let output = retry_linux_host_text_busy(|| command.output()).context(
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionRunner;

impl SessionRunner for LinuxHostSessionRunner {
    fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::LinuxHost
    }

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
enum LinuxHostSessionOutputMode {
    Inherit,
    Capture,
}

impl LinuxHostSessionRunner {
    fn run_with_options(
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
            session = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            program = %launch.program(),
            tty = plan.tty(),
            "launching Linux host session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());
        command.envs(launch.environment().iter().cloned());
        if let Some(current_dir) = launch.current_dir() {
            command.current_dir(current_dir);
        }

        match output_mode {
            LinuxHostSessionOutputMode::Inherit => {
                let status = retry_linux_host_text_busy(|| command.status()).context(
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
                let output = retry_linux_host_text_busy(|| command.output()).context(
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

    fn adopt_with_options(
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
            session = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            pid = plan.pid(),
            program = %launch.program(),
            "adopting process into Linux host session runner"
        );

        let mut command = ProcessCommand::new(launch.program());
        command.args(launch.args());
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

fn retry_linux_host_text_busy<T>(
    mut launch: impl FnMut() -> Result<T, io::Error>,
) -> Result<T, io::Error> {
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

impl SessionRunnerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::LinuxHost => "linux-host",
        }
    }
}
