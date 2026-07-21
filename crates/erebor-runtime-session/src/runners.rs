use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use erebor_runtime_core::{
    ActiveSession, OutputEndpoints, RunnerBinding, RunnerCapabilityDocument, RunnerId,
    RuntimeError, SessionSpec,
};
use snafu::{OptionExt, ResultExt};

pub(crate) mod docker;
pub(crate) mod linux;

pub(crate) use docker::DockerRunnerDriver;
pub(crate) use linux::LinuxRunnerDriver;

use crate::{
    error::session_manager::{RunnerSnafu, RunnerUnavailableSnafu},
    SessionManagerError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerInstallConfig {
    linux_controller_path: PathBuf,
    docker_controller_path: PathBuf,
    process_guard_path: PathBuf,
    docker_path: PathBuf,
    systemd_run_path: PathBuf,
    use_systemd_scope: bool,
}

impl Default for RunnerInstallConfig {
    fn default() -> Self {
        Self {
            linux_controller_path: PathBuf::from(
                "/usr/libexec/erebor/erebor-linux-session-controller",
            ),
            docker_controller_path: PathBuf::from(
                "/usr/libexec/erebor/erebor-docker-session-controller",
            ),
            process_guard_path: PathBuf::from("/usr/libexec/erebor/erebor-linux-process-guard"),
            docker_path: PathBuf::from("/usr/bin/docker"),
            systemd_run_path: PathBuf::from("/usr/bin/systemd-run"),
            use_systemd_scope: true,
        }
    }
}

impl RunnerInstallConfig {
    #[must_use]
    pub fn new(
        linux_controller_path: PathBuf,
        docker_controller_path: PathBuf,
        process_guard_path: PathBuf,
        docker_path: PathBuf,
        systemd_run_path: PathBuf,
        use_systemd_scope: bool,
    ) -> Self {
        Self {
            linux_controller_path,
            docker_controller_path,
            process_guard_path,
            docker_path,
            systemd_run_path,
            use_systemd_scope,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerAdmissionProfile {
    executable_required: bool,
    workload_umask: u32,
    project_runtime_guard: bool,
}

impl RunnerAdmissionProfile {
    #[must_use]
    pub const fn new(
        executable_required: bool,
        workload_umask: u32,
        project_runtime_guard: bool,
    ) -> Self {
        Self {
            executable_required,
            workload_umask,
            project_runtime_guard,
        }
    }

    #[must_use]
    pub const fn executable_required(self) -> bool {
        self.executable_required
    }

    #[must_use]
    pub const fn workload_umask(self) -> u32 {
        self.workload_umask
    }

    #[must_use]
    pub const fn project_runtime_guard(self) -> bool {
        self.project_runtime_guard
    }
}

pub trait RunnerDriver: Send + Sync {
    fn id(&self) -> &RunnerId;

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError>;

    fn admission_profile(&self) -> RunnerAdmissionProfile;

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError>;

    fn start(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError>;

    fn recover(
        &self,
        spec: &SessionSpec,
        binding: &RunnerBinding,
        output: &OutputEndpoints,
    ) -> Result<Box<dyn ActiveSession>, RuntimeError>;

    fn remove(
        &self,
        spec: &SessionSpec,
        binding: Option<&RunnerBinding>,
    ) -> Result<(), RuntimeError>;
}

pub struct RunnerRegistry {
    runners: BTreeMap<RunnerId, Arc<dyn RunnerDriver>>,
}

impl RunnerRegistry {
    #[must_use]
    pub fn new(runners: impl IntoIterator<Item = Arc<dyn RunnerDriver>>) -> Self {
        Self {
            runners: runners
                .into_iter()
                .map(|runner| (runner.id().clone(), runner))
                .collect(),
        }
    }

    pub fn get(&self, id: &RunnerId) -> Result<&Arc<dyn RunnerDriver>, SessionManagerError> {
        self.runners.get(id).context(RunnerUnavailableSnafu {
            runner: id.as_str().to_owned(),
        })
    }

    pub fn compiled(config: RunnerInstallConfig) -> Result<Self, SessionManagerError> {
        Ok(Self::new([
            Arc::new(
                LinuxRunnerDriver::new(
                    config.linux_controller_path,
                    config.process_guard_path,
                    config.systemd_run_path.clone(),
                    config.use_systemd_scope,
                )
                .context(RunnerSnafu)?,
            ) as Arc<dyn RunnerDriver>,
            Arc::new(
                DockerRunnerDriver::new(
                    config.docker_controller_path,
                    config.docker_path,
                    config.systemd_run_path,
                    config.use_systemd_scope,
                )
                .context(RunnerSnafu)?,
            ) as Arc<dyn RunnerDriver>,
        ]))
    }

    pub fn inspect(&self, id: &RunnerId) -> Result<RunnerCapabilityDocument, SessionManagerError> {
        self.get(id)?.inspect().context(RunnerSnafu)
    }
}
