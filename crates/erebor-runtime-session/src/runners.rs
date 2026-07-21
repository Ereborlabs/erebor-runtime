use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use erebor_runtime_core::{
    ActiveSession, EndpointProjection, FilesystemProjection, ImmutableIdentity, OutputEndpoints,
    RunnerBinding, RunnerCapabilityDocument, RunnerId, RuntimeError, SafePathBinding, SafePathKind,
    SessionOwner, SessionSpec, WorkloadPrivilegePlan,
};
use snafu::{OptionExt, ResultExt};

pub(crate) mod docker;
pub(crate) mod linux;

pub(crate) use docker::DockerRunnerDriver;
pub(crate) use linux::LinuxRunnerDriver;

use crate::{
    error::session_manager::{PathResolutionSnafu, RunnerSnafu, RunnerUnavailableSnafu},
    SessionManagerError, SessionPathResolver,
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

pub struct RunnerAdmissionRequest<'a> {
    session_id: &'a str,
    owner: &'a SessionOwner,
    command: &'a [String],
    workspace: &'a Path,
    container_image_digest: Option<&'a str>,
    runtime_guard_host_path: &'a Path,
}

impl<'a> RunnerAdmissionRequest<'a> {
    #[must_use]
    pub const fn new(
        session_id: &'a str,
        owner: &'a SessionOwner,
        command: &'a [String],
        workspace: &'a Path,
        container_image_digest: Option<&'a str>,
        runtime_guard_host_path: &'a Path,
    ) -> Self {
        Self {
            session_id,
            owner,
            command,
            workspace,
            container_image_digest,
            runtime_guard_host_path,
        }
    }
}

pub struct RunnerAdmissionContext<'request, 'resolver> {
    request: RunnerAdmissionRequest<'request>,
    workspace: SafePathBinding,
    resolver: &'resolver dyn SessionPathResolver,
}

impl<'request, 'resolver> RunnerAdmissionContext<'request, 'resolver> {
    fn new(
        request: RunnerAdmissionRequest<'request>,
        resolver: &'resolver dyn SessionPathResolver,
    ) -> Result<Self, SessionManagerError> {
        let workspace = Self::resolve(
            &request,
            resolver,
            request.workspace,
            SafePathKind::Directory,
        )?;
        Ok(Self {
            request,
            workspace,
            resolver,
        })
    }

    fn resolve(
        request: &RunnerAdmissionRequest<'_>,
        resolver: &dyn SessionPathResolver,
        path: &Path,
        kind: SafePathKind,
    ) -> Result<SafePathBinding, SessionManagerError> {
        resolver
            .resolve(request.owner.uid(), request.owner.gid(), path, kind)
            .map(|resolved| resolved.binding().clone())
            .context(PathResolutionSnafu {
                uid: request.owner.uid(),
                gid: request.owner.gid(),
                path: path.to_path_buf(),
            })
    }

    pub fn resolve_path(
        &self,
        path: &Path,
        kind: SafePathKind,
    ) -> Result<SafePathBinding, SessionManagerError> {
        Self::resolve(&self.request, self.resolver, path, kind)
    }

    #[must_use]
    pub const fn session_id(&self) -> &str {
        self.request.session_id
    }

    #[must_use]
    pub const fn owner(&self) -> &SessionOwner {
        self.request.owner
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        self.request.command
    }

    #[must_use]
    pub const fn workspace(&self) -> &SafePathBinding {
        &self.workspace
    }

    #[must_use]
    pub const fn container_image_digest(&self) -> Option<&str> {
        self.request.container_image_digest
    }

    #[must_use]
    pub fn runtime_guard_host_path(&self) -> &Path {
        self.request.runtime_guard_host_path
    }

    pub fn invalid(&self, reason: impl Into<String>) -> SessionManagerError {
        SessionManagerError::InvalidOperation {
            session_id: self.session_id().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }
}

pub struct RunnerExecutionAdmission {
    pub workspace: SafePathBinding,
    pub workload_privileges: WorkloadPrivilegePlan,
    pub executable: Option<SafePathBinding>,
    pub container_image: Option<ImmutableIdentity>,
    pub filesystem_projections: Vec<FilesystemProjection>,
    pub endpoint_projections: Vec<EndpointProjection>,
}

pub trait RunnerDriver: Send + Sync {
    fn id(&self) -> &RunnerId;

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError>;

    fn admit(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
    ) -> Result<RunnerExecutionAdmission, SessionManagerError>;

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

    pub fn admit(
        &self,
        id: &RunnerId,
        request: RunnerAdmissionRequest<'_>,
        resolver: &dyn SessionPathResolver,
    ) -> Result<RunnerExecutionAdmission, SessionManagerError> {
        let context = RunnerAdmissionContext::new(request, resolver)?;
        self.get(id)?.admit(&context)
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
