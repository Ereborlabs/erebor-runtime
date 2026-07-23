use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use erebor_runtime_core::{
    ActiveSession, EndpointProjection, FilesystemProjection, ImmutableIdentity, OutputEndpoints,
    RunnerBinding, RunnerCapabilityDocument, RunnerId, RuntimeError, SafePathBinding, SafePathKind,
    ScriptInterpreterBinding, SessionOwner, SessionSpec, WorkloadPrivilegePlan,
};
use snafu::{OptionExt, ResultExt};

pub(crate) mod docker;
pub(crate) mod linux;

pub(crate) use docker::DockerRunnerDriver;
pub(crate) use linux::LinuxRunnerDriver;

use crate::{
    error::session_manager::{PathResolutionSnafu, RunnerSnafu, RunnerUnavailableSnafu},
    SessionManagerError, SessionPathResolver, SessionRuntime,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunnerInstallConfig {
    program_overrides: BTreeMap<String, PathBuf>,
    use_systemd_scope: bool,
}

impl RunnerInstallConfig {
    #[must_use]
    pub const fn new(
        program_overrides: BTreeMap<String, PathBuf>,
        use_systemd_scope: bool,
    ) -> Self {
        Self {
            program_overrides,
            use_systemd_scope,
        }
    }

    #[must_use]
    pub const fn use_systemd_scope(&self) -> bool {
        self.use_systemd_scope
    }

    pub(crate) fn program(&self, name: &str, default: &Path) -> PathBuf {
        self.program_overrides
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_path_buf())
    }
}

pub struct RunnerAdmissionRequest<'a> {
    session_id: &'a str,
    owner: &'a SessionOwner,
    command: &'a [String],
    executable_search_path: Option<&'a str>,
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
        executable_search_path: Option<&'a str>,
        workspace: &'a Path,
        container_image_digest: Option<&'a str>,
        runtime_guard_host_path: &'a Path,
    ) -> Self {
        Self {
            session_id,
            owner,
            command,
            executable_search_path,
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

    pub fn resolve_executable_prefix(
        &self,
        path: &Path,
        maximum_bytes: u64,
    ) -> Result<(SafePathBinding, Vec<u8>), SessionManagerError> {
        let resolved = self
            .resolver
            .resolve(
                self.request.owner.uid(),
                self.request.owner.gid(),
                path,
                SafePathKind::Executable,
            )
            .context(PathResolutionSnafu {
                uid: self.request.owner.uid(),
                gid: self.request.owner.gid(),
                path: path.to_path_buf(),
            })?;
        let binding = resolved.binding().clone();
        let mut descriptor = resolved.descriptor().try_clone().map_err(|error| {
            self.invalid(format!(
                "cloning the held executable descriptor `{}` failed: {error}",
                path.display()
            ))
        })?;
        let mut prefix = Vec::new();
        descriptor
            .by_ref()
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut prefix)
            .map_err(|error| {
                self.invalid(format!(
                    "reading the held executable descriptor `{}` failed: {error}",
                    path.display()
                ))
            })?;
        if prefix.len() as u64 > maximum_bytes {
            prefix.truncate(maximum_bytes as usize);
        }
        Ok((binding, prefix))
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
    pub const fn executable_search_path(&self) -> Option<&str> {
        self.request.executable_search_path
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
    pub script_interpreters: Vec<ScriptInterpreterBinding>,
    pub container_image: Option<ImmutableIdentity>,
    pub filesystem_projections: Vec<FilesystemProjection>,
    pub endpoint_projections: Vec<EndpointProjection>,
}

/// Transport-neutral availability around the exact capability document used at
/// admission. The document remains the sole capability model.
#[derive(Clone, Debug)]
pub struct RunnerCapabilityReport {
    document: RunnerCapabilityDocument,
    available: bool,
    unavailable_reason: Option<String>,
}

impl RunnerCapabilityReport {
    #[must_use]
    pub const fn document(&self) -> &RunnerCapabilityDocument {
        &self.document
    }

    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }

    #[must_use]
    pub fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }
}

/// The daemon-owned resource operations a runner can select while preparing a
/// session. It is deliberately not a controller protocol: it neither
/// interprets a runner's workload nor requires every runner to use the same
/// set of resources.
pub struct RunnerPreparation<'a> {
    runtime: &'a dyn SessionRuntime,
    recovering: bool,
}

impl<'a> RunnerPreparation<'a> {
    pub(crate) const fn new(runtime: &'a dyn SessionRuntime, recovering: bool) -> Self {
        Self {
            runtime,
            recovering,
        }
    }

    pub fn prepare_execution(
        &self,
        spec: &SessionSpec,
    ) -> Result<OutputEndpoints, SessionManagerError> {
        self.runtime.prepare_execution(spec, self.recovering)
    }

    pub fn start_runtime_guard(
        &self,
        spec: &SessionSpec,
        output: OutputEndpoints,
    ) -> Result<OutputEndpoints, SessionManagerError> {
        self.runtime
            .start_runtime_guard(spec, self.recovering)
            .map(|environment| output.with_runtime_environment(environment))
    }
}

pub trait RunnerDriver: Send + Sync {
    fn id(&self) -> &RunnerId;

    fn inspect(&self) -> Result<RunnerCapabilityDocument, RuntimeError>;

    fn capability_document(&self) -> Result<RunnerCapabilityDocument, RuntimeError>;

    fn admit(
        &self,
        context: &RunnerAdmissionContext<'_, '_>,
    ) -> Result<RunnerExecutionAdmission, SessionManagerError>;

    fn validate_admission(&self, spec: &SessionSpec) -> Result<(), RuntimeError>;

    fn prepare(
        &self,
        spec: &SessionSpec,
        resources: &RunnerPreparation<'_>,
    ) -> Result<OutputEndpoints, SessionManagerError>;

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
            Arc::new(LinuxRunnerDriver::from_install_config(&config).context(RunnerSnafu)?)
                as Arc<dyn RunnerDriver>,
            Arc::new(DockerRunnerDriver::from_install_config(&config).context(RunnerSnafu)?)
                as Arc<dyn RunnerDriver>,
        ]))
    }

    /// Compiles the Phase 3 daemon runner set. Docker remains available to
    /// earlier direct-test owners, but daemon admission deliberately exposes
    /// only Linux-host until the Phase 6 image contract is implemented.
    pub fn compiled_linux_host(config: RunnerInstallConfig) -> Result<Self, SessionManagerError> {
        Ok(Self::new([Arc::new(
            LinuxRunnerDriver::from_install_config(&config).context(RunnerSnafu)?,
        ) as Arc<dyn RunnerDriver>]))
    }

    pub fn inspect(&self, id: &RunnerId) -> Result<RunnerCapabilityDocument, SessionManagerError> {
        self.get(id)?.inspect().context(RunnerSnafu)
    }

    pub fn report(&self, id: &RunnerId) -> Result<RunnerCapabilityReport, SessionManagerError> {
        let runner = self.get(id)?;
        let document = runner.capability_document().context(RunnerSnafu)?;
        match runner.inspect() {
            Ok(inspected) if inspected == document => Ok(RunnerCapabilityReport {
                document,
                available: true,
                unavailable_reason: None,
            }),
            Ok(_) => Err(SessionManagerError::InvalidOperation {
                session_id: String::from("runner-capability"),
                reason: String::from("runner inspection returned a different capability document"),
                location: snafu::Location::default(),
            }),
            Err(error) => Ok(RunnerCapabilityReport {
                document,
                available: false,
                unavailable_reason: Some(error.to_string()),
            }),
        }
    }

    pub fn reports(&self) -> Result<Vec<RunnerCapabilityReport>, SessionManagerError> {
        self.runners.keys().map(|id| self.report(id)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{RunnerInstallConfig, RunnerRegistry};
    use erebor_runtime_core::RunnerId;

    #[test]
    fn phase_three_registry_excludes_docker() -> Result<(), Box<dyn std::error::Error>> {
        let registry = RunnerRegistry::compiled_linux_host(RunnerInstallConfig::default())?;
        assert!(registry.get(&RunnerId::new("linux-host")?).is_ok());
        assert!(registry.get(&RunnerId::new("docker")?).is_err());
        Ok(())
    }

    #[test]
    fn runner_reports_wrap_the_same_capability_document_used_by_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = RunnerRegistry::compiled_linux_host(RunnerInstallConfig::default())?;
        let reports = registry.reports()?;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].document().runner().as_str(), "linux-host");
        if !reports[0].available() {
            assert!(reports[0].unavailable_reason().is_some());
        }
        Ok(())
    }
}
