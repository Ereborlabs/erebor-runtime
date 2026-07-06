mod env;
mod guard_artifact;
mod inputs;
mod linux_ptrace;
mod path;
mod process_bundle;

use erebor_runtime_core::{
    DockerSessionCommandOptions, LinuxHostSessionCommandOptions, SessionInterceptionBackendKind,
    SessionInterceptionConfig,
};

use crate::{SessionExecutionError, SessionPlanContext, SessionStorage};

#[cfg(test)]
pub(crate) use env::process_interception_executable_env;
pub(crate) use inputs::{
    FileOperationInterceptionInput, ProcessExecInterceptionInput, ProcessExecMediationInput,
    ProcessExecMediationMode,
};

use linux_ptrace::{LinuxPtraceInterceptionBackendBundle, LinuxPtraceInterceptionOperations};

pub(crate) struct SessionInterceptionBackendBundle {
    backend: SessionInterceptionBackend,
}

enum SessionInterceptionBackend {
    LinuxPtrace(LinuxPtraceInterceptionBackendBundle),
}

impl SessionInterceptionBackendBundle {
    pub(crate) fn prepare(
        interception: &SessionInterceptionConfig,
        process_exec: Option<ProcessExecInterceptionInput<'_>>,
        file_operations: FileOperationInterceptionInput,
        plan: &impl SessionPlanContext,
        storage: Option<&SessionStorage>,
    ) -> Result<Option<Self>, SessionExecutionError> {
        let operations = LinuxPtraceInterceptionOperations::from_inputs(
            interception,
            process_exec.as_ref(),
            file_operations,
        );
        if !operations.any() {
            return Ok(None);
        }

        match interception.backend() {
            SessionInterceptionBackendKind::LinuxPtrace => {
                LinuxPtraceInterceptionBackendBundle::prepare(
                    process_exec,
                    operations,
                    plan,
                    storage,
                )
                .map(SessionInterceptionBackend::LinuxPtrace)
                .map(|backend| Self { backend })
                .map(Some)
            }
        }
    }

    pub(crate) fn backend_kind(&self) -> &'static str {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(_) => {
                SessionInterceptionBackendKind::LinuxPtrace.as_str()
            }
        }
    }

    pub(crate) fn docker_options(&self) -> DockerSessionCommandOptions {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => bundle.docker_options(),
        }
    }

    pub(crate) fn linux_host_options(
        &self,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => {
                bundle.linux_host_options(browser_cdp_endpoint)
            }
        }
    }

    pub(crate) fn linux_host_adopt_options(
        &self,
        pid: i32,
        browser_cdp_endpoint: Option<&str>,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        match &self.backend {
            SessionInterceptionBackend::LinuxPtrace(bundle) => {
                bundle.linux_host_adopt_options(pid, browser_cdp_endpoint)
            }
        }
    }
}
