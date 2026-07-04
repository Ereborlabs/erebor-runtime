use erebor_runtime_core::{
    DockerSessionCommandOptions, LinuxHostSessionCommandOptions, SessionSurfaceSupervisor,
};

use crate::{
    interception_backend::SessionInterceptionBackendBundle,
    runtime_interception_broker::SessionInterceptionRegistration, SessionExecutionError,
};

#[derive(Default)]
pub(crate) struct SessionSideResources {
    environment: Vec<(String, String)>,
    docker_options: DockerSessionCommandOptions,
    linux_host_options: LinuxHostSessionCommandOptions,
    browser_cdp_endpoint: Option<String>,
    interception_registration: Option<SessionInterceptionRegistration>,
    interception_backend: Option<SessionInterceptionBackendBundle>,
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionSideResources {
    pub(crate) fn new(
        environment: Vec<(String, String)>,
        docker_options: DockerSessionCommandOptions,
        linux_host_options: LinuxHostSessionCommandOptions,
        browser_cdp_endpoint: Option<String>,
        interception_registration: Option<SessionInterceptionRegistration>,
        interception_backend: Option<SessionInterceptionBackendBundle>,
        supervisor: Option<SessionSurfaceSupervisor>,
    ) -> Self {
        Self {
            environment,
            docker_options,
            linux_host_options,
            browser_cdp_endpoint,
            interception_registration,
            interception_backend,
            _supervisor: supervisor,
        }
    }

    pub(crate) fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    pub(crate) fn docker_options(&self) -> &DockerSessionCommandOptions {
        &self.docker_options
    }

    pub(crate) fn linux_host_options(&self) -> &LinuxHostSessionCommandOptions {
        &self.linux_host_options
    }

    pub(crate) fn linux_host_adopt_options(
        &self,
        pid: i32,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        self.interception_backend.as_ref().map_or_else(
            || Ok(LinuxHostSessionCommandOptions::default()),
            |backend| {
                let mut options =
                    backend.linux_host_adopt_options(pid, self.browser_cdp_endpoint.as_deref())?;
                if let Some(interception_registration) = self.interception_registration.as_ref() {
                    for (key, value) in interception_registration.endpoint().environment() {
                        options = options.with_environment(key, value);
                    }
                }
                Ok(options)
            },
        )
    }
}
