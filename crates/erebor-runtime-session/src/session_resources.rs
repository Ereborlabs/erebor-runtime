use std::path::PathBuf;

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
    lifetime: SessionResourceLifetime,
}

#[derive(Default)]
pub(crate) struct SessionResourceLifetime {
    interception_registration: Option<SessionInterceptionRegistration>,
    interception_backend: Option<SessionInterceptionBackendBundle>,
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionResourceLifetime {
    pub(crate) const fn new(
        interception_registration: Option<SessionInterceptionRegistration>,
        interception_backend: Option<SessionInterceptionBackendBundle>,
        supervisor: Option<SessionSurfaceSupervisor>,
    ) -> Self {
        Self {
            interception_registration,
            interception_backend,
            _supervisor: supervisor,
        }
    }
}

impl SessionSideResources {
    pub(crate) fn new(
        environment: Vec<(String, String)>,
        docker_options: DockerSessionCommandOptions,
        linux_host_options: LinuxHostSessionCommandOptions,
        browser_cdp_endpoint: Option<String>,
        lifetime: SessionResourceLifetime,
    ) -> Self {
        Self {
            environment,
            docker_options,
            linux_host_options,
            browser_cdp_endpoint,
            lifetime,
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

    pub(crate) fn add_linux_host_outer_wrapper(&mut self, wrapper: PathBuf) {
        self.linux_host_options.add_outer_wrapper_program(wrapper);
    }

    pub(crate) fn linux_host_adopt_options(
        &self,
        pid: i32,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        self.lifetime.interception_backend.as_ref().map_or_else(
            || Ok(LinuxHostSessionCommandOptions::default()),
            |backend| {
                let mut options =
                    backend.linux_host_adopt_options(pid, self.browser_cdp_endpoint.as_deref())?;
                if let Some(interception_registration) =
                    self.lifetime.interception_registration.as_ref()
                {
                    for (key, value) in interception_registration.endpoint().environment() {
                        options.add_environment(key, value);
                    }
                }
                Ok(options)
            },
        )
    }
}
