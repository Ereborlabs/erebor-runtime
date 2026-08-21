use std::path::PathBuf;

use erebor_runtime_core::{
    DockerSessionCommandOptions, LinuxHostSessionCommandOptions, SessionSurfaceSupervisor,
};

use crate::SessionExecutionError;

#[derive(Default)]
pub(crate) struct SessionSideResources {
    environment: Vec<(String, String)>,
    docker_options: DockerSessionCommandOptions,
    linux_host_options: LinuxHostSessionCommandOptions,
    _lifetime: SessionResourceLifetime,
}

#[derive(Default)]
pub(crate) struct SessionResourceLifetime {
    _supervisor: Option<SessionSurfaceSupervisor>,
}

impl SessionResourceLifetime {
    pub(crate) const fn new(supervisor: Option<SessionSurfaceSupervisor>) -> Self {
        Self {
            _supervisor: supervisor,
        }
    }
}

impl SessionSideResources {
    pub(crate) fn new(
        environment: Vec<(String, String)>,
        docker_options: DockerSessionCommandOptions,
        linux_host_options: LinuxHostSessionCommandOptions,
        lifetime: SessionResourceLifetime,
    ) -> Self {
        Self {
            environment,
            docker_options,
            linux_host_options,
            _lifetime: lifetime,
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
        _pid: i32,
    ) -> Result<LinuxHostSessionCommandOptions, SessionExecutionError> {
        Ok(LinuxHostSessionCommandOptions::default())
    }
}
