use std::net::IpAddr;

use super::kinds::{
    ProcessMediationEndpointSource, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementSurface,
};
use super::settings::{
    ProcessMediationCompatibilityLayerConfig, ProcessMediationEnvironmentLayerConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationPrivateEndpointLayerConfig,
    ProcessMediationReplacementLayerConfig, ProcessMediationRequestedEndpointLayerConfig,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationMatcherConfig {
    executables: Vec<String>,
    required_args: Vec<String>,
    require_remote_debugging_port: bool,
}

impl ProcessMediationMatcherConfig {
    #[must_use]
    pub fn executables(&self) -> &[String] {
        &self.executables
    }

    #[must_use]
    pub fn required_args(&self) -> &[String] {
        &self.required_args
    }

    #[must_use]
    pub const fn require_remote_debugging_port(&self) -> bool {
        self.require_remote_debugging_port
    }
}

impl From<ProcessMediationMatcherLayerConfig> for ProcessMediationMatcherConfig {
    fn from(config: ProcessMediationMatcherLayerConfig) -> Self {
        Self {
            executables: config.executables,
            required_args: config.required_args,
            require_remote_debugging_port: config.require_remote_debugging_port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationRequestedEndpointConfig {
    source: ProcessMediationEndpointSource,
    bind: IpAddr,
    allowed_ports: Vec<u16>,
}

impl ProcessMediationRequestedEndpointConfig {
    #[must_use]
    pub const fn source(&self) -> ProcessMediationEndpointSource {
        self.source
    }

    #[must_use]
    pub const fn bind(&self) -> IpAddr {
        self.bind
    }

    #[must_use]
    pub fn allowed_ports(&self) -> &[u16] {
        &self.allowed_ports
    }
}

impl From<ProcessMediationRequestedEndpointLayerConfig>
    for ProcessMediationRequestedEndpointConfig
{
    fn from(config: ProcessMediationRequestedEndpointLayerConfig) -> Self {
        Self {
            source: config.source,
            bind: config.bind,
            allowed_ports: config.allowed_ports,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMediationReplacementConfig {
    surface: ProcessMediationReplacementSurface,
    private_endpoint: ProcessMediationPrivateEndpointConfig,
}

impl ProcessMediationReplacementConfig {
    #[must_use]
    pub const fn surface(&self) -> ProcessMediationReplacementSurface {
        self.surface
    }

    #[must_use]
    pub const fn private_endpoint(&self) -> &ProcessMediationPrivateEndpointConfig {
        &self.private_endpoint
    }
}

impl From<ProcessMediationReplacementLayerConfig> for ProcessMediationReplacementConfig {
    fn from(config: ProcessMediationReplacementLayerConfig) -> Self {
        Self {
            surface: config.surface,
            private_endpoint: config.private_endpoint.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMediationPrivateEndpointConfig {
    port_strategy: ProcessMediationPrivatePortStrategy,
    port_offset: u16,
}

impl Default for ProcessMediationPrivateEndpointConfig {
    fn default() -> Self {
        Self {
            port_strategy: ProcessMediationPrivatePortStrategy::default(),
            port_offset: 1,
        }
    }
}

impl ProcessMediationPrivateEndpointConfig {
    #[must_use]
    pub const fn port_strategy(&self) -> ProcessMediationPrivatePortStrategy {
        self.port_strategy
    }

    #[must_use]
    pub const fn port_offset(&self) -> u16 {
        self.port_offset
    }
}

impl From<ProcessMediationPrivateEndpointLayerConfig> for ProcessMediationPrivateEndpointConfig {
    fn from(config: ProcessMediationPrivateEndpointLayerConfig) -> Self {
        Self {
            port_strategy: config.port_strategy,
            port_offset: config.port_offset,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationEnvironmentConfig {
    prepend_path: bool,
    executable_env: Vec<String>,
}

impl ProcessMediationEnvironmentConfig {
    #[must_use]
    pub const fn prepend_path(&self) -> bool {
        self.prepend_path
    }

    #[must_use]
    pub fn executable_env(&self) -> &[String] {
        &self.executable_env
    }
}

impl From<ProcessMediationEnvironmentLayerConfig> for ProcessMediationEnvironmentConfig {
    fn from(config: ProcessMediationEnvironmentLayerConfig) -> Self {
        Self {
            prepend_path: config.prepend_path,
            executable_env: config.executable_env,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMediationCompatibilityConfig {
    print_devtools_listening_line: bool,
    keepalive: bool,
}

impl ProcessMediationCompatibilityConfig {
    #[must_use]
    pub const fn print_devtools_listening_line(&self) -> bool {
        self.print_devtools_listening_line
    }

    #[must_use]
    pub const fn keepalive(&self) -> bool {
        self.keepalive
    }
}

impl From<ProcessMediationCompatibilityLayerConfig> for ProcessMediationCompatibilityConfig {
    fn from(config: ProcessMediationCompatibilityLayerConfig) -> Self {
        Self {
            print_devtools_listening_line: config.print_devtools_listening_line,
            keepalive: config.keepalive,
        }
    }
}
