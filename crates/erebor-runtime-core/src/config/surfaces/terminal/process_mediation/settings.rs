use std::net::{IpAddr, Ipv4Addr};

use serde::Deserialize;
use snafu::ensure;

use crate::error::InvalidProcessMediationConfigSnafu;
use crate::RuntimeConfigError;

use super::kinds::{
    ProcessMediationEndpointSource, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementSurface,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationMatcherLayerConfig {
    #[serde(default)]
    pub executables: Vec<String>,
    #[serde(default)]
    pub required_args: Vec<String>,
    #[serde(default)]
    pub require_remote_debugging_port: bool,
}

impl ProcessMediationMatcherLayerConfig {
    pub(in crate::config::surfaces::terminal::process_mediation) fn validate(
        &self,
        handler_id: &str,
    ) -> Result<(), RuntimeConfigError> {
        ensure!(
            !self.executables.is_empty(),
            InvalidProcessMediationConfigSnafu {
                reason: format!(
                    "handler `{handler_id}` must include at least one executable matcher"
                )
            }
        );

        ensure!(
            !self
                .executables
                .iter()
                .any(|executable| executable.trim().is_empty()),
            InvalidProcessMediationConfigSnafu {
                reason: format!("handler `{handler_id}` executable matchers cannot be empty")
            }
        );

        ensure!(
            !self
                .required_args
                .iter()
                .any(|argument| argument.trim().is_empty()),
            InvalidProcessMediationConfigSnafu {
                reason: format!("handler `{handler_id}` required args cannot be empty")
            }
        );

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct ProcessMediationRequestedEndpointLayerConfig {
    pub source: ProcessMediationEndpointSource,
    pub bind: IpAddr,
    pub allowed_ports: Vec<u16>,
}

impl Default for ProcessMediationRequestedEndpointLayerConfig {
    fn default() -> Self {
        Self {
            source: ProcessMediationEndpointSource::default(),
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allowed_ports: Vec::new(),
        }
    }
}

impl ProcessMediationRequestedEndpointLayerConfig {
    pub(in crate::config::surfaces::terminal::process_mediation) fn validate(
        &self,
        handler_id: &str,
    ) -> Result<(), RuntimeConfigError> {
        ensure!(
            self.bind.is_loopback(),
            InvalidProcessMediationConfigSnafu {
                reason: format!("handler `{handler_id}` requested endpoint bind must be loopback")
            }
        );

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct ProcessMediationReplacementLayerConfig {
    pub surface: ProcessMediationReplacementSurface,
    pub private_endpoint: ProcessMediationPrivateEndpointLayerConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct ProcessMediationPrivateEndpointLayerConfig {
    pub port_strategy: ProcessMediationPrivatePortStrategy,
    pub port_offset: u16,
}

impl Default for ProcessMediationPrivateEndpointLayerConfig {
    fn default() -> Self {
        Self {
            port_strategy: ProcessMediationPrivatePortStrategy::default(),
            port_offset: 1,
        }
    }
}

impl ProcessMediationPrivateEndpointLayerConfig {
    pub(in crate::config::surfaces::terminal::process_mediation) fn validate(
        &self,
        handler_id: &str,
    ) -> Result<(), RuntimeConfigError> {
        ensure!(
            !((self.port_strategy == ProcessMediationPrivatePortStrategy::RequestedPlusOffset)
                && self.port_offset == 0),
            InvalidProcessMediationConfigSnafu {
                reason: format!(
                    "handler `{handler_id}` private endpoint port_offset must be positive"
                )
            }
        );

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct ProcessMediationEnvironmentLayerConfig {
    pub prepend_path: bool,
    pub executable_env: Vec<String>,
}

impl Default for ProcessMediationEnvironmentLayerConfig {
    fn default() -> Self {
        Self {
            prepend_path: true,
            executable_env: Vec::new(),
        }
    }
}

impl ProcessMediationEnvironmentLayerConfig {
    pub(in crate::config::surfaces::terminal::process_mediation) fn validate(
        &self,
        handler_id: &str,
    ) -> Result<(), RuntimeConfigError> {
        ensure!(
            !self
                .executable_env
                .iter()
                .any(|variable| variable.trim().is_empty() || variable.contains('=')),
            InvalidProcessMediationConfigSnafu {
                reason: format!(
                    "handler `{handler_id}` executable env names cannot be empty or contain `=`"
                )
            }
        );

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct ProcessMediationCompatibilityLayerConfig {
    pub print_devtools_listening_line: bool,
    pub keepalive: bool,
}

impl Default for ProcessMediationCompatibilityLayerConfig {
    fn default() -> Self {
        Self {
            print_devtools_listening_line: true,
            keepalive: true,
        }
    }
}
