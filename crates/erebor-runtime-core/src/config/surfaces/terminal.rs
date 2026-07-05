use std::path::PathBuf;

use serde::Deserialize;

mod process_mediation;

pub use process_mediation::{
    ProcessInterceptionDecision, ProcessInterceptionHandlerConfig, ProcessInterceptionHandlerKind,
    ProcessMediationCompatibilityConfig, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEndpointSource, ProcessMediationEnvironmentConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerConfig,
    ProcessMediationHandlerKind, ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationPrivateEndpointConfig,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementConfig, ProcessMediationReplacementLayerConfig,
    ProcessMediationReplacementSurface, ProcessMediationRequestedEndpointConfig,
    ProcessMediationRequestedEndpointLayerConfig, TerminalProcessInterceptionConfig,
    TerminalProcessInterceptionLayerConfig, TerminalProcessInterceptionMode,
    TerminalProcessMediationConfig, TerminalProcessMediationLayerConfig,
    TerminalProcessMediationMode,
};

use super::SurfacePolicyResolver;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalSurfaceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub policies: Vec<PathBuf>,
    #[serde(
        default,
        alias = "process_interception",
        alias = "browser_launch_mediation"
    )]
    pub process_mediation: TerminalProcessMediationLayerConfig,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalSurfaceConfig {
    tty: bool,
    policies: Vec<PathBuf>,
    process_mediation: TerminalProcessMediationConfig,
}

impl TerminalSurfaceConfig {
    #[must_use]
    pub const fn tty(&self) -> bool {
        self.tty
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn process_mediation(&self) -> &TerminalProcessMediationConfig {
        &self.process_mediation
    }

    #[must_use]
    pub const fn process_interception(&self) -> &TerminalProcessMediationConfig {
        &self.process_mediation
    }

    pub(in crate::config) fn from_layer(
        config: &TerminalSurfaceLayerConfig,
        default_policies: Vec<PathBuf>,
    ) -> Self {
        Self {
            tty: config.tty,
            policies: SurfacePolicyResolver::resolve(&config.policies, default_policies),
            process_mediation: config.process_mediation.clone().into(),
        }
    }
}
