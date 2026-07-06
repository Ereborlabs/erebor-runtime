use std::path::{Path, PathBuf};

use serde::Deserialize;
use snafu::ensure;

mod browser;
mod filesystem;
mod start_plan;
mod terminal;

pub use browser::{
    BrowserCdpSurfaceConfig, BrowserCdpSurfaceLayerConfig, BrowserLaunchConfig,
    BrowserLaunchLayerConfig,
};
pub use filesystem::{
    FilesystemBackendConfig, FilesystemBackendKind, FilesystemBackendLayerConfig,
    FilesystemPreimageBackendKind, FilesystemRevertConfig, FilesystemRevertLayerConfig,
    FilesystemSurfaceConfig, FilesystemSurfaceLayerConfig, FilesystemVolumeConfig,
    FilesystemVolumeLayerConfig, FilesystemVolumeMode,
};
pub use start_plan::SessionSurfaceStartPlan;
pub use terminal::{
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
    TerminalProcessMediationMode, TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
};

use crate::error::EmptyPolicyPathSnafu;
use crate::RuntimeConfigError;

use super::SessionInterceptionOperation;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionSurfaceLayers {
    #[serde(default)]
    pub browser_cdp: BrowserCdpSurfaceLayerConfig,
    #[serde(default)]
    pub mcp: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub terminal: TerminalSurfaceLayerConfig,
    #[serde(default)]
    pub filesystem: FilesystemSurfaceLayerConfig,
    #[serde(default)]
    pub network: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub saas: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub desktop: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub internal_system: SessionSurfaceToggleConfig,
}

impl SessionSurfaceLayers {
    #[must_use]
    pub fn enabled_surfaces(&self) -> Vec<SessionSurfaceKind> {
        let candidates = [
            (SessionSurfaceKind::BrowserCdp, self.browser_cdp.enabled),
            (SessionSurfaceKind::Mcp, self.mcp.enabled),
            (SessionSurfaceKind::Terminal, self.terminal.enabled),
            (SessionSurfaceKind::Filesystem, self.filesystem.enabled),
            (SessionSurfaceKind::Network, self.network.enabled),
            (SessionSurfaceKind::Saas, self.saas.enabled),
            (SessionSurfaceKind::Desktop, self.desktop.enabled),
            (
                SessionSurfaceKind::InternalSystem,
                self.internal_system.enabled,
            ),
        ];

        candidates
            .into_iter()
            .filter_map(|(layer, enabled)| enabled.then_some(layer))
            .collect()
    }

    pub(in crate::config) fn operation_surface_enabled(
        &self,
        operation: SessionInterceptionOperation,
    ) -> bool {
        match operation {
            SessionInterceptionOperation::ProcessExec => self.terminal.enabled,
            SessionInterceptionOperation::FileOpen
            | SessionInterceptionOperation::FileRead
            | SessionInterceptionOperation::FileMutation => self.filesystem.enabled,
            SessionInterceptionOperation::SocketConnect => self.network.enabled,
        }
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionSurfaceToggleConfig {
    #[serde(default)]
    pub enabled: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSurfaceKind {
    BrowserCdp,
    Mcp,
    Terminal,
    Filesystem,
    Network,
    Saas,
    Desktop,
    InternalSystem,
}

impl SessionSurfaceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserCdp => "browser_cdp",
            Self::Mcp => "mcp",
            Self::Terminal => "terminal",
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Saas => "saas",
            Self::Desktop => "desktop",
            Self::InternalSystem => "internal_system",
        }
    }
}

pub struct PolicyPathValidator;

impl PolicyPathValidator {
    pub fn validate(path: &Path) -> Result<(), RuntimeConfigError> {
        ensure!(!path.as_os_str().is_empty(), EmptyPolicyPathSnafu);
        Ok(())
    }
}

pub(in crate::config) struct SurfacePolicyResolver;

impl SurfacePolicyResolver {
    pub(in crate::config) fn resolve(
        surface_policies: &[PathBuf],
        default_policies: Vec<PathBuf>,
    ) -> Vec<PathBuf> {
        if surface_policies.is_empty() {
            default_policies
        } else {
            surface_policies.to_vec()
        }
    }
}
