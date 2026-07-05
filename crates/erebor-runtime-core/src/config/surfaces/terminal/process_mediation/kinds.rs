use serde::Deserialize;

use super::{
    ProcessMediationHandlerConfig, TerminalProcessMediationConfig,
    TerminalProcessMediationLayerConfig,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalProcessMediationMode {
    #[default]
    Shim,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessInterceptionDecision {
    Allow,
    Deny,
    #[serde(alias = "approval_required", alias = "require_verification")]
    RequireApproval,
    #[default]
    Mediate,
}

impl ProcessInterceptionDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
            Self::Mediate => "mediate",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationHandlerKind {
    ManagedBrowserCdp,
}

impl ProcessMediationHandlerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedBrowserCdp => "managed_browser_cdp",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationEndpointSource {
    #[default]
    RemoteDebuggingPort,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationReplacementSurface {
    #[default]
    BrowserCdp,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationPrivatePortStrategy {
    #[default]
    Ephemeral,
    RequestedPlusOffset,
}
pub type TerminalProcessInterceptionConfig = TerminalProcessMediationConfig;
pub type TerminalProcessInterceptionLayerConfig = TerminalProcessMediationLayerConfig;
pub type TerminalProcessInterceptionMode = TerminalProcessMediationMode;
pub type ProcessInterceptionHandlerConfig = ProcessMediationHandlerConfig;
pub type ProcessInterceptionHandlerKind = ProcessMediationHandlerKind;
