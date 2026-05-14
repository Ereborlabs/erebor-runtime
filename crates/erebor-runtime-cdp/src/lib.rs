//! Browser/CDP enforcement surface contracts for erebor-runtime.

mod error;
mod message;
mod proxy;
mod server;

pub use error::CdpError;
pub use message::{
    enforce_cdp_message, observe_cdp_message, parse_cdp_message, CdpEnforcementAction, CdpMessage,
    CdpSessionContext,
};
pub use proxy::{proxy_cdp_message, CdpBackend, CdpBackendResponse, CdpProxyAction};
pub use server::{CdpProxyServer, CdpProxyServerConfig};

use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

pub const GOVERNED_CDP_METHODS: &[&str] = &[
    "Runtime.evaluate",
    "Runtime.callFunctionOn",
    "Input.dispatchMouseEvent",
    "Input.dispatchKeyEvent",
    "Page.navigate",
    "Fetch.continueRequest",
];

pub const CONTEXT_CDP_METHODS: &[&str] = &[
    "Fetch.requestPaused",
    "Network.requestWillBeSent",
    "Network.responseReceived",
    "Network.loadingFailed",
];

#[must_use]
pub fn is_governed_method(method: &str) -> bool {
    GOVERNED_CDP_METHODS.contains(&method)
}

#[must_use]
pub fn is_context_method(method: &str) -> bool {
    CONTEXT_CDP_METHODS.contains(&method)
}

#[must_use]
pub fn classify_cdp_method(method: &str) -> Option<CdpCommandClassification> {
    let (role, action, risk_level) = match method {
        "Runtime.evaluate" | "Runtime.callFunctionOn" => (
            CdpMethodRole::GovernedCommand,
            ActionKind::BrowserScriptEval,
            RiskLevel::High,
        ),
        "Input.dispatchMouseEvent" => (
            CdpMethodRole::GovernedCommand,
            ActionKind::BrowserClick,
            RiskLevel::Medium,
        ),
        "Input.dispatchKeyEvent" => (
            CdpMethodRole::GovernedCommand,
            ActionKind::BrowserInput,
            RiskLevel::Medium,
        ),
        "Page.navigate" => (
            CdpMethodRole::GovernedCommand,
            ActionKind::BrowserNavigate,
            RiskLevel::Low,
        ),
        "Fetch.continueRequest" => (
            CdpMethodRole::GovernedCommand,
            ActionKind::NetworkRequest,
            RiskLevel::Medium,
        ),
        "Fetch.requestPaused" => (
            CdpMethodRole::ContextEvent,
            ActionKind::NetworkRequest,
            RiskLevel::Medium,
        ),
        "Network.requestWillBeSent" | "Network.responseReceived" | "Network.loadingFailed" => (
            CdpMethodRole::ContextEvent,
            ActionKind::NetworkRequest,
            RiskLevel::Low,
        ),
        _ => return None,
    };

    Some(CdpCommandClassification {
        role,
        surface: ExecutionSurface::BrowserCdp,
        action,
        risk_level,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdpCommandClassification {
    pub role: CdpMethodRole,
    pub surface: ExecutionSurface,
    pub action: ActionKind,
    pub risk_level: RiskLevel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CdpMethodRole {
    GovernedCommand,
    ContextEvent,
}
