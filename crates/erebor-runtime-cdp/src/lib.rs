//! Browser/CDP enforcement surface contracts for erebor-runtime.

mod error;
mod message;
mod proxy;

pub use error::CdpError;
pub use message::{
    enforce_cdp_message, parse_cdp_message, CdpEnforcementAction, CdpMessage, CdpSessionContext,
};
pub use proxy::{proxy_cdp_message, CdpBackend, CdpBackendResponse, CdpProxyAction};

use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

pub const GOVERNED_CDP_METHODS: &[&str] = &[
    "Runtime.evaluate",
    "Runtime.callFunctionOn",
    "Input.dispatchMouseEvent",
    "Input.dispatchKeyEvent",
    "Page.navigate",
    "Fetch.continueRequest",
];

#[must_use]
pub fn is_governed_method(method: &str) -> bool {
    GOVERNED_CDP_METHODS.contains(&method)
}

#[must_use]
pub fn classify_cdp_method(method: &str) -> Option<CdpCommandClassification> {
    let (action, risk_level) = match method {
        "Runtime.evaluate" | "Runtime.callFunctionOn" => {
            (ActionKind::BrowserScriptEval, RiskLevel::High)
        }
        "Input.dispatchMouseEvent" => (ActionKind::BrowserClick, RiskLevel::Medium),
        "Input.dispatchKeyEvent" => (ActionKind::BrowserInput, RiskLevel::Medium),
        "Page.navigate" => (ActionKind::BrowserNavigate, RiskLevel::Low),
        "Fetch.continueRequest" => (ActionKind::NetworkRequest, RiskLevel::Medium),
        _ => return None,
    };

    Some(CdpCommandClassification {
        surface: ExecutionSurface::BrowserCdp,
        action,
        risk_level,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdpCommandClassification {
    pub surface: ExecutionSurface,
    pub action: ActionKind,
    pub risk_level: RiskLevel,
}
