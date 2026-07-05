use cdp_protocol::{fetch, input, page, runtime as cdp_runtime, types::Method};
use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

pub struct CdpMethodRegistry;

impl CdpMethodRegistry {
    pub const GOVERNED_METHODS: &'static [&'static str] = &[
        cdp_runtime::Evaluate::NAME,
        cdp_runtime::CallFunctionOn::NAME,
        input::DispatchMouseEvent::NAME,
        input::DispatchKeyEvent::NAME,
        page::Navigate::NAME,
        fetch::ContinueRequest::NAME,
    ];

    pub const CONTEXT_METHODS: &'static [&'static str] = &[
        "Fetch.requestPaused",
        "Network.requestWillBeSent",
        "Network.responseReceived",
        "Network.loadingFailed",
        "Page.frameNavigated",
        "Page.navigatedWithinDocument",
        "Runtime.executionContextCreated",
        "Target.attachedToTarget",
        "Target.detachedFromTarget",
        "Target.targetCreated",
        "Target.targetDestroyed",
        "Target.targetCrashed",
        "Target.targetInfoChanged",
    ];

    #[must_use]
    pub fn is_governed(method: &str) -> bool {
        Self::GOVERNED_METHODS.contains(&method) || method.starts_with("Target.")
    }

    #[must_use]
    pub fn is_context(method: &str) -> bool {
        Self::CONTEXT_METHODS.contains(&method)
    }

    #[must_use]
    pub fn classify(method: &str) -> Option<CdpCommandClassification> {
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
            "Page.frameNavigated" | "Page.navigatedWithinDocument" => (
                CdpMethodRole::ContextEvent,
                ActionKind::BrowserNavigate,
                RiskLevel::Low,
            ),
            "Runtime.executionContextCreated" => (
                CdpMethodRole::ContextEvent,
                ActionKind::BrowserScriptEval,
                RiskLevel::Low,
            ),
            "Target.attachedToTarget"
            | "Target.detachedFromTarget"
            | "Target.targetCreated"
            | "Target.targetDestroyed"
            | "Target.targetCrashed"
            | "Target.targetInfoChanged" => (
                CdpMethodRole::ContextEvent,
                ActionKind::BrowserTargetManage,
                RiskLevel::Low,
            ),
            method if method.starts_with("Target.") => (
                CdpMethodRole::GovernedCommand,
                ActionKind::BrowserTargetManage,
                RiskLevel::Medium,
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
