//! Browser/CDP enforcement surface contracts for erebor-runtime.

mod error;

pub use error::CdpError;

use erebor_runtime_events::{ActionKind, ExecutionSurface};

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
pub fn classify_cdp_method(method: &str) -> Option<(ExecutionSurface, ActionKind)> {
    let action = match method {
        "Runtime.evaluate" | "Runtime.callFunctionOn" => ActionKind::BrowserScriptEval,
        "Input.dispatchMouseEvent" => ActionKind::BrowserClick,
        "Input.dispatchKeyEvent" => ActionKind::BrowserInput,
        "Page.navigate" => ActionKind::BrowserNavigate,
        "Fetch.continueRequest" => ActionKind::NetworkRequest,
        _ => return None,
    };

    Some((ExecutionSurface::BrowserCdp, action))
}
