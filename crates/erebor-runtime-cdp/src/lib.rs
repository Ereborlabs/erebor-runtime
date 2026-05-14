//! Browser/CDP enforcement surface contracts for erebor-runtime.

use erebor_runtime_events::{ActionKind, ExecutionSurface};
use thiserror::Error;

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

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CdpError {
    #[error("CDP method is missing")]
    MissingMethod,
    #[error("unsupported governed CDP method `{0}`")]
    UnsupportedMethod(String),
}
