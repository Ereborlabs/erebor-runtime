use std::io;

use erebor_runtime_core::RuntimeError;
use snafu::Location;
use thiserror::Error;
use tokio_tungstenite::tungstenite::Error as WebSocketError;

#[derive(Debug, Error)]
pub enum CdpError {
    #[error("CDP method is missing")]
    MissingMethod { location: Location },
    #[error("CDP message is invalid JSON: {source}")]
    InvalidJson {
        source: serde_json::Error,
        location: Location,
    },
    #[error("CDP protocol message is invalid: {source}")]
    InvalidProtocol {
        source: serde_json::Error,
        location: Location,
    },
    #[error("unsupported governed CDP method `{method}`")]
    UnsupportedMethod { method: String, location: Location },
    #[error("CDP method `{actual}` cannot be decoded as `{expected}`")]
    UnexpectedMethod {
        expected: &'static str,
        actual: String,
        location: Location,
    },
    #[error("runtime enforcement failed: {source}")]
    Enforcement {
        source: Box<RuntimeError>,
        location: Location,
    },
    #[error("CDP proxy I/O failed: {source}")]
    Io {
        source: io::Error,
        location: Location,
    },
    #[error("CDP websocket failed: {source}")]
    WebSocket {
        source: Box<WebSocketError>,
        location: Location,
    },
    #[error("owned browser launch failed: {reason}")]
    BrowserLaunch { reason: String, location: Location },
    #[error("CDP browser state synchronization failed: {reason}")]
    BrowserStateSync { reason: String, location: Location },
}

impl CdpError {
    #[track_caller]
    pub fn missing_method() -> Self {
        Self::MissingMethod {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_json(source: serde_json::Error) -> Self {
        Self::InvalidJson {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_protocol(source: serde_json::Error) -> Self {
        Self::InvalidProtocol {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unsupported_method(method: impl Into<String>) -> Self {
        Self::UnsupportedMethod {
            method: method.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unexpected_method(expected: &'static str, actual: impl Into<String>) -> Self {
        Self::UnexpectedMethod {
            expected,
            actual: actual.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn enforcement(source: RuntimeError) -> Self {
        Self::Enforcement {
            source: Box::new(source),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn io(source: io::Error) -> Self {
        Self::Io {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn websocket(source: WebSocketError) -> Self {
        Self::WebSocket {
            source: Box::new(source),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn browser_launch(reason: impl Into<String>) -> Self {
        Self::BrowserLaunch {
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn browser_state_sync(reason: impl Into<String>) -> Self {
        Self::BrowserStateSync {
            reason: reason.into(),
            location: Location::default(),
        }
    }
}
