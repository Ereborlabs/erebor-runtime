use std::io;

use snafu::Location;
use thiserror::Error;
use tokio_tungstenite::tungstenite::Error as WebSocketError;

#[derive(Debug, Error)]
pub enum E2eError {
    #[error("e2e I/O failed: {source}")]
    Io {
        source: io::Error,
        location: Location,
    },
    #[error("e2e websocket failed: {source}")]
    WebSocket {
        source: Box<WebSocketError>,
        location: Location,
    },
    #[error("{operation} failed: {source}")]
    External {
        operation: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        location: Location,
    },
    #[error("e2e JSON failed: {source}")]
    Json {
        source: serde_json::Error,
        location: Location,
    },
    #[error("timed out while waiting for {operation}")]
    Timeout {
        operation: String,
        location: Location,
    },
    #[error("websocket closed while waiting for {operation}")]
    Closed {
        operation: String,
        location: Location,
    },
    #[error("expected no message on `{channel}` but received {message}")]
    UnexpectedMessage {
        channel: String,
        message: String,
        location: Location,
    },
    #[error("unsupported websocket message while waiting for {operation}")]
    UnsupportedWebSocketMessage {
        operation: String,
        location: Location,
    },
    #[error("environment variable `{name}` is not configured")]
    MissingEnv { name: String, location: Location },
}

impl E2eError {
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
    pub fn external(
        operation: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::External {
            operation: operation.into(),
            source: Box::new(source),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn json(source: serde_json::Error) -> Self {
        Self::Json {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn timeout(operation: impl Into<String>) -> Self {
        Self::Timeout {
            operation: operation.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn closed(operation: impl Into<String>) -> Self {
        Self::Closed {
            operation: operation.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unexpected_message(channel: impl Into<String>, message: impl Into<String>) -> Self {
        Self::UnexpectedMessage {
            channel: channel.into(),
            message: message.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unsupported_websocket_message(operation: impl Into<String>) -> Self {
        Self::UnsupportedWebSocketMessage {
            operation: operation.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn missing_env(name: impl Into<String>) -> Self {
        Self::MissingEnv {
            name: name.into(),
            location: Location::default(),
        }
    }
}
