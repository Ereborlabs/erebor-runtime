use std::{any::Any, io};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};
use tokio_tungstenite::tungstenite::Error as WebSocketError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum E2eError {
    #[snafu(display("e2e I/O failed: {source}"))]
    Io {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("e2e websocket failed: {source}"))]
    WebSocket {
        #[snafu(source(from(WebSocketError, Box::new)))]
        source: Box<WebSocketError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{operation} failed: {source}"))]
    External {
        operation: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("e2e JSON failed: {source}"))]
    Json {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("timed out while waiting for {operation}"))]
    Timeout {
        operation: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("websocket closed while waiting for {operation}"))]
    Closed {
        operation: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("expected no message on `{channel}` but received {message}"))]
    UnexpectedMessage {
        channel: String,
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("unsupported websocket message while waiting for {operation}"))]
    UnsupportedWebSocketMessage {
        operation: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("environment variable `{name}` is not configured"))]
    MissingEnv {
        name: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for E2eError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Io { .. } | Self::WebSocket { .. } | Self::External { .. } => {
                StatusCode::External
            }
            Self::Json { .. } => StatusCode::InvalidSyntax,
            Self::Timeout { .. } => StatusCode::DeadlineExceeded,
            Self::Closed { .. } => StatusCode::Unavailable,
            Self::UnexpectedMessage { .. } => StatusCode::Unexpected,
            Self::UnsupportedWebSocketMessage { .. } => StatusCode::Unsupported,
            Self::MissingEnv { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::WebSocket { source, .. } => websocket_retry_hint(source),
            Self::External { .. }
            | Self::Json { .. }
            | Self::Timeout { .. }
            | Self::Closed { .. }
            | Self::UnexpectedMessage { .. }
            | Self::UnsupportedWebSocketMessage { .. }
            | Self::MissingEnv { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn websocket_retry_hint(error: &WebSocketError) -> RetryHint {
    match error {
        WebSocketError::Io(source) => RetryHint::from_io_error(source),
        _ => RetryHint::NonRetryable,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::E2eError;

    #[test]
    fn e2e_statuses_cover_io_json_timeout_and_harness_state() {
        let io_error = E2eError::Io {
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);

        let json = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => return,
            Err(source) => E2eError::Json {
                source,
                location: Location::default(),
            },
        };
        assert_eq!(json.status_code(), StatusCode::InvalidSyntax);

        let timeout = E2eError::Timeout {
            operation: String::from("browser CDP response"),
            location: Location::default(),
        };
        assert_eq!(timeout.status_code(), StatusCode::DeadlineExceeded);

        let unsupported = E2eError::UnsupportedWebSocketMessage {
            operation: String::from("mini upstream"),
            location: Location::default(),
        };
        assert_eq!(unsupported.status_code(), StatusCode::Unsupported);
    }
}
