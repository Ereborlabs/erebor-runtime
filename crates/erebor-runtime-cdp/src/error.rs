use std::{any::Any, io};

use erebor_runtime_core::RuntimeError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};
use tokio_tungstenite::tungstenite::Error as WebSocketError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum CdpError {
    #[snafu(display("CDP method is missing"))]
    MissingMethod {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP message is invalid JSON: {source}"))]
    InvalidJson {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP protocol message is invalid: {source}"))]
    InvalidProtocol {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("unsupported governed CDP method `{method}`"))]
    UnsupportedMethod {
        method: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP method `{actual}` cannot be decoded as `{expected}`"))]
    UnexpectedMethod {
        expected: &'static str,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime enforcement failed: {source}"))]
    Enforcement {
        #[snafu(source(from(RuntimeError, Box::new)))]
        source: Box<RuntimeError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP proxy I/O failed: {source}"))]
    Io {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP websocket failed: {source}"))]
    WebSocket {
        #[snafu(source(from(WebSocketError, Box::new)))]
        source: Box<WebSocketError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("owned browser launch failed: {reason}"))]
    BrowserLaunch {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("CDP browser state synchronization failed: {reason}"))]
    BrowserStateSync {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for CdpError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingMethod { .. } => StatusCode::InvalidArguments,
            Self::InvalidJson { .. } => StatusCode::InvalidSyntax,
            Self::InvalidProtocol { .. } | Self::UnexpectedMethod { .. } => {
                StatusCode::InvalidArguments
            }
            Self::UnsupportedMethod { .. } => StatusCode::Unsupported,
            Self::Enforcement { source, .. } => source.status_code(),
            Self::Io { .. } | Self::WebSocket { .. } => StatusCode::External,
            Self::BrowserLaunch { .. } => StatusCode::Unavailable,
            Self::BrowserStateSync { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Enforcement { source, .. } => source.retry_hint(),
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::WebSocket { source, .. } => websocket_retry_hint(source),
            Self::MissingMethod { .. }
            | Self::InvalidJson { .. }
            | Self::InvalidProtocol { .. }
            | Self::UnsupportedMethod { .. }
            | Self::UnexpectedMethod { .. }
            | Self::BrowserLaunch { .. }
            | Self::BrowserStateSync { .. } => RetryHint::NonRetryable,
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

    use super::CdpError;

    #[test]
    fn cdp_statuses_cover_syntax_protocol_io_and_browser_launch() {
        let invalid_json = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => return,
            Err(source) => CdpError::InvalidJson {
                source,
                location: Location::default(),
            },
        };
        assert_eq!(invalid_json.status_code(), StatusCode::InvalidSyntax);

        let unsupported = CdpError::UnsupportedMethod {
            method: String::from("Target.createBrowserContext"),
            location: Location::default(),
        };
        assert_eq!(unsupported.status_code(), StatusCode::Unsupported);

        let io_error = CdpError::Io {
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);

        let launch = CdpError::BrowserLaunch {
            reason: String::from("Chrome exited early; Chrome stderr: crashpad failed"),
            location: Location::default(),
        };
        assert_eq!(launch.status_code(), StatusCode::Unavailable);
        assert!(launch
            .to_string()
            .contains("Chrome stderr: crashpad failed"));
    }
}
