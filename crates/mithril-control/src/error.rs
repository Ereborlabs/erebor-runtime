use std::any::Any;
use std::net::SocketAddr;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Mithril Control configuration is invalid: {reason}"))]
    InvalidConfiguration {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control failed to read `{}`: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control TLS configuration failed: {source}"))]
    Tls {
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control server `{address}` failed: {source}"))]
    Serve {
        address: SocketAddr,
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control JSON `{}` is invalid: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidConfiguration { .. } | Self::Json { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } | Self::Tls { .. } | Self::Serve { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Serve { .. } => RetryHint::Retryable,
            Self::InvalidConfiguration { .. } | Self::Json { .. } | Self::Tls { .. } => {
                RetryHint::NonRetryable
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
