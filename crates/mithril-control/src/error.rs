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
    #[snafu(display("Mithril policy source `{}` is invalid: {source}", path.display()))]
    PolicySource {
        path: PathBuf,
        #[snafu(source(from(serde_saphyr::Error, Box::new)))]
        source: Box<serde_saphyr::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy `{policy_id}` failed {code}: {reason}"))]
    PolicyValidation {
        policy_id: String,
        code: &'static str,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy signature `{key_id}` is invalid: {reason}"))]
    PolicySignature {
        key_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy state `{}` is invalid: {reason}", path.display()))]
    PolicyState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidConfiguration { .. }
            | Self::Json { .. }
            | Self::PolicySource { .. }
            | Self::PolicyValidation { .. }
            | Self::PolicySignature { .. }
            | Self::PolicyState { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } | Self::Tls { .. } | Self::Serve { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Serve { .. } => RetryHint::Retryable,
            Self::InvalidConfiguration { .. }
            | Self::Json { .. }
            | Self::Tls { .. }
            | Self::PolicySource { .. }
            | Self::PolicyValidation { .. }
            | Self::PolicySignature { .. }
            | Self::PolicyState { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
