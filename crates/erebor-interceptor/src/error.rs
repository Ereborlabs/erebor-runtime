use std::any::Any;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Interceptor configuration `{}` is invalid: {reason}", path.display()))]
    InvalidConfiguration {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Interceptor failed to {action} `{}`: {source}", path.display()))]
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Interceptor failed to {action} `{}` through libbpf: {source}", path.display()))]
    Libbpf {
        action: &'static str,
        path: PathBuf,
        source: libbpf_rs::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Interceptor pin-root lease `{}` is already owned", path.display()))]
    LeaseOwned {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Interceptor pin root `{}` contains stale state", path.display()))]
    StalePinRoot {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Interceptor manifest for `{}` is invalid: {reason}", path.display()))]
    ManifestMismatch {
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
            Self::InvalidConfiguration { .. } | Self::ManifestMismatch { .. } => {
                StatusCode::InvalidArguments
            }
            Self::LeaseOwned { .. } => StatusCode::AlreadyExists,
            Self::StalePinRoot { .. } => StatusCode::IllegalState,
            Self::Io { .. } | Self::Libbpf { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::LeaseOwned { .. } => RetryHint::Retryable,
            Self::InvalidConfiguration { .. }
            | Self::Libbpf { .. }
            | Self::StalePinRoot { .. }
            | Self::ManifestMismatch { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
