use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Package contract failed: {source}"))]
    Contract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Component encoding failed: {source}"))]
    Component {
        source: anyhow::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Component file {} failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Workspace build at {} could not start: {source}", path.display()))]
    Build {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Workspace build at {} failed: {status}", path.display()))]
    BuildFailed {
        path: PathBuf,
        status: std::process::ExitStatus,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Contract { source, .. } => source.status_code(),
            Self::Component { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } | Self::Build { .. } | Self::BuildFailed { .. } => StatusCode::Internal,
        }
    }
    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Contract { source, .. } => source.retry_hint(),
            Self::Io { source, .. } | Self::Build { source, .. } => {
                RetryHint::from_io_error(source)
            }
            _ => RetryHint::NonRetryable,
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
