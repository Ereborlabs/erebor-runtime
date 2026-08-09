use std::any::Any;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Mithril test input `{path:?}` is invalid: {reason}"))]
    InvalidInput {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril test I/O failed for `{path:?}`: {source}"))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril test JSON failed for `{path:?}`: {source}"))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril test command `{program}` failed: {reason}"))]
    Command {
        program: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Interceptor test failed: {source}"))]
    Interceptor {
        source: erebor_interceptor::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node identity test failed: {source}"))]
    Node {
        #[snafu(source(from(mithril_node::Error, Box::new)))]
        source: Box<mithril_node::Error>,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn from_interceptor(source: erebor_interceptor::Error) -> Self {
        Self::Interceptor {
            source,
            location: snafu::Location::default(),
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidInput { .. } | Self::Json { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } | Self::Command { .. } => StatusCode::External,
            Self::Interceptor { source, .. } => source.status_code(),
            Self::Node { source, .. } => source.status_code(),
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidInput { .. } | Self::Json { .. } | Self::Command { .. } => {
                RetryHint::NonRetryable
            }
            Self::Interceptor { source, .. } => source.retry_hint(),
            Self::Node { source, .. } => source.retry_hint(),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
