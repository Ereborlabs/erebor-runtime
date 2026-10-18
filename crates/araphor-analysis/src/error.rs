use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(transparent)]
    Data { source: araphor_data::Error },
    #[snafu(transparent)]
    Query { source: araphor_query::Error },
    #[snafu(display("Native result decoding failed: {source}"))]
    Arrow {
        source: serde_arrow::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Native publication task failed: {source}"))]
    Task {
        source: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<araphor_data::PackageImageError> for Error {
    fn from(source: araphor_data::PackageImageError) -> Self {
        Self::from(araphor_data::Error::from(source))
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Data { source } => source.status_code(),
            Self::Query { source } => source.status_code(),
            Self::Arrow { .. } => StatusCode::InvalidArguments,
            Self::Task { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Data { source } => source.retry_hint(),
            Self::Query { source } => source.retry_hint(),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
