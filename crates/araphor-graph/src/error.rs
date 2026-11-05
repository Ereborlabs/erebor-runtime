use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{IntoError as _, Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Graph {field} is invalid"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph Arrow operation failed: {source}"))]
    Arrow {
        source: arrow_schema::ArrowError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph operation failed: {source}"))]
    Backend {
        source: BackendError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph {resource} changed"))]
    Conflict {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(feature = "store")]
    #[snafu(display("Graph storage operation {operation} failed: {source}"))]
    Database {
        operation: &'static str,
        source: duckdb::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct BackendError(Box<dyn ErrorExt + Send + Sync>);

impl std::fmt::Display for BackendError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(output)
    }
}

impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl Error {
    pub fn backend(source: impl ErrorExt + Send + Sync) -> Self {
        BackendSnafu.into_error(BackendError(Box::new(source)))
    }
}

impl From<arrow_schema::ArrowError> for Error {
    fn from(source: arrow_schema::ArrowError) -> Self {
        ArrowSnafu.into_error(source)
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } => StatusCode::InvalidArguments,
            Self::Arrow { .. } => StatusCode::External,
            Self::Backend { source, .. } => source.0.status_code(),
            Self::Conflict { .. } => StatusCode::IllegalState,
            #[cfg(feature = "store")]
            Self::Database { .. } => StatusCode::External,
        }
    }
    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Backend { source, .. } => source.0.retry_hint(),
            Self::Conflict { .. } => RetryHint::Retryable,
            _ => RetryHint::NonRetryable,
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
