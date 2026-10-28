use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Graph {field} is invalid"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph encoding failed: {source}"))]
    Encoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract failed: {source}"))]
    Contract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph database operation {operation} failed: {source}"))]
    Database {
        operation: &'static str,
        source: duckdb::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } => StatusCode::InvalidArguments,
            Self::Encoding { .. } => StatusCode::Internal,
            Self::Contract { source, .. } => source.status_code(),
            Self::Database { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Contract { source, .. } => source.retry_hint(),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
