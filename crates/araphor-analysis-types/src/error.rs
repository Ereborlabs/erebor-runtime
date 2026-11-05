use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Graph {resource} allocation failed: {source}"))]
    Allocation {
        resource: &'static str,
        source: std::collections::TryReserveError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph {field} is invalid"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph encoding failed: {source}"))]
    Encoding {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph decoding failed: {source}"))]
    Decoding {
        source: rmp_serde::decode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph JSON encoding failed: {source}"))]
    Json {
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

}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } | Self::Allocation { .. } => StatusCode::InvalidArguments,
            Self::Encoding { .. } | Self::Decoding { .. } | Self::Json { .. } => {
                StatusCode::Internal
            }
            Self::Contract { source, .. } => source.status_code(),
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
