use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Definition rejects {field}"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Definition JSON failed: {source}"))]
    Json {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Definition file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("PRQL compilation failed: {source}"))]
    Prql {
        source: prqlc::ErrorMessages,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid { .. } | Self::Json { .. } | Self::Prql { .. } => {
                StatusCode::InvalidArguments
            }
            Self::Io { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
