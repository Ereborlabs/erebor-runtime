use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{IntoError as _, Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Araphor data store failed: {source}"))]
    DataStore {
        #[snafu(source(from(araphor_data::Error, Box::new)))]
        source: Box<araphor_data::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture configuration is invalid: {reason}"))]
    InvalidConfiguration {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor trace rejected {code:?}: {reason}"))]
    Observability {
        code: crate::TraceErrorCodeV1,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Trace authority encoding failed: {source}"))]
    TraceEncoding {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Stored trace authority is invalid: {source}"))]
    TraceDecoding {
        source: rmp_serde::decode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture identity is invalid: {reason}"))]
    IdentityState {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture authorization was rejected: {reason}"))]
    Authorization {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture JSON `{}` is invalid: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor capture backend failed: {source}"))]
    Interceptor {
        source: erebor_interceptor::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<araphor_data::Error> for Error {
    fn from(source: araphor_data::Error) -> Self {
        DataStoreSnafu.into_error(source)
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::DataStore { source, .. } => source.status_code(),
            Self::Interceptor { source, .. } => source.status_code(),
            Self::InvalidConfiguration { .. } | Self::IdentityState { .. } | Self::Json { .. } => {
                StatusCode::InvalidArguments
            }
            Self::Authorization { .. } => StatusCode::PermissionDenied,
            Self::Io { .. } => StatusCode::External,
            Self::TraceEncoding { .. } => StatusCode::Internal,
            Self::TraceDecoding { .. } => StatusCode::IllegalState,
            Self::Observability { code, .. } => match code {
                crate::TraceErrorCodeV1::Denied => StatusCode::PermissionDenied,
                crate::TraceErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                crate::TraceErrorCodeV1::Expired => StatusCode::DeadlineExceeded,
                crate::TraceErrorCodeV1::Missing => StatusCode::NotFound,
                crate::TraceErrorCodeV1::Capacity => StatusCode::Unavailable,
                crate::TraceErrorCodeV1::Invalid => StatusCode::InvalidArguments,
                crate::TraceErrorCodeV1::Integrity => StatusCode::IllegalState,
            },
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::DataStore { source, .. } => source.retry_hint(),
            Self::Interceptor { source, .. } => source.retry_hint(),
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Observability {
                code: crate::TraceErrorCodeV1::Capacity,
                ..
            } => RetryHint::Retryable,
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
