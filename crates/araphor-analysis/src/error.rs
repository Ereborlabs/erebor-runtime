use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(transparent)]
    Data { source: araphor_data::Error },
    #[snafu(transparent)]
    Query { source: araphor_query::Error },
    #[snafu(display("Package encoding failed: {source}"))]
    PackageEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Model metadata encoding failed: {source}"))]
    ModelEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package table encoding failed: {source}"))]
    PackageArrow {
        source: arrow_schema::ArrowError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package Wasm {operation} failed: {source}"))]
    PackageWasm {
        code: araphor_data::PackageErrorCodeV1,
        operation: &'static str,
        #[snafu(source(from(wasmtime::Error, wasmtime::Error::into_boxed_dyn_error)))]
        source: Box<dyn std::error::Error + Send + Sync>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package native {operation} failed: {source}"))]
    PackageNative {
        code: araphor_data::PackageErrorCodeV1,
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract failed: {source}"))]
    AnalysisContract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Model {field} is invalid"))]
    ModelInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Model {resource} exceeds its limit of {limit}"))]
    ModelLimit {
        resource: &'static str,
        limit: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis execution failed: {source}"))]
    AnalysisExecution {
        source: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis {resource} admission is full"))]
    AnalysisBusy {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis file `{}` failed: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn is_busy(&self) -> bool {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(error) = current {
            if matches!(
                error.downcast_ref::<Self>(),
                Some(Self::AnalysisBusy { .. })
            ) || matches!(
                error.downcast_ref::<araphor_data::Error>(),
                Some(araphor_data::Error::AnalysisBusy { .. })
            ) || matches!(
                error.downcast_ref::<araphor_query::Error>(),
                Some(araphor_query::Error::Busy { .. } | araphor_query::Error::Capacity { .. })
            ) {
                return true;
            }
            current = match error.downcast_ref::<Self>() {
                Some(Self::Data { source }) => Some(source),
                Some(Self::Query { source }) => Some(source),
                _ => match error.downcast_ref::<araphor_query::Error>() {
                    Some(araphor_query::Error::Data { source }) => Some(source),
                    _ => error.source(),
                },
            };
        }
        false
    }

    pub(crate) fn package_code(&self) -> araphor_data::PackageErrorCodeV1 {
        use araphor_data::PackageErrorCodeV1 as Code;
        if self.is_busy() {
            return Code::Incomplete;
        }
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(error) = current {
            match error.downcast_ref::<araphor_data::Error>() {
                Some(araphor_data::Error::Package { code, .. }) => return *code,
                Some(araphor_data::Error::AnalysisInputTooLarge { .. }) => return Code::Limit,
                _ => {}
            }
            current = error.source();
        }
        match self {
            Self::Data {
                source: araphor_data::Error::Package { code, .. },
            }
            | Self::PackageWasm { code, .. }
            | Self::PackageNative { code, .. } => *code,
            Self::ModelLimit { .. }
            | Self::Data {
                source: araphor_data::Error::AnalysisInputTooLarge { .. },
            } => Code::Limit,
            Self::Query {
                source: araphor_query::Error::Sql { source },
            } if matches!(
                source.find_root(),
                araphor_query::datafusion::error::DataFusionError::ResourcesExhausted(_)
            ) =>
            {
                Code::Limit
            }
            Self::AnalysisContract { source, .. }
                if source.code() == araphor_analysis_sdk::ErrorCode::Limit =>
            {
                Code::Limit
            }
            _ => match self.status_code() {
                StatusCode::PermissionDenied => Code::Denied,
                StatusCode::Unsupported => Code::Unsupported,
                StatusCode::NotFound => Code::Missing,
                StatusCode::Unavailable | StatusCode::Cancelled | StatusCode::DeadlineExceeded => {
                    Code::Incomplete
                }
                StatusCode::AlreadyExists => Code::Conflict,
                _ => Code::Invalid,
            },
        }
    }
}

impl From<araphor_query::datafusion::error::DataFusionError> for Error {
    fn from(source: araphor_query::datafusion::error::DataFusionError) -> Self {
        Self::Query {
            source: araphor_query::Error::Sql { source },
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Data { source } => source.status_code(),
            Self::Query { source } => source.status_code(),
            Self::AnalysisContract { source, .. } => source.status_code(),
            Self::PackageWasm { code, .. } | Self::PackageNative { code, .. } => match code {
                araphor_data::PackageErrorCodeV1::Invalid
                | araphor_data::PackageErrorCodeV1::Limit => StatusCode::InvalidArguments,
                araphor_data::PackageErrorCodeV1::Denied => StatusCode::PermissionDenied,
                araphor_data::PackageErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                araphor_data::PackageErrorCodeV1::Missing => StatusCode::NotFound,
                araphor_data::PackageErrorCodeV1::Unsupported => StatusCode::Unsupported,
                araphor_data::PackageErrorCodeV1::Incomplete => StatusCode::Unavailable,
            },
            Self::PackageEncoding { .. }
            | Self::PackageArrow { .. }
            | Self::ModelInvalid { .. }
            | Self::ModelLimit { .. } => StatusCode::InvalidArguments,
            Self::ModelEncoding { .. } => StatusCode::Internal,
            Self::AnalysisBusy { .. } => StatusCode::Unavailable,
            Self::AnalysisExecution { .. } | Self::Io { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Data { source } => source.retry_hint(),
            Self::Query { source } => source.retry_hint(),
            Self::AnalysisContract { source, .. } => source.retry_hint(),
            Self::AnalysisBusy { .. } => RetryHint::Retryable,
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
