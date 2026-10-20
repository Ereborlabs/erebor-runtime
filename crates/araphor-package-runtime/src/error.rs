use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(transparent)]
    Data { source: araphor_data::Error },
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
    #[snafu(display("Analysis {resource} admission is full"))]
    AnalysisBusy {
        resource: &'static str,
        requested: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Runtime worker failed: {source}"))]
    Worker { source: tokio::task::JoinError },
    #[snafu(display("Runtime worker result failed: {source}"))]
    WorkerResult {
        source: tokio::sync::oneshot::error::RecvError,
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

impl From<araphor_package::Error> for Error {
    fn from(source: araphor_package::Error) -> Self {
        araphor_data::Error::from(source).into()
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Data { source } => source.status_code(),
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
            Self::AnalysisBusy { .. } => StatusCode::Unavailable,
            Self::Worker { .. } | Self::WorkerResult { .. } | Self::Io { .. } => {
                StatusCode::External
            }
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Data { source } => source.retry_hint(),
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
