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
        requested: usize,
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
    pub(crate) fn missing_input(&self) -> Option<&'static str> {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(error) = current {
            if let Some(araphor_data::Error::Package {
                code:
                    araphor_data::PackageErrorCodeV1::Missing
                    | araphor_data::PackageErrorCodeV1::Incomplete,
                field,
                ..
            }) = error.downcast_ref::<araphor_data::Error>()
            {
                return Some(field);
            }
            current = Self::cause(error);
        }
        None
    }

    fn cause<'a>(
        error: &'a (dyn std::error::Error + 'static),
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        match error.downcast_ref::<Self>() {
            Some(Self::Data { source }) => Some(source),
            Some(Self::Query { source }) => Some(source),
            _ => match error.downcast_ref::<araphor_query::Error>() {
                Some(araphor_query::Error::Data { source }) => Some(source),
                Some(araphor_query::Error::Contract { source }) => Some(source),
                _ => error.source(),
            },
        }
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.busy_resource().is_some()
    }

    pub(crate) fn busy_resource(&self) -> Option<(&'static str, usize)> {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(error) = current {
            if let Some(Self::AnalysisBusy {
                resource,
                requested,
                ..
            }) = error.downcast_ref::<Self>()
            {
                return Some((resource, *requested));
            }
            if let Some(araphor_data::Error::AnalysisBusy { resource, .. }) =
                error.downcast_ref::<araphor_data::Error>()
            {
                return Some((resource, 1));
            }
            if let Some(
                araphor_query::Error::Busy { resource, .. }
                | araphor_query::Error::Capacity { resource, .. },
            ) = error.downcast_ref::<araphor_query::Error>()
            {
                return Some((resource, 1));
            }
            current = Self::cause(error);
        }
        None
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
            if error
                .downcast_ref::<araphor_analysis_sdk::Error>()
                .is_some_and(|error| error.code() == araphor_analysis_sdk::ErrorCode::Limit)
            {
                return Code::Limit;
            }
            current = Self::cause(error);
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

#[cfg(test)]
mod tests {
    use super::*;
    use araphor_analysis_sdk::{Error as SdkError, ErrorCode};
    use araphor_data::PackageErrorCodeV1 as Code;
    use araphor_query::datafusion::error::DataFusionError;

    #[test]
    fn missing_input_keeps_domain() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for code in [
            Code::Missing,
            Code::Incomplete,
            Code::Denied,
            Code::Invalid,
            Code::Limit,
            Code::Conflict,
            Code::Unsupported,
        ] {
            let error = Error::from(DataFusionError::Context(
                "input capture".into(),
                Box::new(DataFusionError::External(Box::new(code.error("input")))),
            ));
            assert_eq!(
                error.missing_input().is_some(),
                matches!(code, Code::Missing | Code::Incomplete)
            );
        }
        let control = araphor_data::AnalysisReadControl::default();
        control.cancel()?;
        let errors = [
            control.check().err().ok_or("cancel accepted")?,
            araphor_data::Error::AnalysisReadDeadline {
                location: snafu::location!(),
            },
            araphor_data::Error::AnalysisBusy {
                resource: "input",
                location: snafu::location!(),
            },
        ];
        for source in errors {
            let error = Error::from(DataFusionError::External(Box::new(source)));
            assert!(error.missing_input().is_none());
        }
        Ok(())
    }

    #[test]
    fn wrapped_sdk_package_codes() {
        for (code, package) in [
            (ErrorCode::Invalid, Code::Invalid),
            (ErrorCode::Incompatible, Code::Unsupported),
            (ErrorCode::Unauthorized, Code::Denied),
            (ErrorCode::Incomplete, Code::Incomplete),
            (ErrorCode::Limit, Code::Limit),
            (ErrorCode::Failed, Code::Invalid),
        ] {
            for wrapper in 0..6 {
                let contract = SdkError::contract(code, "contract field");
                let (status, retry) = (contract.status_code(), contract.retry_hint());
                let error = match wrapper {
                    0 => Error::AnalysisContract {
                        source: contract,
                        location: snafu::location!(),
                    },
                    1 => Error::Query {
                        source: araphor_query::Error::Contract { source: contract },
                    },
                    2 => Error::Data {
                        source: araphor_data::Error::AnalysisContract {
                            source: contract,
                            location: snafu::location!(),
                        },
                    },
                    _ => {
                        let source: Box<dyn std::error::Error + Send + Sync> = match wrapper {
                            3 => Box::new(contract),
                            4 => Box::new(araphor_query::Error::Contract { source: contract }),
                            _ => Box::new(araphor_data::Error::AnalysisContract {
                                source: contract,
                                location: snafu::location!(),
                            }),
                        };
                        Error::from(DataFusionError::Context(
                            "native stage".into(),
                            Box::new(DataFusionError::External(source)),
                        ))
                    }
                };
                assert_eq!(error.package_code(), package, "{code:?}/{wrapper}");
                assert_eq!(error.status_code(), status, "{code:?}/{wrapper}");
                assert_eq!(error.retry_hint(), retry, "{code:?}/{wrapper}");
                assert!(!error.is_busy(), "{code:?}/{wrapper}");
            }
        }
    }

    #[test]
    fn native_pressure_can_retry() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let memory = araphor_query::memory::Memory::new(Some(8), Some(8));
        let held = memory.reserve_input(8)?;
        let pressure = Error::from(DataFusionError::Context(
            "native stage".into(),
            Box::new(memory.reserve_input(1).err().ok_or("pressure accepted")?),
        ));
        assert!(pressure.is_busy());
        assert_eq!(pressure.package_code(), Code::Incomplete);
        assert_eq!(pressure.status_code(), StatusCode::Unavailable);
        assert_eq!(pressure.retry_hint(), RetryHint::Retryable);
        let oversize = Error::from(DataFusionError::Context(
            "native stage".into(),
            Box::new(memory.reserve_input(9).err().ok_or("oversize accepted")?),
        ));
        assert!(!oversize.is_busy());
        assert_eq!(oversize.package_code(), Code::Limit);
        assert_eq!(oversize.status_code(), StatusCode::InvalidArguments);
        assert_eq!(oversize.retry_hint(), RetryHint::NonRetryable);
        let busy = Error::from(DataFusionError::External(Box::new(
            araphor_data::Error::AnalysisBusy {
                resource: "source read",
                location: snafu::location!(),
            },
        )));
        assert!(busy.is_busy());
        assert_eq!(busy.package_code(), Code::Incomplete);
        assert_eq!(busy.retry_hint(), RetryHint::Retryable);
        drop(held);
        assert!(memory.reserve_input(8).is_ok());
        Ok(())
    }
}
