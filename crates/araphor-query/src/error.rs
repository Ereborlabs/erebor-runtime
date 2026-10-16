use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(transparent)]
    Data { source: araphor_data::Error },
    #[snafu(display("SQL operation failed"))]
    Sql {
        source: datafusion::error::DataFusionError,
    },
    #[snafu(display("Invalid {field}"))]
    Invalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("No {resource} capacity is available"))]
    Capacity {
        resource: &'static str,
        source: datafusion::error::DataFusionError,
    },
    #[snafu(display("No {resource} capacity is available"))]
    Busy {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    InvalidQuery,
    InvalidCheckpoint,
    Unsupported,
    InputTooLarge,
    ResultTooLarge,
    CursorExpired,
    Cancelled,
    DeadlineExceeded,
    Busy,
    Denied,
    StorageUnavailable,
    OutputTimeout,
    EvaluationFailed,
}

impl Failure {
    fn data(error: &araphor_data::Error) -> Self {
        use araphor_data::Error;
        match error {
            Error::AnalysisInputTooLarge { .. } => Self::InputTooLarge,
            Error::AnalysisReadDenied { .. } => Self::Denied,
            Error::AnalysisUnavailable { .. } => Self::Unsupported,
            Error::AnalysisReplayExpired { .. } | Error::RetainedRangeExpired { .. } => {
                Self::CursorExpired
            }
            Error::AnalysisReadCancelled { .. } => Self::Cancelled,
            Error::AnalysisReadDeadline { .. } => Self::DeadlineExceeded,
            Error::AnalysisBusy { .. } => Self::Busy,
            Error::RetentionUnavailable { .. }
            | Error::StorageCapacity { .. }
            | Error::ProtectedInputCapacity { .. } => Self::StorageUnavailable,
            _ => Self::EvaluationFailed,
        }
    }

    pub fn native(error: &datafusion::error::DataFusionError) -> Self {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(source) = current {
            if let Some(source) = source.downcast_ref::<Error>() {
                return Self::from(source);
            }
            if let Some(source) = source.downcast_ref::<araphor_data::Error>() {
                return Self::data(source);
            }
            current = source.source();
        }
        use datafusion::error::DataFusionError;
        match error.find_root() {
            DataFusionError::ResourcesExhausted(resource) if resource.contains("input") => {
                Self::InputTooLarge
            }
            DataFusionError::ResourcesExhausted(_) => Self::ResultTooLarge,
            DataFusionError::NotImplemented(_) => Self::Unsupported,
            DataFusionError::Plan(_)
            | DataFusionError::SQL(..)
            | DataFusionError::SchemaError(..) => Self::InvalidQuery,
            _ => Self::EvaluationFailed,
        }
    }
}

impl From<&Error> for Failure {
    fn from(error: &Error) -> Self {
        match error {
            Error::Data { source } => Self::data(source),
            Error::Sql { source } => Self::native(source),
            Error::Invalid { field, .. } if field.starts_with("cursor") => Self::InvalidCheckpoint,
            Error::Invalid { .. } => Self::InvalidQuery,
            Error::Busy { .. } | Error::Capacity { .. } => Self::Busy,
        }
    }
}

impl Error {
    fn domain<'a>(mut source: &'a (dyn std::error::Error + 'static)) -> Option<&'a dyn ErrorExt> {
        loop {
            if let Some(error) = source.downcast_ref::<Self>() {
                return Some(error);
            }
            if let Some(error) = source.downcast_ref::<araphor_data::Error>() {
                return Some(error);
            }
            source = source.source()?;
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        use datafusion::error::DataFusionError;
        match self {
            Self::Data { source } => source.status_code(),
            Self::Invalid { .. } => StatusCode::InvalidArguments,
            Self::Busy { .. } | Self::Capacity { .. } => StatusCode::Unavailable,
            Self::Sql { source } => match Self::domain(source) {
                Some(error) => error.status_code(),
                None => match source.find_root() {
                    DataFusionError::ResourcesExhausted(_)
                    | DataFusionError::Plan(_)
                    | DataFusionError::SchemaError(..)
                    | DataFusionError::SQL(..) => StatusCode::InvalidArguments,
                    DataFusionError::NotImplemented(_) => StatusCode::Unsupported,
                    _ => StatusCode::External,
                },
            },
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Data { source } => source.retry_hint(),
            Self::Busy { .. } | Self::Capacity { .. } => RetryHint::Retryable,
            Self::Sql { source } => {
                Self::domain(source).map_or(RetryHint::NonRetryable, ErrorExt::retry_hint)
            }
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn output_msg(&self) -> String {
        match self {
            Self::Data { source } => source.output_msg(),
            _ => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::error::DataFusionError;

    #[test]
    fn capacity_pressure_can_retry() {
        let memory = crate::memory::Memory::new(8, 8);
        let held = memory.reserve_input(8).unwrap();
        let pressure = Error::Sql {
            source: memory.reserve_input(1).unwrap_err(),
        };
        assert_eq!(pressure.status_code(), StatusCode::Unavailable);
        assert_eq!(pressure.retry_hint(), RetryHint::Retryable);
        assert_eq!(Failure::from(&pressure), Failure::Busy);
        let oversize = Error::Sql {
            source: memory.reserve_input(9).unwrap_err(),
        };
        assert_eq!(oversize.status_code(), StatusCode::InvalidArguments);
        assert_eq!(oversize.retry_hint(), RetryHint::NonRetryable);
        assert_eq!(Failure::from(&oversize), Failure::InputTooLarge);
        drop(held);
        assert!(memory.reserve_input(8).is_ok());
    }

    #[test]
    fn wrapped_cancel_keeps_category() {
        let control = araphor_data::AnalysisReadControl::default();
        control.cancel().unwrap();
        let source = control.check().unwrap_err();
        let (status, retry) = (source.status_code(), source.retry_hint());
        let error = Error::Sql {
            source: DataFusionError::External(Box::new(source)),
        };
        assert_eq!(error.status_code(), status);
        assert_eq!(error.retry_hint(), retry);
        assert_eq!(error.output_msg(), "SQL operation failed");
    }
}
