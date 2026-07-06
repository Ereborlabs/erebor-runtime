use erebor_runtime_e2e::E2eError;
use snafu::Location;

pub(crate) fn external_error(
    operation: impl Into<String>,
    source: impl std::error::Error + Send + Sync + 'static,
) -> E2eError {
    E2eError::External {
        operation: operation.into(),
        source: Box::new(source),
        location: Location::default(),
    }
}

pub(crate) fn timeout_error(operation: impl Into<String>) -> E2eError {
    E2eError::Timeout {
        operation: operation.into(),
        location: Location::default(),
    }
}

pub(crate) fn closed_error(operation: impl Into<String>) -> E2eError {
    E2eError::Closed {
        operation: operation.into(),
        location: Location::default(),
    }
}
