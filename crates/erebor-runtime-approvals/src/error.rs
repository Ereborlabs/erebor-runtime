use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ApprovalError {
    #[snafu(display("approval binding is invalid: {reason}"))]
    InvalidBinding {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval `{approval_id}` is not pending"))]
    NotPending {
        approval_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval `{approval_id}` is not approved"))]
    NotApproved {
        approval_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval `{approval_id}` expired"))]
    Expired {
        approval_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval `{approval_id}` does not bind the current effect"))]
    BindingMismatch {
        approval_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval `{approval_id}` was not found"))]
    NotFound {
        approval_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("approval repository is unavailable: {reason}"))]
    RepositoryUnavailable {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, ApprovalError>;

impl ApprovalError {
    #[must_use]
    pub fn not_found(approval_id: impl Into<String>) -> Self {
        Self::NotFound {
            approval_id: approval_id.into(),
            location: Location::default(),
        }
    }

    #[must_use]
    pub fn repository_unavailable(reason: impl Into<String>) -> Self {
        Self::RepositoryUnavailable {
            reason: reason.into(),
            location: Location::default(),
        }
    }
}

impl ErrorExt for ApprovalError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidBinding { .. } | Self::BindingMismatch { .. } => {
                StatusCode::InvalidArguments
            }
            Self::NotPending { .. } | Self::NotApproved { .. } | Self::Expired { .. } => {
                StatusCode::IllegalState
            }
            Self::NotFound { .. } => StatusCode::NotFound,
            Self::RepositoryUnavailable { .. } => StatusCode::Unavailable,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::RepositoryUnavailable { .. } => RetryHint::Retryable,
            Self::InvalidBinding { .. }
            | Self::NotPending { .. }
            | Self::NotApproved { .. }
            | Self::Expired { .. }
            | Self::BindingMismatch { .. }
            | Self::NotFound { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
