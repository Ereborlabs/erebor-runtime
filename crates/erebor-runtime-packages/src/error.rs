use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PackageError {
    #[snafu(display("invalid package model: {reason}"))]
    InvalidModel {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("canonical encoding failed: {source}"))]
    CanonicalEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notation verifier configuration is invalid: {reason}"))]
    InvalidVerifierConfiguration {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to inspect Notation verifier `{}`: {source}", path.display()))]
    InspectVerifier {
        path: std::path::PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notation verifier `{}` does not match its pinned SHA-256", path.display()))]
    VerifierDigestMismatch {
        path: std::path::PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notation verifier `{}` could not run: {source}", path.display()))]
    InvokeVerifier {
        path: std::path::PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notation rejected package `{subject}`: {reason}"))]
    VerificationRejected {
        subject: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "Notation returned an invalid verification result for `{subject}`: {reason}"
    ))]
    InvalidVerifierResult {
        subject: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, PackageError>;

impl ErrorExt for PackageError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidModel { .. } | Self::InvalidVerifierConfiguration { .. } => {
                StatusCode::InvalidArguments
            }
            Self::CanonicalEncoding { .. } => StatusCode::Internal,
            Self::InspectVerifier { .. } | Self::InvokeVerifier { .. } => StatusCode::External,
            Self::VerifierDigestMismatch { .. }
            | Self::VerificationRejected { .. }
            | Self::InvalidVerifierResult { .. } => StatusCode::PolicyDenied,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::InspectVerifier { source, .. } | Self::InvokeVerifier { source, .. } => {
                RetryHint::from_io_error(source)
            }
            Self::InvalidModel { .. }
            | Self::CanonicalEncoding { .. }
            | Self::InvalidVerifierConfiguration { .. }
            | Self::VerifierDigestMismatch { .. }
            | Self::VerificationRejected { .. }
            | Self::InvalidVerifierResult { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
