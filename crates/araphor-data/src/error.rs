use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Package {code:?} rejects {field}"), visibility(pub))]
    Package {
        code: crate::PackageErrorCodeV1,
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package encoding failed: {source}"), visibility(pub))]
    PackageEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package table encoding failed: {source}"))]
    PackageArrow {
        source: duckdb::arrow::error::ArrowError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract failed: {source}"), visibility(pub))]
    AnalysisContract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notification {code:?} rejects {field}"), visibility(pub))]
    Notification {
        code: crate::NotificationErrorCodeV1,
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notification encoding failed: {source}"), visibility(pub))]
    NotificationEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph {field} is invalid"), visibility(pub))]
    GraphInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph encoding failed: {source}"), visibility(pub))]
    GraphEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph context failed: {source}"))]
    GraphContext {
        source: Box<dyn std::error::Error + Send + Sync>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery {field} is invalid"), visibility(pub))]
    DiscoveryInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(
        display("Discovery {kind} conflicts with retained state"),
        visibility(pub)
    )]
    DiscoveryConflict {
        kind: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery encoding failed: {source}"), visibility(pub))]
    DiscoveryEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery policy context failed: {source}"))]
    DiscoveryContext {
        source: Box<dyn std::error::Error + Send + Sync>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery execution failed: {source}"))]
    DiscoveryExecution {
        source: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Canonical encoding failed: {reason}"))]
    CanonicalEncoding {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Trace contract is invalid: {reason}"))]
    TraceInvalid {
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{reason}"))]
    EvidenceFrame {
        reason: &'static str,
        input_bytes: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("evidence record protobuf is invalid"), visibility(pub))]
    EvidenceDecode {
        frame_bytes: usize,
        source: prost::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis extraction reached its {resource} limit"))]
    AnalysisInputTooLarge {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis read is not authorized"))]
    AnalysisReadDenied {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis relation {relation} is unavailable"))]
    AnalysisUnavailable {
        relation: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis replay position precedes its retained floor"))]
    AnalysisReplayExpired {
        position: crate::StorePositionV1,
        floor: crate::StorePositionV1,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The analysis read was cancelled"))]
    AnalysisReadCancelled {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The analysis read reached its deadline"))]
    AnalysisReadDeadline {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis storage reached its {resource} limit"))]
    StorageCapacity {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis {resource} admission is full"))]
    AnalysisBusy {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Required security input reached its {resource} budget"))]
    ProtectedInputCapacity {
        resource: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis intake is unavailable until retention succeeds"))]
    RetentionUnavailable {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis database operation {operation} failed: {source}"))]
    AnalysisDatabase {
        operation: &'static str,
        source: duckdb::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis store `{}` is invalid: {reason}", path.display()))]
    AnalysisState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(
        display("Analysis evidence range {first_cursor}..={last_cursor} has expired"),
        visibility(pub)
    )]
    RetainedRangeExpired {
        first_cursor: u64,
        last_cursor: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis progress or immutable result conflicts with committed state"))]
    AnalysisConflict {
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
    #[snafu(display("Analysis JSON `{}` failed: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<araphor_package::Error> for Error {
    fn from(source: araphor_package::Error) -> Self {
        match source {
            araphor_package::Error::Package {
                code,
                field,
                location,
            } => Self::Package {
                code: match code {
                    araphor_package::ErrorCode::Invalid => crate::PackageErrorCodeV1::Invalid,
                    araphor_package::ErrorCode::Limit => crate::PackageErrorCodeV1::Limit,
                    araphor_package::ErrorCode::Denied => crate::PackageErrorCodeV1::Denied,
                    araphor_package::ErrorCode::Conflict => crate::PackageErrorCodeV1::Conflict,
                    araphor_package::ErrorCode::Missing => crate::PackageErrorCodeV1::Missing,
                    araphor_package::ErrorCode::Unsupported => {
                        crate::PackageErrorCodeV1::Unsupported
                    }
                    araphor_package::ErrorCode::Incomplete => crate::PackageErrorCodeV1::Incomplete,
                },
                field,
                location,
            },
            araphor_package::Error::PackageEncoding { source, location } => {
                Self::PackageEncoding { source, location }
            }
            araphor_package::Error::AnalysisContract { source, location } => {
                Self::AnalysisContract { source, location }
            }
            araphor_package::Error::Io {
                path,
                source,
                location,
            } => Self::Io {
                path,
                source,
                location,
            },
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Package { code, .. } => match code {
                crate::PackageErrorCodeV1::Invalid | crate::PackageErrorCodeV1::Limit => {
                    StatusCode::InvalidArguments
                }
                crate::PackageErrorCodeV1::Denied => StatusCode::PermissionDenied,
                crate::PackageErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                crate::PackageErrorCodeV1::Missing => StatusCode::NotFound,
                crate::PackageErrorCodeV1::Unsupported => StatusCode::Unsupported,
                crate::PackageErrorCodeV1::Incomplete => StatusCode::Unavailable,
            },
            Self::PackageEncoding { .. } | Self::PackageArrow { .. } => {
                StatusCode::InvalidArguments
            }
            Self::AnalysisContract { source, .. } => source.status_code(),
            Self::Notification { code, .. } => match code {
                crate::NotificationErrorCodeV1::Invalid | crate::NotificationErrorCodeV1::Limit => {
                    StatusCode::InvalidArguments
                }
                crate::NotificationErrorCodeV1::Denied => StatusCode::PermissionDenied,
                crate::NotificationErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                crate::NotificationErrorCodeV1::Unavailable => StatusCode::Unavailable,
            },
            Self::NotificationEncoding { .. } => StatusCode::Internal,
            Self::CanonicalEncoding { .. }
            | Self::DiscoveryInvalid { .. }
            | Self::TraceInvalid { .. }
            | Self::AnalysisInputTooLarge { .. } => StatusCode::InvalidArguments,
            Self::GraphInvalid { .. } => StatusCode::InvalidArguments,
            Self::AnalysisReadDenied { .. } => StatusCode::PermissionDenied,
            Self::AnalysisUnavailable { .. } => StatusCode::Unsupported,
            Self::AnalysisReplayExpired { .. } | Self::RetainedRangeExpired { .. } => {
                StatusCode::NotFound
            }
            Self::AnalysisReadCancelled { .. } => StatusCode::Cancelled,
            Self::AnalysisReadDeadline { .. } => StatusCode::DeadlineExceeded,
            Self::StorageCapacity { .. }
            | Self::AnalysisBusy { .. }
            | Self::ProtectedInputCapacity { .. }
            | Self::RetentionUnavailable { .. } => StatusCode::Unavailable,
            Self::AnalysisConflict { .. } | Self::DiscoveryConflict { .. } => {
                StatusCode::AlreadyExists
            }
            Self::EvidenceFrame { .. }
            | Self::EvidenceDecode { .. }
            | Self::AnalysisState { .. }
            | Self::Json { .. } => StatusCode::IllegalState,
            Self::AnalysisDatabase { .. }
            | Self::Io { .. }
            | Self::DiscoveryContext { .. }
            | Self::DiscoveryExecution { .. } => StatusCode::External,
            Self::GraphContext { .. } => StatusCode::External,
            Self::GraphEncoding { .. } => StatusCode::Internal,
            Self::DiscoveryEncoding { .. } => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::AnalysisContract { source, .. } => source.retry_hint(),
            Self::AnalysisBusy { .. }
            | Self::StorageCapacity { .. }
            | Self::ProtectedInputCapacity { .. }
            | Self::RetentionUnavailable { .. } => RetryHint::Retryable,
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod package_tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn image_errors_keep_domain() -> TestResult {
        use crate::PackageErrorCodeV1 as Code;
        use araphor_package::ErrorCode as ImageCode;

        for (image, code) in [
            (ImageCode::Invalid, Code::Invalid),
            (ImageCode::Limit, Code::Limit),
            (ImageCode::Denied, Code::Denied),
            (ImageCode::Conflict, Code::Conflict),
            (ImageCode::Missing, Code::Missing),
            (ImageCode::Unsupported, Code::Unsupported),
            (ImageCode::Incomplete, Code::Incomplete),
        ] {
            let image = image.error("image field");
            let status = image.status_code();
            let retry = image.retry_hint();
            let error = Error::from(image);
            assert!(
                matches!(error, Error::Package { code: actual, field: "image field", .. } if actual == code)
            );
            assert_eq!(error.status_code(), status);
            assert_eq!(error.retry_hint(), retry);
        }
        let contract = araphor_analysis_sdk::Error::contract(
            araphor_analysis_sdk::ErrorCode::Incompatible,
            "image contract",
        );
        let error = Error::from(araphor_package::Error::AnalysisContract {
            source: contract,
            location: snafu::location!(),
        });
        assert!(matches!(error, Error::AnalysisContract { ref source, .. }
            if source.code() == araphor_analysis_sdk::ErrorCode::Incompatible));
        let json = serde_json::from_str::<bool>("invalid")
            .err()
            .ok_or("JSON accepted")?;
        let message = json.to_string();
        let error = Error::from(araphor_package::Error::PackageEncoding {
            source: json,
            location: snafu::location!(),
        });
        assert!(
            matches!(error, Error::PackageEncoding { ref source, .. } if source.to_string() == message)
        );
        let image = araphor_package::Error::Io {
            path: "image.oci".into(),
            source: std::io::Error::new(std::io::ErrorKind::Interrupted, "image read"),
            location: snafu::location!(),
        };
        let retry = image.retry_hint();
        let error = Error::from(image);
        assert_eq!(error.retry_hint(), retry);
        assert!(matches!(error, Error::Io { ref path, ref source, .. }
            if path == std::path::Path::new("image.oci") && source.kind() == std::io::ErrorKind::Interrupted));
        Ok(())
    }
}
