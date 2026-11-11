use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Native Data operation {operation} failed: {source}"))]
    NativeStorage {
        operation: &'static str,
        source: fjall::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Native Data {field} is invalid"))]
    NativeState {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(transparent)]
    PreparedNotification { source: std::sync::Arc<Error> },
    #[snafu(transparent)]
    GraphFacility { source: araphor_graph::Error },
    #[snafu(transparent)]
    Definition {
        source: araphor_discovery_definition::Error,
    },
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
    #[snafu(display("Managed encoding failed: {source}"))]
    ManagedEncoding {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Managed decoding failed: {source}"))]
    ManagedDecoding {
        source: rmp_serde::decode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package context encoding failed: {source}"))]
    PackageContextEncode {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package context decoding failed: {source}"))]
    PackageContextDecode {
        source: rmp_serde::decode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package response encoding failed: {source}"))]
    PackageResponseEncode {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package response decoding failed: {source}"))]
    PackageResponseDecode {
        source: rmp_serde::decode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Package table encoding failed: {source}"))]
    PackageArrow {
        source: araphor_analysis_sdk::arrow_schema::ArrowError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis contract failed: {source}"), visibility(pub))]
    AnalysisContract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Analysis key encoding failed: {source}"))]
    AnalysisKeyEncode {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Stored artifact is invalid"))]
    StoredArtifact {
        source: Box<Error>,
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
    NotificationEncode {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notification decoding failed: {source}"), visibility(pub))]
    NotificationDecode {
        source: rmp_serde::decode::Error,
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
    #[snafu(display("Graph native encoding failed: {source}"))]
    GraphNativeEncoding {
        source: rmp_serde::encode::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph native decoding failed: {source}"))]
    GraphNativeDecoding {
        source: rmp_serde::decode::Error,
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
    #[snafu(display("The input journal no longer retains {position:?}"))]
    AnalysisInputExpired {
        position: crate::StorePositionV1,
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
    #[snafu(display("Captured analysis sources changed"))]
    AnalysisSourceChanged {
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

impl Error {
    pub(crate) fn unprepared(&self) -> &Self {
        match self {
            Self::PreparedNotification { source } => source.unprepared(),
            _ => self,
        }
    }

    pub(crate) fn stored_artifact(self) -> Self {
        let invalid = match self.unprepared() {
            Self::Package { code, .. } => matches!(
                code,
                crate::PackageErrorCodeV1::Invalid
                    | crate::PackageErrorCodeV1::Missing
                    | crate::PackageErrorCodeV1::Unsupported
                    | crate::PackageErrorCodeV1::Limit
            ),
            Self::PackageEncoding { .. }
            | Self::ManagedEncoding { .. }
            | Self::ManagedDecoding { .. }
            | Self::PackageContextEncode { .. }
            | Self::PackageContextDecode { .. }
            | Self::PackageArrow { .. } => true,
            Self::AnalysisContract { source, .. }
                if !matches!(source, araphor_analysis_sdk::Error::Io { .. }) =>
            {
                matches!(
                    source.status_code(),
                    StatusCode::InvalidArguments | StatusCode::Unsupported | StatusCode::Internal
                )
            }
            _ => false,
        };
        if invalid {
            Self::StoredArtifact {
                source: Box::new(self),
                location: snafu::location!(),
            }
        } else {
            self
        }
    }
}

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

impl From<araphor_analysis_types::Error> for Error {
    fn from(source: araphor_analysis_types::Error) -> Self {
        match source {
            araphor_analysis_types::Error::Allocation { resource, .. } => {
                AnalysisInputTooLargeSnafu { resource }.build()
            }
            araphor_analysis_types::Error::Invalid { field, location } => {
                Self::GraphInvalid { field, location }
            }
            araphor_analysis_types::Error::Json { source, location } => {
                Self::GraphEncoding { source, location }
            }
            araphor_analysis_types::Error::Encoding { source, location } => {
                Self::GraphNativeEncoding { source, location }
            }
            araphor_analysis_types::Error::Decoding { source, location } => {
                Self::GraphNativeDecoding { source, location }
            }
            araphor_analysis_types::Error::Contract { source, location } => {
                Self::AnalysisContract { source, location }
            }
        }
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NativeStorage {
                source: fjall::Error::HistoryUnavailable(..),
                ..
            } => StatusCode::NotFound,

            Self::NativeStorage { .. } => StatusCode::External,

            Self::NativeState { .. } => StatusCode::IllegalState,
            Self::PreparedNotification { source } => source.status_code(),
            Self::GraphFacility { source } => source.status_code(),
            Self::Definition { source } => source.status_code(),
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
            Self::PackageEncoding { .. }
            | Self::ManagedEncoding { .. }
            | Self::ManagedDecoding { .. }
            | Self::PackageContextEncode { .. }
            | Self::PackageContextDecode { .. }
            | Self::PackageArrow { .. } => StatusCode::InvalidArguments,
            Self::PackageResponseEncode { .. } => StatusCode::Internal,
            Self::PackageResponseDecode { .. } => StatusCode::InvalidArguments,
            Self::AnalysisContract { source, .. } => source.status_code(),
            Self::Notification { code, .. } => match code {
                crate::NotificationErrorCodeV1::Invalid | crate::NotificationErrorCodeV1::Limit => {
                    StatusCode::InvalidArguments
                }
                crate::NotificationErrorCodeV1::Denied => StatusCode::PermissionDenied,
                crate::NotificationErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                crate::NotificationErrorCodeV1::Unavailable => StatusCode::Unavailable,
            },
            Self::NotificationEncode { .. } | Self::AnalysisKeyEncode { .. } => {
                StatusCode::Internal
            }
            Self::NotificationDecode { .. } => StatusCode::IllegalState,
            Self::CanonicalEncoding { .. }
            | Self::DiscoveryInvalid { .. }
            | Self::TraceInvalid { .. }
            | Self::AnalysisInputTooLarge { .. } => StatusCode::InvalidArguments,
            Self::GraphInvalid { .. } => StatusCode::InvalidArguments,
            Self::AnalysisReadDenied { .. } => StatusCode::PermissionDenied,
            Self::AnalysisUnavailable { .. } => StatusCode::Unsupported,
            Self::AnalysisReplayExpired { .. }
            | Self::AnalysisInputExpired { .. }
            | Self::RetainedRangeExpired { .. } => StatusCode::NotFound,
            Self::AnalysisReadCancelled { .. } => StatusCode::Cancelled,
            Self::AnalysisReadDeadline { .. } => StatusCode::DeadlineExceeded,
            Self::AnalysisBusy { .. }
            | Self::ProtectedInputCapacity { .. }
            | Self::RetentionUnavailable { .. } => StatusCode::Unavailable,
            Self::AnalysisConflict { .. }
            | Self::AnalysisSourceChanged { .. }
            | Self::DiscoveryConflict { .. } => StatusCode::AlreadyExists,
            Self::EvidenceFrame { .. }
            | Self::EvidenceDecode { .. }
            | Self::AnalysisState { .. }
            | Self::StoredArtifact { .. }
            | Self::Json { .. } => StatusCode::IllegalState,
            Self::Io { .. } | Self::DiscoveryContext { .. } | Self::DiscoveryExecution { .. } => {
                StatusCode::External
            }
            Self::GraphContext { .. } => StatusCode::External,
            Self::GraphEncoding { .. }
            | Self::GraphNativeEncoding { .. }
            | Self::GraphNativeDecoding { .. } => StatusCode::Internal,
            Self::DiscoveryEncoding { .. } => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::PreparedNotification { source } => source.retry_hint(),
            Self::GraphFacility { source } => source.retry_hint(),
            Self::Definition { source } => source.retry_hint(),
            Self::AnalysisContract { source, .. } => source.retry_hint(),
            Self::AnalysisBusy { .. }
            | Self::ProtectedInputCapacity { .. }
            | Self::RetentionUnavailable { .. } => RetryHint::Retryable,
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        match self {
            Self::PreparedNotification { source } => source.as_any(),
            _ => self,
        }
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

    #[test]
    fn stored_errors_keep_boundaries() -> TestResult {
        use crate::PackageErrorCodeV1 as Code;
        use araphor_analysis_sdk::{Error as Contract, ErrorCode};

        let mut semantic = [Code::Invalid, Code::Limit, Code::Missing, Code::Unsupported]
            .into_iter()
            .map(|code| code.error("stored row"))
            .collect::<Vec<_>>();
        for code in [
            ErrorCode::Invalid,
            ErrorCode::Incompatible,
            ErrorCode::Failed,
        ] {
            semantic.push(Error::AnalysisContract {
                source: Contract::contract(code, "stored descriptor"),
                location: snafu::location!(),
            });
        }
        semantic.push(Error::PackageEncoding {
            source: serde_json::from_str::<bool>("invalid")
                .err()
                .ok_or("JSON accepted")?,
            location: snafu::location!(),
        });
        semantic.push(Error::ManagedDecoding {
            source: rmp_serde::decode::Error::Syntax("invalid stored row".into()),
            location: snafu::location!(),
        });
        semantic.push(Error::PackageArrow {
            source: araphor_analysis_sdk::arrow_schema::ArrowError::ParseError(
                "stored batch".into(),
            ),
            location: snafu::location!(),
        });
        semantic.push(Error::AnalysisContract {
            source: Contract::Encoding {
                source: serde_json::from_str::<bool>("invalid")
                    .err()
                    .ok_or("JSON accepted")?,
                location: snafu::location!(),
            },
            location: snafu::location!(),
        });
        for error in semantic {
            let kind = std::mem::discriminant(&error);
            let message = error.to_string();
            let error = error.stored_artifact().stored_artifact();
            assert_eq!(error.status_code(), StatusCode::IllegalState);
            assert_eq!(error.retry_hint(), RetryHint::NonRetryable);
            assert_eq!(error.to_string(), "Stored artifact is invalid");
            let Error::StoredArtifact { source, .. } = &error else {
                return Err("stored semantic error unclassified".into());
            };
            assert_eq!(std::mem::discriminant(source.as_ref()), kind);
            assert_eq!(source.to_string(), message);
            assert_eq!(
                std::error::Error::source(&error).map(ToString::to_string),
                Some(message)
            );
        }

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("absent");
        for error in [
            AnalysisReadCancelledSnafu.build(),
            AnalysisReadDeadlineSnafu.build(),
            AnalysisReadDeniedSnafu.build(),
            AnalysisConflictSnafu.build(),
            AnalysisBusySnafu { resource: "writer" }.build(),
            ProtectedInputCapacitySnafu { resource: "memory" }.build(),
            RetentionUnavailableSnafu.build(),
            Code::Denied.error("stored scope"),
            Code::Conflict.error("stored pin"),
            Code::Incomplete.error("stored input"),
            Error::NativeStorage {
                operation: "read stored row",
                source: fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "storage read failed",
                )),
                location: snafu::location!(),
            },
            Error::Io {
                path: path.clone(),
                source: std::fs::File::open(&path)
                    .err()
                    .ok_or("absent file opened")?,
                location: snafu::location!(),
            },
            Error::AnalysisContract {
                source: Contract::Io {
                    path: path.clone(),
                    source: std::fs::File::open(&path)
                        .err()
                        .ok_or("absent file opened")?,
                    location: snafu::location!(),
                },
                location: snafu::location!(),
            },
            Error::AnalysisContract {
                source: Contract::Io {
                    path: path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "read interrupted",
                    ),
                    location: snafu::location!(),
                },
                location: snafu::location!(),
            },
            Error::AnalysisContract {
                source: Contract::contract(ErrorCode::Unauthorized, "stored scope"),
                location: snafu::location!(),
            },
            Error::AnalysisContract {
                source: Contract::contract(ErrorCode::Incomplete, "stored input"),
                location: snafu::location!(),
            },
            Error::Json {
                path: path.clone(),
                source: serde_json::from_str::<bool>("invalid")
                    .err()
                    .ok_or("JSON accepted")?,
                location: snafu::location!(),
            },
            AnalysisStateSnafu {
                path: &path,
                reason: "invalid stored row",
            }
            .build(),
        ] {
            let kind = std::mem::discriminant(&error);
            let message = error.to_string();
            let status = error.status_code();
            let retry = error.retry_hint();
            let source = std::error::Error::source(&error).map(ToString::to_string);
            let error = error.stored_artifact();
            assert_eq!(std::mem::discriminant(&error), kind);
            assert_eq!(error.to_string(), message);
            assert_eq!(error.status_code(), status);
            assert_eq!(error.retry_hint(), retry);
            assert_eq!(
                std::error::Error::source(&error).map(ToString::to_string),
                source
            );
        }
        Ok(())
    }
}

impl Error {
    pub(crate) fn reject_path<T>(root: &std::path::Path, reason: &str) -> Result<T> {
        crate::AnalysisStateSnafu {
            path: root.to_path_buf(),
            reason: reason.to_owned(),
        }
        .fail()
    }
}
