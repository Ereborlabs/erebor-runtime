use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Analysis contract failed: {source}"))]
    AnalysisContract {
        source: araphor_analysis_sdk::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notification {code:?} rejects {field}"))]
    Notification {
        code: crate::NotificationErrorCodeV1,
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Notification encoding failed: {source}"))]
    NotificationEncoding {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph {field} is invalid"))]
    GraphInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Graph encoding failed: {source}"))]
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
    #[snafu(display("Discovery {field} is invalid"))]
    DiscoveryInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery {kind} conflicts with retained state"))]
    DiscoveryConflict {
        kind: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery encoding failed: {source}"))]
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
    #[snafu(display("Query {field} is invalid"))]
    QueryInvalid {
        field: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query disclosure is not authorized"))]
    QueryDenied {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query execution task failed: {source}"))]
    QueryExecution {
        source: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query relation {relation} is unavailable"))]
    QueryUnsupported {
        relation: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query {resource} exceeds its limit of {limit}"))]
    QueryLimit {
        resource: &'static str,
        limit: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query checkpoint cannot replay below the tenant retention floor"))]
    QueryCursorExpired {
        position: crate::StorePositionV1,
        floor: crate::StorePositionV1,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Query metadata encoding failed: {source}"))]
    QueryEncoding {
        source: serde_json::Error,
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
    #[snafu(display("evidence record protobuf is invalid"))]
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
    #[snafu(display("Analysis evidence range {first_cursor}..={last_cursor} has expired"))]
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

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
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
            | Self::QueryInvalid { .. }
            | Self::QueryLimit { .. }
            | Self::AnalysisInputTooLarge { .. } => StatusCode::InvalidArguments,
            Self::GraphInvalid { .. } => StatusCode::InvalidArguments,
            Self::QueryUnsupported { .. } => StatusCode::Unsupported,
            Self::QueryDenied { .. } => StatusCode::PermissionDenied,
            Self::QueryCursorExpired { .. } | Self::RetainedRangeExpired { .. } => {
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
            | Self::QueryExecution { .. }
            | Self::DiscoveryContext { .. }
            | Self::DiscoveryExecution { .. } => StatusCode::External,
            Self::GraphContext { .. } => StatusCode::External,
            Self::GraphEncoding { .. } => StatusCode::Internal,
            Self::QueryEncoding { .. } | Self::DiscoveryEncoding { .. } => StatusCode::Internal,
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
