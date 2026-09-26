use std::any::Any;
use std::net::SocketAddr;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Araphor data store failed: {source}"))]
    DataStore {
        source: Box<araphor_data::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor trace rejected {code:?}: {reason}"))]
    Observability {
        code: crate::TraceErrorCodeV1,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Discovery database operation {operation} failed: {source}"))]
    DiscoveryDatabase {
        operation: &'static str,
        #[snafu(source(from(rusqlite::Error, Box::new)))]
        source: Box<rusqlite::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "Evidence range {first_cursor}..={last_cursor} expired before it was opened"
    ))]
    RetainedRangeExpired {
        identity: Box<crate::EvidenceIntakeIdentityV1>,
        first_cursor: u64,
        last_cursor: u64,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor discovery rejected {code}: {reason}"))]
    Discovery {
        code: &'static str,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control configuration is invalid: {reason}"))]
    InvalidConfiguration {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control failed to read `{}`: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control TLS configuration failed: {source}"))]
    Tls {
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control server `{address}` failed: {source}"))]
    Serve {
        address: SocketAddr,
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control JSON `{}` is invalid: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy source `{}` is invalid: {source}", path.display()))]
    PolicySource {
        path: PathBuf,
        #[snafu(source(from(serde_saphyr::Error, Box::new)))]
        source: Box<serde_saphyr::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy `{policy_id}` failed {code}: {reason}"))]
    PolicyValidation {
        policy_id: String,
        code: &'static str,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy signature `{key_id}` is invalid: {reason}"))]
    PolicySignature {
        key_id: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril policy state `{}` is invalid: {reason}", path.display()))]
    PolicyState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril administrative approval failed: {reason}"))]
    AdministrativeApproval {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node decommission failed: {reason}"))]
    Decommission {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril evidence state `{}` is invalid: {reason}", path.display()))]
    EvidenceState {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Control store `{}` is invalid: {reason}", path.display()))]
    ControlStore {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Observability { code, .. } => match code {
                crate::TraceErrorCodeV1::Denied => StatusCode::PermissionDenied,
                crate::TraceErrorCodeV1::Conflict => StatusCode::AlreadyExists,
                crate::TraceErrorCodeV1::Expired => StatusCode::DeadlineExceeded,
                crate::TraceErrorCodeV1::Missing => StatusCode::NotFound,
                crate::TraceErrorCodeV1::Capacity => StatusCode::Unavailable,
                crate::TraceErrorCodeV1::Invalid => StatusCode::InvalidArguments,
                crate::TraceErrorCodeV1::Integrity => StatusCode::IllegalState,
            },
            Self::RetainedRangeExpired { .. } => StatusCode::NotFound,
            Self::Discovery { .. }
            | Self::InvalidConfiguration { .. }
            | Self::Json { .. }
            | Self::PolicySource { .. }
            | Self::PolicyValidation { .. }
            | Self::PolicySignature { .. }
            | Self::PolicyState { .. }
            | Self::EvidenceState { .. }
            | Self::ControlStore { .. }
            | Self::Decommission { .. }
            | Self::AdministrativeApproval { .. } => StatusCode::InvalidArguments,
            Self::DataStore { .. }
            | Self::DiscoveryDatabase { .. }
            | Self::Io { .. }
            | Self::Tls { .. }
            | Self::Serve { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Observability {
                code: crate::TraceErrorCodeV1::Capacity,
                ..
            } => RetryHint::Retryable,
            Self::Observability { .. } => RetryHint::NonRetryable,
            Self::DiscoveryDatabase { source, .. } => {
                if matches!(
                    source.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) {
                    RetryHint::Retryable
                } else {
                    RetryHint::NonRetryable
                }
            }
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Serve { .. } => RetryHint::Retryable,
            Self::DataStore { .. }
            | Self::RetainedRangeExpired { .. }
            | Self::Discovery { .. }
            | Self::InvalidConfiguration { .. }
            | Self::Json { .. }
            | Self::Tls { .. }
            | Self::PolicySource { .. }
            | Self::PolicyValidation { .. }
            | Self::PolicySignature { .. }
            | Self::PolicyState { .. }
            | Self::EvidenceState { .. }
            | Self::ControlStore { .. }
            | Self::Decommission { .. }
            | Self::AdministrativeApproval { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
