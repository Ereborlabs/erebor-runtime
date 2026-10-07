use std::any::Any;
use std::net::SocketAddr;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{IntoError as _, Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Client listener operation {operation} failed"))]
    ClientListener {
        operation: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Client authentication failed: {reason}"))]
    ClientUnauthenticated {
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("The client has no current tenant investigate permission"))]
    ClientDenied {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Client authentication state is unavailable: {reason}"))]
    ClientState {
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Client OIDC operation {operation} failed"))]
    ClientOidc {
        operation: &'static str,
        unauthenticated: bool,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor data store failed: {source}"))]
    DataStore {
        #[snafu(source(from(araphor_data::Error, Box::new)))]
        source: Box<araphor_data::Error>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Stored coverage report is invalid: {source}"))]
    CoverageDecode {
        source: prost::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Araphor observability failed: {source}"))]
    Observability {
        #[snafu(source(from(araphor_observability::Error, Box::new)))]
        source: Box<araphor_observability::Error>,
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

impl From<araphor_data::Error> for Error {
    fn from(source: araphor_data::Error) -> Self {
        DataStoreSnafu.into_error(source)
    }
}

impl From<araphor_observability::Error> for Error {
    fn from(source: araphor_observability::Error) -> Self {
        ObservabilitySnafu.into_error(source)
    }
}

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ClientUnauthenticated { .. }
            | Self::ClientDenied { .. }
            | Self::ClientOidc {
                unauthenticated: true,
                ..
            } => StatusCode::PermissionDenied,
            Self::ClientState { .. } | Self::ClientOidc { .. } | Self::ClientListener { .. } => {
                StatusCode::Unavailable
            }
            Self::DataStore { source, .. }
                if matches!(
                    source.as_ref(),
                    araphor_data::Error::CanonicalEncoding { .. }
                        | araphor_data::Error::DiscoveryInvalid { .. }
                        | araphor_data::Error::DiscoveryConflict { .. }
                        | araphor_data::Error::TraceInvalid { .. }
                        | araphor_data::Error::AnalysisConflict { .. }
                        | araphor_data::Error::RetainedRangeExpired { .. }
                        | araphor_data::Error::StorageCapacity { .. }
                        | araphor_data::Error::ProtectedInputCapacity { .. }
                        | araphor_data::Error::AnalysisBusy { .. }
                ) =>
            {
                source.status_code()
            }
            Self::Observability { source, .. } => source.status_code(),
            Self::CoverageDecode { .. } => StatusCode::IllegalState,
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
            Self::DataStore { .. } | Self::Io { .. } | Self::Tls { .. } | Self::Serve { .. } => {
                StatusCode::External
            }
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::ClientState { .. }
            | Self::ClientListener { .. }
            | Self::ClientOidc {
                unauthenticated: false,
                ..
            } => RetryHint::Retryable,
            Self::ClientUnauthenticated { .. }
            | Self::ClientDenied { .. }
            | Self::ClientOidc {
                unauthenticated: true,
                ..
            } => RetryHint::NonRetryable,
            Self::DataStore { source, .. }
                if matches!(
                    source.as_ref(),
                    araphor_data::Error::StorageCapacity { .. }
                        | araphor_data::Error::ProtectedInputCapacity { .. }
                        | araphor_data::Error::AnalysisBusy { .. }
                ) =>
            {
                source.retry_hint()
            }
            Self::Observability { source, .. } => source.retry_hint(),
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Serve { .. } => RetryHint::Retryable,
            Self::CoverageDecode { .. }
            | Self::DataStore { .. }
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
