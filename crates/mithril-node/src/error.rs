use std::any::Any;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_ipc::IpcProtocolError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Mithril node configuration is invalid: {reason}"))]
    InvalidConfiguration {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril native identity state is invalid: {reason}"))]
    IdentityState {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril authorization proof was rejected: {reason}"))]
    Authorization {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node failed to access `{}`: {source}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node JSON `{}` is invalid: {source}", path.display()))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node Interceptor startup failed: {source}"))]
    Interceptor {
        source: erebor_interceptor::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node policy candidate failed: {source}"))]
    Policy {
        source: mithril_control::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node control transport failed: {source}"))]
    ControlTransport {
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node control RPC failed: {source}"))]
    ControlRpc {
        #[snafu(source(from(tonic::Status, Box::new)))]
        source: Box<tonic::Status>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node container-runtime transport failed: {source}"))]
    ContainerRuntimeTransport {
        source: tonic::transport::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node container-runtime RPC failed: {source}"))]
    ContainerRuntimeRpc {
        #[snafu(source(from(tonic::Status, Box::new)))]
        source: Box<tonic::Status>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node failed to inspect container process {pid}: {source}"))]
    ContainerRuntimeProcess {
        pid: i32,
        source: procfs::ProcError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril node control protocol failed: {reason}"))]
    ControlProtocol {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Runtime observation IPC failed: {source}"))]
    LocalIpc {
        source: IpcProtocolError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Mithril Runtime observation task failed: {source}"))]
    LocalTask {
        source: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidConfiguration { .. }
            | Self::IdentityState { .. }
            | Self::Json { .. }
            | Self::ControlProtocol { .. } => StatusCode::InvalidArguments,
            Self::Authorization { .. } => StatusCode::PermissionDenied,
            Self::LocalIpc { source, .. } => source.status_code(),
            Self::Interceptor { source, .. } => source.status_code(),
            Self::Policy { source, .. } => source.status_code(),
            Self::Io { .. }
            | Self::ControlTransport { .. }
            | Self::ControlRpc { .. }
            | Self::ContainerRuntimeTransport { .. }
            | Self::ContainerRuntimeRpc { .. }
            | Self::ContainerRuntimeProcess { .. }
            | Self::LocalTask { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::Interceptor { source, .. } => source.retry_hint(),
            Self::Policy { source, .. } => source.retry_hint(),
            Self::LocalIpc { source, .. } => source.retry_hint(),
            Self::ControlTransport { .. }
            | Self::ControlRpc { .. }
            | Self::ContainerRuntimeTransport { .. }
            | Self::ContainerRuntimeRpc { .. }
            | Self::ContainerRuntimeProcess { .. }
            | Self::LocalTask { .. } => RetryHint::Retryable,
            Self::InvalidConfiguration { .. }
            | Self::IdentityState { .. }
            | Self::Authorization { .. }
            | Self::Json { .. }
            | Self::ControlProtocol { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
