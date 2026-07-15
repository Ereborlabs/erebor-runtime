use std::{any::Any, io, path::PathBuf};

use erebor_runtime_context::ContextRepositoryError;
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_filesystem::FilesystemError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum CodexSessionError {
    #[snafu(display("configured Codex profile is incompatible with this session: {reason}"))]
    IncompatibleProfile {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read Codex profile artifact `{}`: {source}", path.display()))]
    ReadArtifact {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex profile artifact `{}` does not match its SHA-256 pin", path.display()))]
    ArtifactDigestMismatch {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex managed hook directory `{}` is not an exact trusted artifact set", path.display()))]
    ArtifactDirectoryUnsafe {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("fleet-managed Codex profile artifact `{}` is not root-owned and non-writable", path.display()))]
    ArtifactNotFleetProtected {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to prepare the Codex session filesystem projection: {source}"))]
    FilesystemProjection {
        #[snafu(source(from(FilesystemError, Box::new)))]
        source: Box<FilesystemError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket registry lock failed"))]
    TicketRegistryLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex prompt-reconciliation state lock failed"))]
    PromptReconciliationStateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket `{ticket_id}` was not found"))]
    TicketNotFound {
        ticket_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket `{ticket_id}` expired"))]
    TicketExpired {
        ticket_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket `{ticket_id}` belongs to an exited hook process"))]
    TicketProcessExited {
        ticket_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket `{ticket_id}` peer identity did not match"))]
    TicketPeerMismatch {
        ticket_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook ticket `{ticket_id}` was already consumed"))]
    TicketReplayed {
        ticket_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook protocol version `{version}` is unsupported"))]
    UnsupportedHookProtocol {
        version: u32,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook broker I/O failed: {source}"))]
    HookBrokerIo {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to bind Codex hook ticket to pid {pid}: {source}"))]
    Pidfd {
        pid: i32,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook broker IPC failed: {source}"))]
    HookBrokerProtocol {
        source: erebor_runtime_ipc::IpcProtocolError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook event is invalid: {reason}"))]
    InvalidHookEvent {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook broker rejected {stage}: {reason}"))]
    HookRejected {
        stage: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex App Server transport I/O failed during {operation}: {source}"))]
    AppServerTransportIo {
        operation: &'static str,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex App Server transport protocol is invalid: {reason}"))]
    AppServerTransportProtocol {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to record Codex App Server ingress context: {source}"))]
    AppServerTransportContext {
        #[snafu(source(from(ContextRepositoryError, Box::new)))]
        source: Box<ContextRepositoryError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex App Server exited with code {code:?}"))]
    AppServerTransportChildExit {
        code: Option<i32>,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for CodexSessionError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::IncompatibleProfile { .. }
            | Self::ArtifactDigestMismatch { .. }
            | Self::ArtifactDirectoryUnsafe { .. }
            | Self::ArtifactNotFleetProtected { .. }
            | Self::TicketNotFound { .. }
            | Self::TicketExpired { .. }
            | Self::TicketProcessExited { .. }
            | Self::TicketPeerMismatch { .. }
            | Self::TicketReplayed { .. }
            | Self::UnsupportedHookProtocol { .. } => StatusCode::InvalidArguments,
            Self::ReadArtifact { .. } => StatusCode::External,
            Self::FilesystemProjection { source, .. } => source.status_code(),
            Self::TicketRegistryLock { .. } | Self::PromptReconciliationStateLock { .. } => {
                StatusCode::Internal
            }
            Self::HookBrokerIo { .. } => StatusCode::External,
            Self::Pidfd { .. } => StatusCode::External,
            Self::HookBrokerProtocol { .. }
            | Self::InvalidHookEvent { .. }
            | Self::HookRejected { .. }
            | Self::AppServerTransportProtocol { .. } => StatusCode::InvalidArguments,
            Self::AppServerTransportIo { .. } => StatusCode::External,
            Self::AppServerTransportContext { source, .. } => source.status_code(),
            Self::AppServerTransportChildExit { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::ReadArtifact { source, .. } => RetryHint::from_io_error(source),
            Self::FilesystemProjection { source, .. } => source.retry_hint(),
            Self::IncompatibleProfile { .. }
            | Self::ArtifactDigestMismatch { .. }
            | Self::ArtifactDirectoryUnsafe { .. }
            | Self::ArtifactNotFleetProtected { .. }
            | Self::TicketRegistryLock { .. }
            | Self::PromptReconciliationStateLock { .. }
            | Self::TicketNotFound { .. }
            | Self::TicketExpired { .. }
            | Self::TicketProcessExited { .. }
            | Self::TicketPeerMismatch { .. }
            | Self::TicketReplayed { .. }
            | Self::UnsupportedHookProtocol { .. } => RetryHint::NonRetryable,
            Self::HookBrokerIo { source, .. } => RetryHint::from_io_error(source),
            Self::Pidfd { source, .. } => RetryHint::from_io_error(source),
            Self::HookBrokerProtocol { .. }
            | Self::InvalidHookEvent { .. }
            | Self::HookRejected { .. }
            | Self::AppServerTransportProtocol { .. }
            | Self::AppServerTransportChildExit { .. } => RetryHint::NonRetryable,
            Self::AppServerTransportContext { source, .. } => source.retry_hint(),
            Self::AppServerTransportIo { source, .. } => RetryHint::from_io_error(source),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
