use std::{any::Any, io, path::PathBuf};

use erebor_runtime_context::ContextRepositoryError;
use erebor_runtime_core::AuditError;
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
    #[snafu(display("Codex hook registry lock failed"))]
    HookRegistryLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex prompt-reconciliation state lock failed"))]
    PromptReconciliationStateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex Context DAG state lock failed"))]
    ContextDagStateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex invocation-lease state lock failed"))]
    InvocationLeaseStateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to durably record a Codex invocation-lease fact: {source}"))]
    InvocationLeaseAudit {
        source: AuditError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook peer identity was already authenticated"))]
    HookPeerReplayed {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook broker I/O failed: {source}"))]
    HookBrokerIo {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Codex hook broker RPC failed: {reason}"))]
    HookBrokerProtocol {
        reason: String,
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
    #[snafu(display("failed to record durable Codex Context DAG evidence: {source}"))]
    ContextDag {
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
            | Self::HookPeerReplayed { .. } => StatusCode::InvalidArguments,
            Self::FilesystemProjection { source, .. } => source.status_code(),
            Self::HookRegistryLock { .. }
            | Self::PromptReconciliationStateLock { .. }
            | Self::ContextDagStateLock { .. }
            | Self::InvocationLeaseStateLock { .. } => StatusCode::Internal,
            Self::InvocationLeaseAudit { source, .. } => source.status_code(),
            Self::HookBrokerIo { .. } => StatusCode::External,
            Self::HookBrokerProtocol { .. }
            | Self::InvalidHookEvent { .. }
            | Self::HookRejected { .. }
            | Self::AppServerTransportProtocol { .. } => StatusCode::InvalidArguments,
            Self::AppServerTransportIo { .. } => StatusCode::External,
            Self::AppServerTransportContext { source, .. } | Self::ContextDag { source, .. } => {
                source.status_code()
            }
            Self::AppServerTransportChildExit { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::FilesystemProjection { source, .. } => source.retry_hint(),
            Self::IncompatibleProfile { .. }
            | Self::ArtifactDigestMismatch { .. }
            | Self::ArtifactDirectoryUnsafe { .. }
            | Self::ArtifactNotFleetProtected { .. }
            | Self::HookRegistryLock { .. }
            | Self::PromptReconciliationStateLock { .. }
            | Self::ContextDagStateLock { .. }
            | Self::InvocationLeaseStateLock { .. }
            | Self::HookPeerReplayed { .. } => RetryHint::NonRetryable,
            Self::InvocationLeaseAudit { source, .. } => source.retry_hint(),
            Self::HookBrokerIo { source, .. } => RetryHint::from_io_error(source),
            Self::HookBrokerProtocol { .. }
            | Self::InvalidHookEvent { .. }
            | Self::HookRejected { .. }
            | Self::AppServerTransportProtocol { .. }
            | Self::AppServerTransportChildExit { .. } => RetryHint::NonRetryable,
            Self::AppServerTransportContext { source, .. } | Self::ContextDag { source, .. } => {
                source.retry_hint()
            }
            Self::AppServerTransportIo { source, .. } => RetryHint::from_io_error(source),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
