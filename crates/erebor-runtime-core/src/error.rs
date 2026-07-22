mod config;
mod runtime;
mod session_registry;
pub(crate) mod session_spec;

pub use config::RuntimeConfigError;
pub use runtime::RuntimeError;
pub use session_registry::SessionRegistryError;
pub use session_spec::SessionSpecError;

pub(crate) use config::{
    BrowserCdpInvalidBrowserUrlSnafu, DuplicateSessionDiagnosticNameSnafu,
    EmptyAuditDebugMatcherSnafu, EmptyConfigSnafu, EmptyDockerSessionImageSnafu,
    EmptyDockerSessionNetworkSnafu, EmptyPolicyPathSnafu, EmptySessionActorIdSnafu,
    EmptySessionCommandSnafu, EmptySessionDiagnosticCommandSnafu, EmptySessionDiagnosticNameSnafu,
    EmptySessionWorkspaceSnafu, InvalidFilesystemSurfaceConfigSnafu, InvalidJsonSnafu,
    InvalidProcessMediationConfigSnafu, InvalidSessionAdoptPidSnafu,
    InvalidSessionInterceptionConfigSnafu, MissingPolicySnafu, NoSessionSurfacesSnafu,
    UnknownSessionDiagnosticSnafu,
};
pub(crate) use runtime::{
    BuildAsyncRuntimeSnafu, ContextSessionMismatchSnafu, DurableAuditSnafu,
    NoSessionSurfaceServicesSnafu, PolicySnafu, SessionRunnerExitSnafu, SessionRunnerLaunchSnafu,
    SurfaceExitedSnafu, UnsupportedSessionRunnerOperationSnafu, UnsupportedSessionSurfaceSnafu,
};
pub(crate) use session_registry::{
    ContextArtifactSymlinkSnafu, ContextRepositorySnafu, CopyArtifactSnafu, CreateDirSnafu,
    DecodeRecordSnafu, EncodeRecordSnafu, InspectContextArtifactSnafu,
    InvalidContextArtifactMetadataSnafu, InvalidContextArtifactPathSnafu,
    InvalidSessionDirectoryNameSnafu, MissingContextArtifactSnafu, ReadRecordSnafu,
    SessionDirectoryCollisionSnafu, SessionDirectoryMismatchSnafu, SessionDirectoryOccupiedSnafu,
    SessionDirectorySymlinkSnafu, SessionIdMismatchSnafu, UnknownSessionSnafu, WriteRecordSnafu,
};
