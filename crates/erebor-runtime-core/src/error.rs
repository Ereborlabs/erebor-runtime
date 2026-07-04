mod config;
mod runtime;
mod session_registry;

pub use config::RuntimeConfigError;
pub use runtime::RuntimeError;
pub use session_registry::SessionRegistryError;

pub(crate) use config::{
    BrowserCdpInvalidBrowserUrlSnafu, DuplicateSessionDiagnosticNameSnafu,
    EmptyAuditDebugMatcherSnafu, EmptyConfigSnafu, EmptyDockerSessionImageSnafu,
    EmptyDockerSessionNetworkSnafu, EmptyPolicyPathSnafu, EmptySessionActorIdSnafu,
    EmptySessionCommandSnafu, EmptySessionDiagnosticCommandSnafu, EmptySessionDiagnosticNameSnafu,
    EmptySessionWorkspaceSnafu, InvalidJsonSnafu, InvalidProcessMediationConfigSnafu,
    InvalidSessionAdoptPidSnafu, InvalidSessionInterceptionConfigSnafu, MissingPolicySnafu,
    NoSessionSurfacesSnafu, UnknownSessionDiagnosticSnafu,
};
pub(crate) use runtime::{
    BuildAsyncRuntimeSnafu, NoSessionSurfaceServicesSnafu, PolicySnafu, SessionRunnerExitSnafu,
    SessionRunnerLaunchSnafu, SurfaceExitedSnafu, UnsupportedSessionRunnerOperationSnafu,
    UnsupportedSessionSurfaceSnafu,
};
pub(crate) use session_registry::{
    CopyArtifactSnafu, CreateDirSnafu, DecodeRecordSnafu, EncodeRecordSnafu, ReadRecordSnafu,
    UnknownSessionSnafu, WriteRecordSnafu,
};
