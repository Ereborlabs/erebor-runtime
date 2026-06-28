//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod runtime;
mod session;
mod session_registry;
#[cfg(test)]
mod tests;

pub use config::{
    docker_container_name_for_session, validate_policy_path, AuditCommandLogLevel,
    BrowserCdpAuditSurfaceLoggingConfig, BrowserCdpSurfaceConfig, BrowserCdpSurfaceLayerConfig,
    BrowserLaunchConfig, BrowserLaunchLayerConfig, DesktopAuditSurfaceLoggingConfig,
    DockerSessionCommandOptions, DockerSessionCommandPlan, DockerSessionMount,
    DockerSessionRunnerConfig, DockerSessionRunnerLayerConfig,
    InternalSystemAuditSurfaceLoggingConfig, LinuxHostSessionCommandOptions,
    LinuxHostSessionCommandPlan, LinuxHostSessionRunnerConfig, LinuxHostSessionRunnerLayerConfig,
    McpAuditSurfaceLoggingConfig, NetworkAuditSurfaceLoggingConfig, ProcessInterceptionDecision,
    ProcessInterceptionHandlerConfig, ProcessInterceptionHandlerKind,
    ProcessMediationCompatibilityConfig, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEndpointSource, ProcessMediationEnvironmentConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerConfig,
    ProcessMediationHandlerKind, ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationPrivateEndpointConfig,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementConfig, ProcessMediationReplacementLayerConfig,
    ProcessMediationReplacementSurface, ProcessMediationRequestedEndpointConfig,
    ProcessMediationRequestedEndpointLayerConfig, RuntimeAuditConfig,
    RuntimeAuditSurfaceLoggingConfig, RuntimeConfig, SaaSAuditSurfaceLoggingConfig,
    SessionActorLayerConfig, SessionAdoptPlan, SessionAdoptTarget, SessionDiagnosticLayerConfig,
    SessionInterceptionBackendKind, SessionInterceptionCapabilityReport, SessionInterceptionConfig,
    SessionInterceptionConfigSource, SessionInterceptionLayerConfig, SessionInterceptionOperation,
    SessionInterceptionOperationCapability, SessionLayerConfig, SessionRunPlan,
    SessionRunnerConfig, SessionRunnerKind, SessionRunnerLayerConfig, SessionSurfaceKind,
    SessionSurfaceLayers, SessionSurfaceStartPlan, SessionSurfaceToggleConfig,
    TerminalAuditSurfaceLoggingConfig, TerminalProcessInterceptionConfig,
    TerminalProcessInterceptionLayerConfig, TerminalProcessInterceptionMode,
    TerminalProcessMediationConfig, TerminalProcessMediationLayerConfig,
    TerminalProcessMediationMode, TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError, SessionRegistryError};
pub use runtime::{
    RunningSessionSurface, SessionSurfaceDefinition, SessionSurfaceFailure,
    SessionSurfaceFailureSender, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
    SessionSurfaceService, SessionSurfaceSupervisor,
};
pub use session::{
    DockerSessionRunner, LinuxHostSessionRunner, SessionCapturedRunOutcome, SessionRunOutcome,
    SessionRunner, SessionRunnerLauncher,
};
pub use session_registry::{
    SessionRegistry, SessionRegistryFinish, SessionRegistryRecord, SessionRegistryStatus,
    StartedSessionRegistryRecord, DEFAULT_SESSION_REGISTRY_PATH,
};
