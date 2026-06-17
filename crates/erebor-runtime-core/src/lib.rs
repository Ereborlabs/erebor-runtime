//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod runtime;
mod session;
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
    SessionLayerConfig, SessionRunPlan, SessionRunnerConfig, SessionRunnerKind,
    SessionRunnerLayerConfig, SessionSurfaceKind, SessionSurfaceLayers, SessionSurfaceStartPlan,
    SessionSurfaceToggleConfig, TerminalAuditSurfaceLoggingConfig, TerminalProcessGuardBackend,
    TerminalProcessGuardConfig, TerminalProcessGuardLayerConfig, TerminalProcessInterceptionConfig,
    TerminalProcessInterceptionLayerConfig, TerminalProcessInterceptionMode,
    TerminalProcessMediationConfig, TerminalProcessMediationLayerConfig,
    TerminalProcessMediationMode, TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError};
pub use runtime::{
    RunningSessionSurface, SessionSurfaceDefinition, SessionSurfaceFailure,
    SessionSurfaceFailureSender, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
    SessionSurfaceService, SessionSurfaceSupervisor,
};
pub use session::{
    DockerSessionRunner, LinuxHostSessionRunner, SessionCapturedRunOutcome, SessionRunOutcome,
    SessionRunner, SessionRunnerLauncher,
};
