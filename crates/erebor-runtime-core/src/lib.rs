//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod runtime;
mod session;
#[cfg(test)]
mod tests;

pub use config::{
    docker_container_name_for_session, validate_policy_path, BrowserCdpSurfaceConfig,
    BrowserCdpSurfaceLayerConfig, BrowserLaunchConfig, BrowserLaunchLayerConfig,
    DockerSessionCommandOptions, DockerSessionCommandPlan, DockerSessionMount,
    DockerSessionRunnerConfig, DockerSessionRunnerLayerConfig, LinuxHostSessionCommandOptions,
    LinuxHostSessionCommandPlan, LinuxHostSessionRunnerConfig, LinuxHostSessionRunnerLayerConfig,
    ProcessMediationCompatibilityConfig, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEndpointSource, ProcessMediationEnvironmentConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerConfig,
    ProcessMediationHandlerKind, ProcessMediationHandlerLayerConfig, ProcessMediationMatcherConfig,
    ProcessMediationMatcherLayerConfig, ProcessMediationReplacementConfig,
    ProcessMediationReplacementLayerConfig, ProcessMediationReplacementSurface,
    ProcessMediationRequestedEndpointConfig, ProcessMediationRequestedEndpointLayerConfig,
    RuntimeAuditConfig, RuntimeConfig, SessionActorLayerConfig, SessionAdoptPlan,
    SessionDiagnosticLayerConfig, SessionLayerConfig, SessionRunPlan, SessionRunnerConfig,
    SessionRunnerKind, SessionRunnerLayerConfig, SessionSurfaceKind, SessionSurfaceLayers,
    SessionSurfaceStartPlan, SessionSurfaceToggleConfig, TerminalProcessGuardBackend,
    TerminalProcessGuardConfig, TerminalProcessGuardLayerConfig, TerminalProcessMediationConfig,
    TerminalProcessMediationLayerConfig, TerminalProcessMediationMode, TerminalSurfaceConfig,
    TerminalSurfaceLayerConfig,
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
