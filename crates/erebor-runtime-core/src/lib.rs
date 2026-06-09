//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod runtime;
mod session;
#[cfg(test)]
mod tests;

pub use config::{
    validate_policy_path, BrowserCdpSurfaceConfig, BrowserCdpSurfaceLayerConfig,
    BrowserLaunchConfig, BrowserLaunchLayerConfig, DockerSessionCommandPlan,
    DockerSessionRunnerConfig, DockerSessionRunnerLayerConfig, RuntimeAuditConfig, RuntimeConfig,
    SessionActorLayerConfig, SessionDiagnosticLayerConfig, SessionLayerConfig, SessionRunPlan,
    SessionRunnerConfig, SessionRunnerKind, SessionRunnerLayerConfig, SessionSurfaceKind,
    SessionSurfaceLayers, SessionSurfaceStartPlan, SessionSurfaceToggleConfig,
    TerminalSurfaceConfig, TerminalSurfaceLayerConfig,
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
    terminal_process_event, DockerSessionRunner, SessionRunOutcome, SessionRunner,
    SessionRunnerLauncher, TerminalSessionAuthorization, TerminalSessionSurface,
};
