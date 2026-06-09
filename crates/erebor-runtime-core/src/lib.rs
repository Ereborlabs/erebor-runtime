//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
mod runtime;
#[cfg(test)]
mod tests;

pub use config::{
    validate_policy_path, BrowserCdpLayerConfig, BrowserCdpRuntimeConfig, BrowserLaunchConfig,
    BrowserLaunchLayerConfig, DockerSessionLaunchPlan, DockerSessionRuntimeConfig,
    DockerSessionRuntimeLayerConfig, GovernanceLayer, GovernanceLayerConfig, GovernanceLayers,
    RuntimeAuditConfig, RuntimeConfig, RuntimeStartPlan, SessionActorLayerConfig,
    SessionDiagnosticLayerConfig, SessionLayerConfig, SessionRunPlan, SessionRuntimeConfig,
    SessionRuntimeKind, SessionRuntimeLayerConfig,
};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError};
pub use runtime::{
    GovernanceRuntime, RunningRuntime, RuntimeDefinition, RuntimeFailure, RuntimeFailureSender,
    RuntimeLaunchPlan, RuntimeLauncher, RuntimeSupervisor,
};
