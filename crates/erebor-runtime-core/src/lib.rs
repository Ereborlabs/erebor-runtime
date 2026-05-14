//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
#[cfg(test)]
mod tests;

pub use config::{
    validate_policy_path, GovernanceLayer, GovernanceLayerConfig, GovernanceLayers, RuntimeConfig,
    RuntimeStartPlan,
};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError};
