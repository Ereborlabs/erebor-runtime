//! Core enforcement loop contracts for erebor-runtime.

mod config;
mod engine;
mod error;
#[cfg(test)]
mod tests;

pub use config::{GovernanceLayer, GovernanceLayerConfig, GovernanceLayers, RuntimeConfig};
pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::{RuntimeConfigError, RuntimeError};
