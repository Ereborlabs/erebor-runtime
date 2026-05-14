//! Core enforcement loop contracts for erebor-runtime.

mod engine;
mod error;
#[cfg(test)]
mod tests;

pub use engine::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DenyApprovalProvider, EnforcementOutcome, LocalEnforcementEngine, NoopAuditSink,
};
pub use error::RuntimeError;
