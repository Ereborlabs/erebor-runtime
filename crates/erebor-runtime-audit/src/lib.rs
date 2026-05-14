//! Audit log sinks and readers for erebor-runtime.

mod error;
mod jsonl;
#[cfg(test)]
mod tests;

pub use error::AuditLogError;
pub use jsonl::{append_audit_record, read_audit_records, JsonlAuditSink};
