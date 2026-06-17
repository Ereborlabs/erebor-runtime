//! Audit log sinks and readers for erebor-runtime.

mod error;
mod evidence_trace;
mod jsonl;
#[cfg(test)]
mod tests;

pub use error::{AuditLogError, EvidenceTraceError};
pub use evidence_trace::{
    EvidenceTraceArtifact, EvidenceTracePaths, EvidenceTraceReceipt, EvidenceTraceReport,
    EvidenceTraceRequest, EvidenceTraceSink, FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer,
};
pub use jsonl::{append_audit_record, read_audit_records, JsonlAuditSink};
