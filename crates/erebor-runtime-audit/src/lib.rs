//! Audit log sinks and readers for erebor-runtime.

mod error;
mod evidence_trace;
mod filter;
mod jsonl;
#[cfg(test)]
mod tests;

pub use error::{AuditLogError, EvidenceTraceError};
pub use evidence_trace::{
    EvidenceTraceArtifact, EvidenceTracePaths, EvidenceTraceReceipt, EvidenceTraceReport,
    EvidenceTraceRequest, EvidenceTraceSink, FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer,
};
pub use filter::{
    should_record_audit_record, should_record_with_surface_logging, FilteredAuditSink,
};
pub use jsonl::{append_audit_record, read_audit_records, JsonlAuditSink};
