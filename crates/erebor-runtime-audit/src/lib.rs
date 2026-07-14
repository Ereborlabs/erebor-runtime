//! Audit log sinks and readers for erebor-runtime.

mod error;
mod evidence_trace;
mod filter;
mod jsonl;
mod session_review;
#[cfg(test)]
mod tests;

pub use error::{AuditLogError, EvidenceTraceError, SessionReviewError};
pub use evidence_trace::{
    EvidenceTraceArtifact, EvidenceTracePaths, EvidenceTraceReceipt, EvidenceTraceReport,
    EvidenceTraceRequest, EvidenceTraceSink, EvidenceTraceSource, FileEvidenceTraceSink,
    MarkdownEvidenceTraceRenderer,
};
pub use filter::{AuditFilter, FilteredAuditSink};
pub use jsonl::{
    append_audit_record, append_durable_audit_record, read_audit_records, JsonlAuditSink,
};
pub use session_review::{
    SessionDecisionSummary, SessionReview, SessionReviewArtifacts, SessionReviewOutputFormat,
    SessionReviewRenderer, SessionReviewSource, SessionSummary, SessionSummaryBuilder,
    SessionTimelineItem,
};
