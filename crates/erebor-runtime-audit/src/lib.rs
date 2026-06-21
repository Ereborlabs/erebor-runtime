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
    EvidenceTraceRequest, EvidenceTraceSink, FileEvidenceTraceSink, MarkdownEvidenceTraceRenderer,
};
pub use filter::{
    should_record_audit_record, should_record_with_surface_logging, FilteredAuditSink,
};
pub use jsonl::{append_audit_record, read_audit_records, JsonlAuditSink};
pub use session_review::{
    render_session_describe, render_session_describe_from_paths, render_session_list,
    render_session_list_from_path, render_session_show, render_session_show_from_paths,
    review_session, session_summaries, SessionDecisionSummary, SessionReview,
    SessionReviewArtifacts, SessionReviewOutputFormat, SessionSummary, SessionTimelineItem,
};
