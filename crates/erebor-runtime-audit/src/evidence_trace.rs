//! Evidence traces derived from governed session audit logs.
//!
//! JSONL audit records are the source of truth. This module turns those records,
//! plus the policy/config artifacts for the same run, into DPO-readable
//! evidence traces and routes them through sink abstractions.

mod artifacts;
mod redaction;
mod render;
mod report;
mod request;
mod sink;
mod source;
#[cfg(test)]
mod test_support;

pub(crate) use artifacts::{EvidenceHasher, EvidenceTraceArtifactLoader};
pub(crate) use redaction::EvidenceRedactor;
pub(crate) use request::EvidenceTraceSessionSummary;

pub use artifacts::EvidenceTraceArtifact;
pub use render::MarkdownEvidenceTraceRenderer;
pub use report::{EvidenceTraceReceipt, EvidenceTraceReport};
pub use request::EvidenceTraceRequest;
pub use sink::{EvidenceTraceSink, FileEvidenceTraceSink};
pub use source::{EvidenceTracePaths, EvidenceTraceSource};
