mod artifacts;
mod decisions;
mod record;
mod render;
mod source;
mod summary;
#[cfg(test)]
mod test_support;
mod timeline;

pub use artifacts::SessionReviewArtifacts;
pub use decisions::SessionDecisionSummary;
pub use render::{SessionReviewOutputFormat, SessionReviewRenderer};
pub use source::SessionReviewSource;
pub use summary::{SessionSummary, SessionSummaryBuilder};
pub use timeline::SessionTimelineItem;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SessionReview {
    pub summary: SessionSummary,
    pub important_decisions: Vec<SessionDecisionSummary>,
    pub timeline: Vec<SessionTimelineItem>,
    pub policy_sha256: Option<String>,
    pub config_sha256: Option<String>,
}
