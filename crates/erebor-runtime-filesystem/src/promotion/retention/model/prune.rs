use serde::Serialize;

use crate::ostree::OstreePruneSummary;

use super::{FilesystemRetainedLocalArtifact, FilesystemRetainedRef};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetentionPrune {
    selector: String,
    pruned_refs: Vec<FilesystemRetainedRef>,
    skipped_refs: Vec<FilesystemRetainedRef>,
    pruned_local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
    skipped_local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
    ostree_prune: FilesystemOstreePrune,
}

impl FilesystemRetentionPrune {
    pub(in crate::promotion::retention) fn new(
        selector: impl Into<String>,
        pruned_refs: Vec<FilesystemRetainedRef>,
        skipped_refs: Vec<FilesystemRetainedRef>,
        pruned_local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
        skipped_local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
        ostree_prune: FilesystemOstreePrune,
    ) -> Self {
        Self {
            selector: selector.into(),
            pruned_refs,
            skipped_refs,
            pruned_local_artifacts,
            skipped_local_artifacts,
            ostree_prune,
        }
    }

    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    #[must_use]
    pub fn pruned_refs(&self) -> &[FilesystemRetainedRef] {
        &self.pruned_refs
    }

    #[must_use]
    pub fn skipped_refs(&self) -> &[FilesystemRetainedRef] {
        &self.skipped_refs
    }

    #[must_use]
    pub fn pruned_local_artifacts(&self) -> &[FilesystemRetainedLocalArtifact] {
        &self.pruned_local_artifacts
    }

    #[must_use]
    pub fn skipped_local_artifacts(&self) -> &[FilesystemRetainedLocalArtifact] {
        &self.skipped_local_artifacts
    }

    #[must_use]
    pub const fn ostree_prune(&self) -> FilesystemOstreePrune {
        self.ostree_prune
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemOstreePrune {
    objects_total: i32,
    objects_pruned: i32,
    pruned_object_size_total: u64,
}

impl FilesystemOstreePrune {
    pub(in crate::promotion::retention) const fn empty() -> Self {
        Self {
            objects_total: 0,
            objects_pruned: 0,
            pruned_object_size_total: 0,
        }
    }

    pub(in crate::promotion::retention) const fn from_summary(summary: OstreePruneSummary) -> Self {
        Self {
            objects_total: summary.objects_total(),
            objects_pruned: summary.objects_pruned(),
            pruned_object_size_total: summary.pruned_object_size_total(),
        }
    }

    #[must_use]
    pub const fn objects_total(self) -> i32 {
        self.objects_total
    }

    #[must_use]
    pub const fn objects_pruned(self) -> i32 {
        self.objects_pruned
    }

    #[must_use]
    pub const fn pruned_object_size_total(self) -> u64 {
        self.pruned_object_size_total
    }
}
