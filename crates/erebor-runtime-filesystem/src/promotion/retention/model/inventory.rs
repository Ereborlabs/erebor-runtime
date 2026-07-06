use serde::Serialize;

use super::{FilesystemRetainedLocalArtifact, FilesystemRetainedRef};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetentionInventory {
    transactions: Vec<FilesystemRetentionTransaction>,
    loose_refs: Vec<FilesystemRetainedRef>,
    local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
}

impl FilesystemRetentionInventory {
    pub(in crate::promotion::retention) fn new(
        transactions: Vec<FilesystemRetentionTransaction>,
        loose_refs: Vec<FilesystemRetainedRef>,
        local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
    ) -> Self {
        Self {
            transactions,
            loose_refs,
            local_artifacts,
        }
    }

    #[must_use]
    pub fn transactions(&self) -> &[FilesystemRetentionTransaction] {
        &self.transactions
    }

    #[must_use]
    pub fn loose_refs(&self) -> &[FilesystemRetainedRef] {
        &self.loose_refs
    }

    #[must_use]
    pub fn local_artifacts(&self) -> &[FilesystemRetainedLocalArtifact] {
        &self.local_artifacts
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetentionTransaction {
    handle: String,
    promotion_id: String,
    name: Option<String>,
    state: FilesystemRetentionState,
    refs: Vec<FilesystemRetainedRef>,
    local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
    subtransactions: Vec<FilesystemRetentionSubtransaction>,
}

impl FilesystemRetentionTransaction {
    pub(in crate::promotion::retention) fn new(
        handle: String,
        promotion_id: String,
        name: Option<String>,
        state: FilesystemRetentionState,
        refs: Vec<FilesystemRetainedRef>,
        local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
        subtransactions: Vec<FilesystemRetentionSubtransaction>,
    ) -> Self {
        Self {
            handle,
            promotion_id,
            name,
            state,
            refs,
            local_artifacts,
            subtransactions,
        }
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub const fn state(&self) -> FilesystemRetentionState {
        self.state
    }

    #[must_use]
    pub fn refs(&self) -> &[FilesystemRetainedRef] {
        &self.refs
    }

    #[must_use]
    pub fn local_artifacts(&self) -> &[FilesystemRetainedLocalArtifact] {
        &self.local_artifacts
    }

    #[must_use]
    pub fn subtransactions(&self) -> &[FilesystemRetentionSubtransaction] {
        &self.subtransactions
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetentionSubtransaction {
    handle: String,
    promotion_id: String,
    volume_id: String,
    name: Option<String>,
    state: FilesystemRetentionState,
    refs: Vec<FilesystemRetainedRef>,
    local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
}

impl FilesystemRetentionSubtransaction {
    pub(in crate::promotion::retention) fn new(
        handle: String,
        promotion_id: String,
        volume_id: String,
        name: Option<String>,
        state: FilesystemRetentionState,
        refs: Vec<FilesystemRetainedRef>,
        local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
    ) -> Self {
        Self {
            handle,
            promotion_id,
            volume_id,
            name,
            state,
            refs,
            local_artifacts,
        }
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub const fn state(&self) -> FilesystemRetentionState {
        self.state
    }

    #[must_use]
    pub fn refs(&self) -> &[FilesystemRetainedRef] {
        &self.refs
    }

    #[must_use]
    pub fn local_artifacts(&self) -> &[FilesystemRetainedLocalArtifact] {
        &self.local_artifacts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemRetentionState {
    Applied,
    PartiallyRestored,
    Restored,
    Corrupt,
}
