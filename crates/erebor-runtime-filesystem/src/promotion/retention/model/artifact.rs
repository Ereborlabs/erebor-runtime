use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetainedRef {
    kind: FilesystemRetainedRefKind,
    promotion_id: String,
    volume_id: Option<String>,
    reference: String,
    status: FilesystemRetainedArtifactStatus,
    required_for_rollback: bool,
    protected: bool,
}

impl FilesystemRetainedRef {
    pub(in crate::promotion::retention) fn new(
        kind: FilesystemRetainedRefKind,
        promotion_id: impl Into<String>,
        volume_id: Option<String>,
        reference: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            promotion_id: promotion_id.into(),
            volume_id,
            reference: reference.into(),
            status: FilesystemRetainedArtifactStatus::Present,
            required_for_rollback: false,
            protected: false,
        }
    }

    pub(in crate::promotion::retention) const fn with_status(
        mut self,
        status: FilesystemRetainedArtifactStatus,
    ) -> Self {
        self.status = status;
        self
    }

    pub(in crate::promotion::retention) const fn require_rollback(
        mut self,
        required: bool,
    ) -> Self {
        self.required_for_rollback = required;
        self
    }

    pub(in crate::promotion::retention) const fn protect(mut self, protected: bool) -> Self {
        self.protected = protected;
        self
    }

    #[must_use]
    pub const fn kind(&self) -> FilesystemRetainedRefKind {
        self.kind
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn volume_id(&self) -> Option<&str> {
        self.volume_id.as_deref()
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub const fn status(&self) -> FilesystemRetainedArtifactStatus {
        self.status
    }

    #[must_use]
    pub const fn required_for_rollback(&self) -> bool {
        self.required_for_rollback
    }

    #[must_use]
    pub const fn protected(&self) -> bool {
        self.protected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemRetainedRefKind {
    CheckpointManifest,
    CheckpointLayer,
    PromotionManifest,
    PromotionPreimage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemRetainedLocalArtifact {
    kind: FilesystemRetainedLocalKind,
    promotion_id: Option<String>,
    volume_id: Option<String>,
    path: PathBuf,
    status: FilesystemRetainedArtifactStatus,
    required_for_rollback: bool,
    protected: bool,
}

impl FilesystemRetainedLocalArtifact {
    pub(in crate::promotion::retention) fn new(
        kind: FilesystemRetainedLocalKind,
        promotion_id: Option<String>,
        volume_id: Option<String>,
        path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            kind,
            promotion_id,
            volume_id,
            path: path.into(),
            status: FilesystemRetainedArtifactStatus::Missing,
            required_for_rollback: false,
            protected: false,
        }
    }

    pub(in crate::promotion::retention) fn detect(mut self) -> Self {
        if self.path.exists() {
            self.status = FilesystemRetainedArtifactStatus::Present;
        }
        self
    }

    pub(in crate::promotion::retention) const fn require_rollback(
        mut self,
        required: bool,
    ) -> Self {
        self.required_for_rollback = required;
        self
    }

    pub(in crate::promotion::retention) const fn protect(mut self, protected: bool) -> Self {
        self.protected = protected;
        self
    }

    #[must_use]
    pub const fn kind(&self) -> FilesystemRetainedLocalKind {
        self.kind
    }

    #[must_use]
    pub fn promotion_id(&self) -> Option<&str> {
        self.promotion_id.as_deref()
    }

    #[must_use]
    pub fn volume_id(&self) -> Option<&str> {
        self.volume_id.as_deref()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn status(&self) -> FilesystemRetainedArtifactStatus {
        self.status
    }

    #[must_use]
    pub const fn required_for_rollback(&self) -> bool {
        self.required_for_rollback
    }

    #[must_use]
    pub const fn protected(&self) -> bool {
        self.protected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemRetainedLocalKind {
    PromotionWorkdir,
    RollbackCheckout,
    CowPreimageArtifact,
    PromotionLock,
    TransactionCatalogJournal,
    RetentionJournal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemRetainedArtifactStatus {
    Present,
    Missing,
    Corrupt,
}
