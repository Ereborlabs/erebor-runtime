use crate::{
    ostree::{OstreeRepository, SystemOstreeRepository},
    FilesystemSessionStorage, Result,
};

mod inventory;
mod journal;
mod model;
mod prune;
mod resolve;

pub use model::{
    FilesystemOstreePrune, FilesystemRetainedArtifactStatus, FilesystemRetainedLocalArtifact,
    FilesystemRetainedLocalKind, FilesystemRetainedRef, FilesystemRetainedRefKind,
    FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemRetentionState,
    FilesystemRetentionSubtransaction, FilesystemRetentionTransaction,
};

use inventory::RetentionInventoryLoader;
use journal::RetentionJournal;
use prune::RetentionPruner;

impl FilesystemRetentionInventory {
    pub fn load(storage: &FilesystemSessionStorage) -> Result<Self> {
        Self::load_using_repository(storage, &SystemOstreeRepository)
    }

    pub(crate) fn load_using_repository(
        storage: &FilesystemSessionStorage,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let inventory = RetentionInventoryLoader::new(storage, repository)?.load()?;
        RetentionJournal::new(storage).append_list(&inventory)?;
        Ok(inventory)
    }
}

impl FilesystemRetentionPrune {
    pub fn prune(storage: &FilesystemSessionStorage, selector: &str) -> Result<Self> {
        Self::prune_using_repository(storage, selector, &SystemOstreeRepository)
    }

    pub(crate) fn prune_using_repository(
        storage: &FilesystemSessionStorage,
        selector: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        RetentionPruner::new(storage, repository).prune(selector)
    }
}
