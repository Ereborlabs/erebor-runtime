use crate::{
    ostree::{OstreeRepository, SystemOstreeRepository},
    FilesystemSessionStorage, Result,
};

use super::FilesystemRollback;

mod journal;
mod load;
mod model;
mod resolve;
mod state;

pub use model::{
    FilesystemSubtransaction, FilesystemSubtransactionState, FilesystemTransaction,
    FilesystemTransactionCatalog, FilesystemTransactionChange, FilesystemTransactionRename,
    FilesystemTransactionRollback, FilesystemTransactionState, FilesystemTransactionTarget,
};

use journal::CatalogRollbackJournal;
use load::TransactionCatalogLoader;
use resolve::{CatalogTargetResolver, TransactionTargetName};
use state::CatalogState;

impl FilesystemTransactionCatalog {
    pub fn load(storage: &FilesystemSessionStorage) -> Result<Self> {
        Self::load_using_repository(storage, &SystemOstreeRepository)
    }

    pub(crate) fn load_using_repository(
        storage: &FilesystemSessionStorage,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        TransactionCatalogLoader::new(storage, repository)?.load()
    }
}

impl FilesystemTransactionTarget {
    pub fn show(storage: &FilesystemSessionStorage, selector: &str) -> Result<Self> {
        Self::show_using_repository(storage, selector, &SystemOstreeRepository)
    }

    pub(crate) fn show_using_repository(
        storage: &FilesystemSessionStorage,
        selector: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let catalog = FilesystemTransactionCatalog::load_using_repository(storage, repository)?;
        CatalogTargetResolver::new(&catalog).resolve(selector)
    }
}

impl FilesystemTransactionRename {
    pub fn rename(storage: &FilesystemSessionStorage, selector: &str, name: &str) -> Result<Self> {
        Self::rename_using_repository(storage, selector, name, &SystemOstreeRepository)
    }

    pub(crate) fn rename_using_repository(
        storage: &FilesystemSessionStorage,
        selector: &str,
        name: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let catalog = FilesystemTransactionCatalog::load_using_repository(storage, repository)?;
        let resolver = CatalogTargetResolver::new(&catalog);
        let target = resolver.resolve(selector)?;
        let key = target.catalog_key();
        let name = TransactionTargetName::new(name)?;
        resolver.ensure_unique_name(&key, &name)?;
        let name = name.into_string();
        let mut metadata = CatalogState::read(storage)?;
        metadata.set_name(key, name.clone());
        metadata.write(storage)?;
        metadata.append_rename_event(storage, selector, &name)?;
        Ok(FilesystemTransactionRename::new(selector, name))
    }
}

impl FilesystemTransactionRollback {
    pub fn rollback(storage: &FilesystemSessionStorage, selector: &str) -> Result<Self> {
        Self::rollback_using_repository(storage, selector, &SystemOstreeRepository)
    }

    pub(crate) fn rollback_using_repository(
        storage: &FilesystemSessionStorage,
        selector: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        let catalog = FilesystemTransactionCatalog::load_using_repository(storage, repository)?;
        let target = CatalogTargetResolver::new(&catalog).resolve(selector)?;
        let key = target.catalog_key();
        let mut metadata = CatalogState::read(storage)?;
        let promotion_id = key.promotion_id().to_owned();
        let selected = target.selected_volumes();
        let pending = selected
            .iter()
            .filter(|volume_id| !metadata.is_restored(&promotion_id, volume_id))
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            metadata.append_rollback_event(
                storage,
                CatalogRollbackJournal::already_restored(selector, &promotion_id, &selected),
            )?;
            return Ok(FilesystemTransactionRollback::new(
                promotion_id,
                selector,
                Vec::new(),
            ));
        }
        let rollback = match FilesystemRollback::rollback_promotion_volumes_using_repository(
            storage,
            &promotion_id,
            &pending,
            repository,
        ) {
            Ok(rollback) => rollback,
            Err(error) => {
                metadata.append_rollback_event(
                    storage,
                    CatalogRollbackJournal::failed(
                        selector,
                        &promotion_id,
                        &selected,
                        &pending,
                        error.to_string(),
                    ),
                )?;
                return Err(error);
            }
        };
        for volume_id in rollback.restored_volumes() {
            metadata.mark_restored(&promotion_id, volume_id);
        }
        metadata.write(storage)?;
        metadata.append_rollback_event(
            storage,
            CatalogRollbackJournal::succeeded(
                selector,
                &promotion_id,
                &selected,
                rollback.restored_volumes(),
            ),
        )?;
        Ok(FilesystemTransactionRollback::new(
            promotion_id,
            selector,
            rollback.restored_volumes().to_vec(),
        ))
    }
}
