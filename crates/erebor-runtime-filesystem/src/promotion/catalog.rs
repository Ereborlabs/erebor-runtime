use crate::{
    ostree::{OstreeCommandRunner, SystemOstreeCommandRunner},
    FilesystemSessionStorage, Result,
};

use super::rollback::rollback_promotion_volumes_with_runner;

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
use load::load_catalog;
use resolve::{ensure_unique_name, resolve_target, selected_volumes, target_key, validate_name};
use state::CatalogState;

pub fn list_transaction_catalog(
    storage: &FilesystemSessionStorage,
) -> Result<FilesystemTransactionCatalog> {
    list_transaction_catalog_with_runner(storage, &SystemOstreeCommandRunner)
}

pub fn show_transaction_target(
    storage: &FilesystemSessionStorage,
    selector: &str,
) -> Result<FilesystemTransactionTarget> {
    show_transaction_target_with_runner(storage, selector, &SystemOstreeCommandRunner)
}

pub fn rename_transaction_target(
    storage: &FilesystemSessionStorage,
    selector: &str,
    name: &str,
) -> Result<FilesystemTransactionRename> {
    rename_transaction_target_with_runner(storage, selector, name, &SystemOstreeCommandRunner)
}

pub fn rollback_transaction_target(
    storage: &FilesystemSessionStorage,
    selector: &str,
) -> Result<FilesystemTransactionRollback> {
    rollback_transaction_target_with_runner(storage, selector, &SystemOstreeCommandRunner)
}

pub(crate) fn list_transaction_catalog_with_runner(
    storage: &FilesystemSessionStorage,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemTransactionCatalog> {
    load_catalog(storage, runner)
}

pub(crate) fn show_transaction_target_with_runner(
    storage: &FilesystemSessionStorage,
    selector: &str,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemTransactionTarget> {
    let catalog = load_catalog(storage, runner)?;
    resolve_target(&catalog, selector)
}

pub(crate) fn rename_transaction_target_with_runner(
    storage: &FilesystemSessionStorage,
    selector: &str,
    name: &str,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemTransactionRename> {
    let name = validate_name(name)?;
    let catalog = load_catalog(storage, runner)?;
    let target = resolve_target(&catalog, selector)?;
    let key = target_key(&target);
    ensure_unique_name(&catalog, &key, &name)?;
    let mut metadata = CatalogState::read(storage)?;
    metadata.set_name(key, name.clone());
    metadata.write(storage)?;
    metadata.append_rename_event(storage, selector, &name)?;
    Ok(FilesystemTransactionRename::new(selector, name))
}

pub(crate) fn rollback_transaction_target_with_runner(
    storage: &FilesystemSessionStorage,
    selector: &str,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemTransactionRollback> {
    let catalog = load_catalog(storage, runner)?;
    let target = resolve_target(&catalog, selector)?;
    let key = target_key(&target);
    let mut metadata = CatalogState::read(storage)?;
    let promotion_id = key.promotion_id().to_owned();
    let selected = selected_volumes(&target);
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
    let rollback =
        match rollback_promotion_volumes_with_runner(storage, &promotion_id, &pending, runner) {
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
