use std::collections::BTreeSet;

use snafu::ensure;

use crate::Result;

use super::{
    model::{FilesystemTransactionCatalog, FilesystemTransactionTarget},
    state::CatalogTargetKey,
};

pub(super) fn resolve_target(
    catalog: &FilesystemTransactionCatalog,
    selector: &str,
) -> Result<FilesystemTransactionTarget> {
    if let Some(target) = resolve_handle(catalog, selector) {
        return Ok(target);
    }
    resolve_name(catalog, selector)
}

pub(super) fn target_key(target: &FilesystemTransactionTarget) -> CatalogTargetKey {
    match target {
        FilesystemTransactionTarget::Transaction(transaction) => {
            CatalogTargetKey::transaction(transaction.promotion_id())
        }
        FilesystemTransactionTarget::Subtransaction(subtransaction) => {
            CatalogTargetKey::subtransaction(
                subtransaction.promotion_id(),
                subtransaction.volume_id(),
            )
        }
    }
}

pub(super) fn selected_volumes(target: &FilesystemTransactionTarget) -> Vec<String> {
    match target {
        FilesystemTransactionTarget::Transaction(transaction) => transaction
            .subtransactions()
            .iter()
            .map(|subtransaction| subtransaction.volume_id().to_owned())
            .collect(),
        FilesystemTransactionTarget::Subtransaction(subtransaction) => {
            vec![subtransaction.volume_id().to_owned()]
        }
    }
}

pub(super) fn ensure_unique_name(
    catalog: &FilesystemTransactionCatalog,
    target: &CatalogTargetKey,
    name: &str,
) -> Result<()> {
    let mut owners = BTreeSet::new();
    for transaction in catalog.transactions() {
        if transaction.name() == Some(name) {
            owners.insert(CatalogTargetKey::transaction(transaction.promotion_id()));
        }
        for subtransaction in transaction.subtransactions() {
            if subtransaction.name() == Some(name) {
                owners.insert(CatalogTargetKey::subtransaction(
                    transaction.promotion_id(),
                    subtransaction.volume_id(),
                ));
            }
        }
    }
    ensure!(
        owners.is_empty() || owners == BTreeSet::from([target.clone()]),
        crate::error::InvalidTransactionNameSnafu {
            name: name.to_owned(),
            reason: String::from("name is already used by another transaction target"),
        }
    );
    Ok(())
}

pub(super) fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    ensure!(
        !name.is_empty() && !name.contains('\n'),
        crate::error::InvalidTransactionNameSnafu {
            name: name.to_owned(),
            reason: String::from("name must be non-empty and single-line"),
        }
    );
    Ok(name.to_owned())
}

fn resolve_handle(
    catalog: &FilesystemTransactionCatalog,
    selector: &str,
) -> Option<FilesystemTransactionTarget> {
    for transaction in catalog.transactions() {
        if transaction.handle() == selector {
            return Some(FilesystemTransactionTarget::Transaction(
                transaction.clone(),
            ));
        }
        for subtransaction in transaction.subtransactions() {
            if subtransaction.handle() == selector {
                return Some(FilesystemTransactionTarget::Subtransaction(
                    subtransaction.clone(),
                ));
            }
        }
    }
    None
}

fn resolve_name(
    catalog: &FilesystemTransactionCatalog,
    selector: &str,
) -> Result<FilesystemTransactionTarget> {
    let mut matches = Vec::new();
    for transaction in catalog.transactions() {
        if transaction.name() == Some(selector) {
            matches.push(FilesystemTransactionTarget::Transaction(
                transaction.clone(),
            ));
        }
        for subtransaction in transaction.subtransactions() {
            if subtransaction.name() == Some(selector) {
                matches.push(FilesystemTransactionTarget::Subtransaction(
                    subtransaction.clone(),
                ));
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => crate::error::InvalidTransactionHandleSnafu {
            handle: selector.to_owned(),
            reason: String::from("no transaction or subtransaction matches this handle or name"),
        }
        .fail(),
        _ => crate::error::InvalidTransactionHandleSnafu {
            handle: selector.to_owned(),
            reason: String::from("transaction or subtransaction name is ambiguous"),
        }
        .fail(),
    }
}
