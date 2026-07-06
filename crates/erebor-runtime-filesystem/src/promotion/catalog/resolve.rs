use std::collections::BTreeSet;

use snafu::ensure;

use crate::Result;

use super::{
    model::{FilesystemTransactionCatalog, FilesystemTransactionTarget},
    state::CatalogTargetKey,
};

pub(super) struct CatalogTargetResolver<'a> {
    catalog: &'a FilesystemTransactionCatalog,
}

impl<'a> CatalogTargetResolver<'a> {
    pub(super) const fn new(catalog: &'a FilesystemTransactionCatalog) -> Self {
        Self { catalog }
    }

    pub(super) fn resolve(&self, selector: &str) -> Result<FilesystemTransactionTarget> {
        if let Some(target) = self.resolve_handle(selector) {
            return Ok(target);
        }
        self.resolve_name(selector)
    }

    pub(super) fn ensure_unique_name(
        &self,
        target: &CatalogTargetKey,
        name: &TransactionTargetName,
    ) -> Result<()> {
        let mut owners = BTreeSet::new();
        for transaction in self.catalog.transactions() {
            if transaction.name() == Some(name.as_str()) {
                owners.insert(CatalogTargetKey::transaction(transaction.promotion_id()));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.name() == Some(name.as_str()) {
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
                name: name.as_str().to_owned(),
                reason: String::from("name is already used by another transaction target"),
            }
        );
        Ok(())
    }

    fn resolve_handle(&self, selector: &str) -> Option<FilesystemTransactionTarget> {
        for transaction in self.catalog.transactions() {
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

    fn resolve_name(&self, selector: &str) -> Result<FilesystemTransactionTarget> {
        let mut matches = Vec::new();
        for transaction in self.catalog.transactions() {
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
                reason: String::from(
                    "no transaction or subtransaction matches this handle or name",
                ),
            }
            .fail(),
            _ => crate::error::InvalidTransactionHandleSnafu {
                handle: selector.to_owned(),
                reason: String::from("transaction or subtransaction name is ambiguous"),
            }
            .fail(),
        }
    }
}

pub(super) struct TransactionTargetName {
    value: String,
}

impl TransactionTargetName {
    pub(super) fn new(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(
            !value.is_empty() && !value.contains('\n'),
            crate::error::InvalidTransactionNameSnafu {
                name: value.to_owned(),
                reason: String::from("name must be non-empty and single-line"),
            }
        );
        Ok(Self {
            value: value.to_owned(),
        })
    }

    pub(super) fn as_str(&self) -> &str {
        &self.value
    }

    pub(super) fn into_string(self) -> String {
        self.value
    }
}
