use crate::Result;

use super::model::{
    FilesystemRetainedRef, FilesystemRetentionInventory, FilesystemRetentionSubtransaction,
    FilesystemRetentionTransaction,
};

pub(super) enum RetentionTarget {
    Transaction(FilesystemRetentionTransaction),
    Subtransaction(FilesystemRetentionSubtransaction),
    Ref(FilesystemRetainedRef),
}

pub(super) struct RetentionTargetResolver<'a> {
    inventory: &'a FilesystemRetentionInventory,
}

impl<'a> RetentionTargetResolver<'a> {
    pub(super) const fn new(inventory: &'a FilesystemRetentionInventory) -> Self {
        Self { inventory }
    }

    pub(super) fn resolve(&self, selector: &str) -> Result<RetentionTarget> {
        if selector.starts_with("erebor/") {
            return self.resolve_ref(selector);
        }
        if let Some(target) = self.resolve_handle(selector) {
            return Ok(target);
        }
        self.resolve_name(selector)
    }

    fn resolve_ref(&self, selector: &str) -> Result<RetentionTarget> {
        for reference in self.all_refs() {
            if reference.reference() == selector {
                return Ok(RetentionTarget::Ref(reference.clone()));
            }
        }
        crate::error::InvalidRetentionTargetSnafu {
            target: selector.to_owned(),
            reason: String::from("no retained ref matches this selector"),
        }
        .fail()
    }

    fn resolve_handle(&self, selector: &str) -> Option<RetentionTarget> {
        for transaction in self.inventory.transactions() {
            if transaction.handle() == selector {
                return Some(RetentionTarget::Transaction(transaction.clone()));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.handle() == selector {
                    return Some(RetentionTarget::Subtransaction(subtransaction.clone()));
                }
            }
        }
        None
    }

    fn resolve_name(&self, selector: &str) -> Result<RetentionTarget> {
        let mut matches = Vec::new();
        for transaction in self.inventory.transactions() {
            if transaction.name() == Some(selector) {
                matches.push(RetentionTarget::Transaction(transaction.clone()));
            }
            for subtransaction in transaction.subtransactions() {
                if subtransaction.name() == Some(selector) {
                    matches.push(RetentionTarget::Subtransaction(subtransaction.clone()));
                }
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => crate::error::InvalidRetentionTargetSnafu {
                target: selector.to_owned(),
                reason: String::from(
                    "no retention transaction, subtransaction, or ref matches this selector",
                ),
            }
            .fail(),
            _ => crate::error::InvalidRetentionTargetSnafu {
                target: selector.to_owned(),
                reason: String::from("retention target name is ambiguous"),
            }
            .fail(),
        }
    }

    fn all_refs(&self) -> Vec<&FilesystemRetainedRef> {
        let mut refs = Vec::new();
        for transaction in self.inventory.transactions() {
            refs.extend(transaction.refs());
            for subtransaction in transaction.subtransactions() {
                refs.extend(subtransaction.refs());
            }
        }
        refs.extend(self.inventory.loose_refs());
        refs
    }
}
