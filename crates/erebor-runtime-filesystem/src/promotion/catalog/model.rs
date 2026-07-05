use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemTransactionCatalog {
    transactions: Vec<FilesystemTransaction>,
}

impl FilesystemTransactionCatalog {
    pub(super) fn new(transactions: Vec<FilesystemTransaction>) -> Self {
        Self { transactions }
    }

    #[must_use]
    pub fn transactions(&self) -> &[FilesystemTransaction] {
        &self.transactions
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemTransaction {
    handle: String,
    promotion_id: String,
    name: Option<String>,
    state: FilesystemTransactionState,
    change_count: usize,
    subtransactions: Vec<FilesystemSubtransaction>,
}

impl FilesystemTransaction {
    pub(super) fn new(
        handle: String,
        promotion_id: String,
        name: Option<String>,
        state: FilesystemTransactionState,
        change_count: usize,
        subtransactions: Vec<FilesystemSubtransaction>,
    ) -> Self {
        Self {
            handle,
            promotion_id,
            name,
            state,
            change_count,
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
    pub const fn state(&self) -> FilesystemTransactionState {
        self.state
    }

    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.change_count
    }

    #[must_use]
    pub fn subtransactions(&self) -> &[FilesystemSubtransaction] {
        &self.subtransactions
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemSubtransaction {
    handle: String,
    promotion_id: String,
    volume_id: String,
    name: Option<String>,
    state: FilesystemSubtransactionState,
    changes: Vec<FilesystemTransactionChange>,
}

impl FilesystemSubtransaction {
    pub(super) fn new(
        handle: String,
        promotion_id: String,
        volume_id: String,
        name: Option<String>,
        state: FilesystemSubtransactionState,
        changes: Vec<FilesystemTransactionChange>,
    ) -> Self {
        Self {
            handle,
            promotion_id,
            volume_id,
            name,
            state,
            changes,
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
    pub const fn state(&self) -> FilesystemSubtransactionState {
        self.state
    }

    #[must_use]
    pub fn changes(&self) -> &[FilesystemTransactionChange] {
        &self.changes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemTransactionChange {
    operation: String,
    path: String,
}

impl FilesystemTransactionChange {
    pub(super) fn new(operation: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            path: path.into(),
        }
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemTransactionState {
    Applied,
    PartiallyRestored,
    Restored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemSubtransactionState {
    Applied,
    Restored,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilesystemTransactionTarget {
    Transaction(FilesystemTransaction),
    Subtransaction(FilesystemSubtransaction),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemTransactionRename {
    handle: String,
    name: String,
}

impl FilesystemTransactionRename {
    pub(super) fn new(handle: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
            name: name.into(),
        }
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemTransactionRollback {
    promotion_id: String,
    handle: String,
    restored_volumes: Vec<String>,
}

impl FilesystemTransactionRollback {
    pub(super) fn new(
        promotion_id: impl Into<String>,
        handle: impl Into<String>,
        restored_volumes: Vec<String>,
    ) -> Self {
        Self {
            promotion_id: promotion_id.into(),
            handle: handle.into(),
            restored_volumes,
        }
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    #[must_use]
    pub fn restored_volumes(&self) -> &[String] {
        &self.restored_volumes
    }
}
