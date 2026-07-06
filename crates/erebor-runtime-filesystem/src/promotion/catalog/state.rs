use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{EncodeTransactionCatalogSnafu, TransactionCatalogIoSnafu},
    FilesystemSessionStorage, Result,
};

use super::journal::{CatalogRollbackJournal, TransactionCatalogJournal};

const CATALOG_DIR: &str = "transaction-catalog";
const CATALOG_FILE: &str = "erebor-transaction-catalog.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(in crate::promotion) struct CatalogState {
    #[serde(default = "CatalogState::current_version")]
    version: u32,
    #[serde(default)]
    names: Vec<CatalogName>,
    #[serde(default)]
    restored: Vec<CatalogRestoredSubtransaction>,
}

impl Default for CatalogState {
    fn default() -> Self {
        Self {
            version: Self::current_version(),
            names: Vec::new(),
            restored: Vec::new(),
        }
    }
}

impl CatalogState {
    pub(in crate::promotion) fn read(storage: &FilesystemSessionStorage) -> Result<Self> {
        CatalogStateStore::new(storage).read()
    }

    pub(super) fn write(&self, storage: &FilesystemSessionStorage) -> Result<()> {
        CatalogStateStore::new(storage).write(self)
    }

    pub(in crate::promotion) fn name_for(&self, key: &CatalogTargetKey) -> Option<&str> {
        self.names
            .iter()
            .find(|entry| entry.key == *key)
            .map(|entry| entry.name.as_str())
    }

    pub(super) fn set_name(&mut self, key: CatalogTargetKey, name: String) {
        if let Some(entry) = self.names.iter_mut().find(|entry| entry.key == key) {
            entry.name = name;
        } else {
            self.names.push(CatalogName { key, name });
        }
    }

    pub(in crate::promotion) fn is_restored(&self, promotion_id: &str, volume_id: &str) -> bool {
        self.restored
            .iter()
            .any(|entry| entry.promotion_id == promotion_id && entry.volume_id == volume_id)
    }

    pub(super) fn mark_restored(&mut self, promotion_id: &str, volume_id: &str) {
        if self.is_restored(promotion_id, volume_id) {
            return;
        }
        self.restored.push(CatalogRestoredSubtransaction {
            promotion_id: promotion_id.to_owned(),
            volume_id: volume_id.to_owned(),
            restored_at_unix_ms: CatalogClock::unix_time_ms(),
        });
    }

    pub(super) fn append_rename_event(
        &self,
        storage: &FilesystemSessionStorage,
        selector: &str,
        name: &str,
    ) -> Result<()> {
        TransactionCatalogJournal::new(storage).append_rename(selector, name)
    }

    pub(super) fn append_rollback_event(
        &self,
        storage: &FilesystemSessionStorage,
        event: CatalogRollbackJournal<'_>,
    ) -> Result<()> {
        TransactionCatalogJournal::new(storage).append_rollback(event)
    }

    const fn current_version() -> u32 {
        1
    }
}

struct CatalogStateStore<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> CatalogStateStore<'a> {
    const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    fn read(&self) -> Result<CatalogState> {
        let path = self.path();
        if !path.exists() {
            return Ok(CatalogState::default());
        }
        let source = fs::read_to_string(&path).context(TransactionCatalogIoSnafu {
            action: "read transaction catalog",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeTransactionCatalogSnafu { path })
    }

    fn write(&self, state: &CatalogState) -> Result<()> {
        let path = self.path();
        self.create_parent()?;
        let source = serde_json::to_vec_pretty(state)
            .context(EncodeTransactionCatalogSnafu { path: path.clone() })?;
        fs::write(&path, source).context(TransactionCatalogIoSnafu {
            action: "write transaction catalog",
            path: path.as_path(),
        })
    }

    fn path(&self) -> PathBuf {
        self.catalog_dir().join(CATALOG_FILE)
    }

    fn catalog_dir(&self) -> PathBuf {
        self.storage.root().join(CATALOG_DIR)
    }

    fn create_parent(&self) -> Result<()> {
        let dir = self.catalog_dir();
        fs::create_dir_all(&dir).context(TransactionCatalogIoSnafu {
            action: "create transaction catalog directory",
            path: dir.as_path(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::promotion) enum CatalogTargetKey {
    Transaction {
        promotion_id: String,
    },
    Subtransaction {
        promotion_id: String,
        volume_id: String,
    },
}

impl CatalogTargetKey {
    pub(in crate::promotion) fn transaction(promotion_id: &str) -> Self {
        Self::Transaction {
            promotion_id: promotion_id.to_owned(),
        }
    }

    pub(in crate::promotion) fn subtransaction(promotion_id: &str, volume_id: &str) -> Self {
        Self::Subtransaction {
            promotion_id: promotion_id.to_owned(),
            volume_id: volume_id.to_owned(),
        }
    }

    pub(in crate::promotion) fn promotion_id(&self) -> &str {
        match self {
            Self::Transaction { promotion_id } | Self::Subtransaction { promotion_id, .. } => {
                promotion_id
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CatalogName {
    #[serde(flatten)]
    key: CatalogTargetKey,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CatalogRestoredSubtransaction {
    promotion_id: String,
    volume_id: String,
    restored_at_unix_ms: u64,
}

struct CatalogClock;

impl CatalogClock {
    fn unix_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }
}
