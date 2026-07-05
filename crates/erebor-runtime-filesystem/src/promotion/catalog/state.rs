use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{EncodeTransactionCatalogSnafu, TransactionCatalogIoSnafu},
    FilesystemSessionStorage, Result,
};

use super::journal::{append_rename_event, append_rollback_event, CatalogRollbackJournal};

const CATALOG_DIR: &str = "transaction-catalog";
const CATALOG_FILE: &str = "erebor-transaction-catalog.json";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct CatalogState {
    #[serde(default = "catalog_version")]
    version: u32,
    #[serde(default)]
    names: Vec<CatalogName>,
    #[serde(default)]
    restored: Vec<CatalogRestoredSubtransaction>,
}

impl CatalogState {
    pub(super) fn read(storage: &FilesystemSessionStorage) -> Result<Self> {
        let path = catalog_path(storage);
        if !path.exists() {
            return Ok(Self {
                version: catalog_version(),
                ..Self::default()
            });
        }
        let source = fs::read_to_string(&path).context(TransactionCatalogIoSnafu {
            action: "read transaction catalog",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodeTransactionCatalogSnafu { path })
    }

    pub(super) fn write(&self, storage: &FilesystemSessionStorage) -> Result<()> {
        let path = catalog_path(storage);
        create_parent(&path)?;
        let source = serde_json::to_vec_pretty(self)
            .context(EncodeTransactionCatalogSnafu { path: path.clone() })?;
        fs::write(&path, source).context(TransactionCatalogIoSnafu {
            action: "write transaction catalog",
            path: path.as_path(),
        })
    }

    pub(super) fn name_for(&self, key: &CatalogTargetKey) -> Option<&str> {
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

    pub(super) fn is_restored(&self, promotion_id: &str, volume_id: &str) -> bool {
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
            restored_at_unix_ms: unix_time_ms(),
        });
    }

    pub(super) fn append_rename_event(
        &self,
        storage: &FilesystemSessionStorage,
        selector: &str,
        name: &str,
    ) -> Result<()> {
        append_rename_event(storage, selector, name)
    }

    pub(super) fn append_rollback_event(
        &self,
        storage: &FilesystemSessionStorage,
        event: CatalogRollbackJournal<'_>,
    ) -> Result<()> {
        append_rollback_event(storage, event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum CatalogTargetKey {
    Transaction {
        promotion_id: String,
    },
    Subtransaction {
        promotion_id: String,
        volume_id: String,
    },
}

impl CatalogTargetKey {
    pub(super) fn transaction(promotion_id: &str) -> Self {
        Self::Transaction {
            promotion_id: promotion_id.to_owned(),
        }
    }

    pub(super) fn subtransaction(promotion_id: &str, volume_id: &str) -> Self {
        Self::Subtransaction {
            promotion_id: promotion_id.to_owned(),
            volume_id: volume_id.to_owned(),
        }
    }

    pub(super) fn promotion_id(&self) -> &str {
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

fn catalog_path(storage: &FilesystemSessionStorage) -> PathBuf {
    catalog_dir(storage).join(CATALOG_FILE)
}

fn catalog_dir(storage: &FilesystemSessionStorage) -> PathBuf {
    storage.root().join(CATALOG_DIR)
}

fn create_parent(path: &Path) -> Result<()> {
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    fs::create_dir_all(&parent).context(TransactionCatalogIoSnafu {
        action: "create transaction catalog directory",
        path: parent.as_path(),
    })
}

fn catalog_version() -> u32 {
    1
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}
