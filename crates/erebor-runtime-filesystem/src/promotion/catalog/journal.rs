use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{EncodeTransactionCatalogSnafu, TransactionCatalogIoSnafu},
    promotion::ids::PromotionId,
    FilesystemSessionStorage, Result,
};

const CATALOG_DIR: &str = "transaction-catalog";
const CATALOG_JOURNAL_FILE: &str = "erebor-transaction-catalog.jsonl";

pub(super) struct CatalogRollbackJournal<'a> {
    selector: &'a str,
    promotion_id: &'a str,
    selected_volumes: &'a [String],
    ref_volumes: &'a [String],
    restored_volumes: &'a [String],
    outcome: &'static str,
    error: Option<String>,
}

impl<'a> CatalogRollbackJournal<'a> {
    pub(super) fn succeeded(
        selector: &'a str,
        promotion_id: &'a str,
        selected_volumes: &'a [String],
        restored_volumes: &'a [String],
    ) -> Self {
        Self {
            selector,
            promotion_id,
            selected_volumes,
            ref_volumes: restored_volumes,
            restored_volumes,
            outcome: "success",
            error: None,
        }
    }

    pub(super) fn already_restored(
        selector: &'a str,
        promotion_id: &'a str,
        selected_volumes: &'a [String],
    ) -> Self {
        Self {
            selector,
            promotion_id,
            selected_volumes,
            ref_volumes: &[],
            restored_volumes: &[],
            outcome: "already_restored",
            error: None,
        }
    }

    pub(super) fn failed(
        selector: &'a str,
        promotion_id: &'a str,
        selected_volumes: &'a [String],
        ref_volumes: &'a [String],
        error: String,
    ) -> Self {
        Self {
            selector,
            promotion_id,
            selected_volumes,
            ref_volumes,
            restored_volumes: &[],
            outcome: "failed",
            error: Some(error),
        }
    }
}

pub(super) struct TransactionCatalogJournal<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> TransactionCatalogJournal<'a> {
    pub(super) const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    pub(super) fn append_rename(&self, selector: &str, name: &str) -> Result<()> {
        self.append_event(&CatalogEvent::Rename {
            selector: selector.to_owned(),
            name: name.to_owned(),
        })
    }

    pub(super) fn append_rollback(&self, event: CatalogRollbackJournal<'_>) -> Result<()> {
        self.append_event(&CatalogEvent::Rollback {
            selector: event.selector.to_owned(),
            session_id: event.promotion_id.to_owned(),
            promotion_id: event.promotion_id.to_owned(),
            selected_volumes: event.selected_volumes.to_vec(),
            restored_volumes: event.restored_volumes.to_vec(),
            refs: CatalogRollbackRefs::new(event.promotion_id, event.ref_volumes).refs()?,
            outcome: event.outcome.to_owned(),
            error: event.error,
        })
    }

    fn append_event(&self, event: &CatalogEvent) -> Result<()> {
        let path = self.path();
        self.create_parent()?;
        let mut source = serde_json::to_string(event)
            .context(EncodeTransactionCatalogSnafu { path: path.clone() })?;
        source.push('\n');
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        std::io::Write::write_all(
            &mut options.open(&path).context(TransactionCatalogIoSnafu {
                action: "open transaction catalog journal",
                path: path.as_path(),
            })?,
            source.as_bytes(),
        )
        .context(TransactionCatalogIoSnafu {
            action: "write transaction catalog journal",
            path: path.as_path(),
        })
    }

    fn path(&self) -> PathBuf {
        self.storage
            .root()
            .join(CATALOG_DIR)
            .join(CATALOG_JOURNAL_FILE)
    }

    fn create_parent(&self) -> Result<()> {
        let path = self.path();
        let parent = path.parent().map(PathBuf::from).unwrap_or_default();
        fs::create_dir_all(&parent).context(TransactionCatalogIoSnafu {
            action: "create transaction catalog directory",
            path: parent.as_path(),
        })
    }
}

struct CatalogRollbackRefs<'a> {
    promotion_id: &'a str,
    volumes: &'a [String],
}

impl<'a> CatalogRollbackRefs<'a> {
    const fn new(promotion_id: &'a str, volumes: &'a [String]) -> Self {
        Self {
            promotion_id,
            volumes,
        }
    }

    fn refs(&self) -> Result<Vec<CatalogRollbackRef>> {
        if self.volumes.is_empty() {
            return Ok(Vec::new());
        }
        let mut refs = vec![CatalogRollbackRef {
            kind: String::from("promotion_manifest"),
            volume_id: None,
            reference: PromotionId::new(self.promotion_id)?.manifest_ref(),
        }];
        for volume_id in self.volumes {
            refs.push(CatalogRollbackRef {
                kind: String::from("promotion_preimage"),
                volume_id: Some(volume_id.clone()),
                reference: PromotionId::new(self.promotion_id)?.preimage_ref(volume_id),
            });
        }
        Ok(refs)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum CatalogEvent {
    Rename {
        selector: String,
        name: String,
    },
    Rollback {
        selector: String,
        session_id: String,
        promotion_id: String,
        selected_volumes: Vec<String>,
        restored_volumes: Vec<String>,
        refs: Vec<CatalogRollbackRef>,
        outcome: String,
        error: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CatalogRollbackRef {
    kind: String,
    volume_id: Option<String>,
    reference: String,
}
