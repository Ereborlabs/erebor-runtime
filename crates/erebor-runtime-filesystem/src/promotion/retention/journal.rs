use std::{fs, path::PathBuf};

use serde::Serialize;
use snafu::ResultExt;

use crate::{
    error::{EncodeRetentionSnafu, RetentionIoSnafu},
    FilesystemSessionStorage, Result,
};

use super::model::{FilesystemRetentionInventory, FilesystemRetentionPrune};

const RETENTION_DIR: &str = "retention";
const RETENTION_JOURNAL_FILE: &str = "erebor-retention.jsonl";

pub(super) struct RetentionJournal<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> RetentionJournal<'a> {
    pub(super) const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    pub(super) fn append_list(&self, inventory: &FilesystemRetentionInventory) -> Result<()> {
        self.append_event(&RetentionEvent::List {
            transactions: inventory.transactions().len(),
            loose_refs: inventory.loose_refs().len(),
            local_artifacts: inventory.local_artifacts().len(),
        })
    }

    pub(super) fn append_prune(
        &self,
        selector: &str,
        outcome: &'static str,
        result: Option<&FilesystemRetentionPrune>,
        error: Option<String>,
    ) -> Result<()> {
        self.append_event(&RetentionEvent::Prune {
            selector: selector.to_owned(),
            outcome: outcome.to_owned(),
            pruned_refs: result
                .map(|result| result.pruned_refs().len())
                .unwrap_or_default(),
            skipped_refs: result
                .map(|result| result.skipped_refs().len())
                .unwrap_or_default(),
            pruned_local_artifacts: result
                .map(|result| result.pruned_local_artifacts().len())
                .unwrap_or_default(),
            skipped_local_artifacts: result
                .map(|result| result.skipped_local_artifacts().len())
                .unwrap_or_default(),
            error,
        })
    }

    fn append_event(&self, event: &RetentionEvent) -> Result<()> {
        let path = self.path();
        self.create_parent()?;
        let mut source =
            serde_json::to_string(event).context(EncodeRetentionSnafu { path: path.clone() })?;
        source.push('\n');
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        std::io::Write::write_all(
            &mut options.open(&path).context(RetentionIoSnafu {
                action: "open retention journal",
                path: path.as_path(),
            })?,
            source.as_bytes(),
        )
        .context(RetentionIoSnafu {
            action: "write retention journal",
            path: path.as_path(),
        })
    }

    fn path(&self) -> PathBuf {
        self.storage
            .root()
            .join(RETENTION_DIR)
            .join(RETENTION_JOURNAL_FILE)
    }

    fn create_parent(&self) -> Result<()> {
        let parent = self.storage.root().join(RETENTION_DIR);
        fs::create_dir_all(&parent).context(RetentionIoSnafu {
            action: "create retention journal directory",
            path: parent.as_path(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum RetentionEvent {
    List {
        transactions: usize,
        loose_refs: usize,
        local_artifacts: usize,
    },
    Prune {
        selector: String,
        outcome: String,
        pruned_refs: usize,
        skipped_refs: usize,
        pruned_local_artifacts: usize,
        skipped_local_artifacts: usize,
        error: Option<String>,
    },
}
