use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{EncodePromotionManifestSnafu, PromotionIoSnafu},
    Result,
};

pub(super) const PROMOTION_JOURNAL_FILE: &str = "erebor-promotion-journal.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PromotionJournal {
    pub promotion_id: String,
    pub state: PromotionJournalState,
    pub applied_operations: Vec<String>,
}

impl PromotionJournal {
    pub(super) fn new(promotion_id: impl Into<String>) -> Self {
        Self {
            promotion_id: promotion_id.into(),
            state: PromotionJournalState::PreimageCommitted,
            applied_operations: Vec::new(),
        }
    }

    pub(super) fn path(root: &Path) -> std::path::PathBuf {
        root.join(PROMOTION_JOURNAL_FILE)
    }

    pub(super) fn read(root: &Path) -> Result<Self> {
        let path = Self::path(root);
        let source = fs::read_to_string(&path).context(PromotionIoSnafu {
            action: "read promotion journal",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodePromotionManifestSnafu {
            path: path.as_path(),
        })
    }

    pub(super) fn write(&self, root: &Path) -> Result<()> {
        fs::create_dir_all(root).context(PromotionIoSnafu {
            action: "create promotion journal directory",
            path: root,
        })?;
        let path = Self::path(root);
        let source = serde_json::to_vec_pretty(self).context(EncodePromotionManifestSnafu {
            path: path.as_path(),
        })?;
        fs::write(&path, source).context(PromotionIoSnafu {
            action: "write promotion journal",
            path: path.as_path(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PromotionJournalState {
    PreimageCommitted,
    Applying,
    Applied,
}
