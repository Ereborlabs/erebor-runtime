use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{EncodePromotionManifestSnafu, IncompletePromotionSnafu, PromotionIoSnafu},
    promotion::FilesystemPromotionManifest,
    Result,
};

use super::FilesystemPromotionState;

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

    pub(super) fn read_optional(root: &Path) -> Result<Option<Self>> {
        let path = Self::path(root);
        if !path.exists() {
            return Ok(None);
        }
        Self::read(root).map(Some)
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

pub(super) fn fail_if_existing_incomplete(root: &Path, promotion_id: &str) -> Result<()> {
    let path = PromotionJournal::path(root);
    if !path.exists() {
        return Ok(());
    }
    let journal = PromotionJournal::read(root)?;
    IncompletePromotionSnafu {
        promotion_id: promotion_id.to_owned(),
        reason: format!(
            "existing journal state is {:?} with applied operations {:?}",
            journal.state, journal.applied_operations
        ),
    }
    .fail()
}

pub(super) fn ensure_journal_applied(promotion_id: &str, journal: &PromotionJournal) -> Result<()> {
    if journal.state != PromotionJournalState::Applied {
        return IncompletePromotionSnafu {
            promotion_id: promotion_id.to_owned(),
            reason: format!(
                "journal state is {:?} with applied operations {:?}",
                journal.state, journal.applied_operations
            ),
        }
        .fail();
    }
    Ok(())
}

pub(super) fn ensure_manifest_applied(
    promotion_id: &str,
    manifest: &FilesystemPromotionManifest,
) -> Result<()> {
    if manifest.state != FilesystemPromotionState::Applied {
        return IncompletePromotionSnafu {
            promotion_id: promotion_id.to_owned(),
            reason: format!("promotion manifest state is {:?}", manifest.state),
        }
        .fail();
    }
    Ok(())
}

pub(super) fn ensure_manifest_or_journal_applied(
    promotion_id: &str,
    manifest: &FilesystemPromotionManifest,
    journal: Option<&PromotionJournal>,
) -> Result<()> {
    if manifest.state == FilesystemPromotionState::Applied {
        return Ok(());
    }
    if journal.is_some_and(|journal| journal.state == PromotionJournalState::Applied) {
        return Ok(());
    }
    ensure_manifest_applied(promotion_id, manifest)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PromotionJournalState {
    PreimageCommitted,
    Applying,
    Applied,
}
