use std::fs;

use snafu::{ensure, ResultExt};

use crate::{
    error::{ProtectedRetentionTargetSnafu, RetentionIoSnafu},
    ostree::OstreeRepository,
    FilesystemSessionStorage, Result,
};

use super::{
    inventory::RetentionInventoryLoader,
    journal::RetentionJournal,
    model::{
        FilesystemOstreePrune, FilesystemRetainedArtifactStatus, FilesystemRetainedLocalArtifact,
        FilesystemRetainedLocalKind, FilesystemRetainedRef, FilesystemRetainedRefKind,
        FilesystemRetentionPrune, FilesystemRetentionState,
    },
    resolve::{RetentionTarget, RetentionTargetResolver},
};

pub(super) struct RetentionPruner<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    repository: &'a R,
}

impl<'a, R> RetentionPruner<'a, R>
where
    R: OstreeRepository,
{
    pub(super) const fn new(storage: &'a FilesystemSessionStorage, repository: &'a R) -> Self {
        Self {
            storage,
            repository,
        }
    }

    pub(super) fn prune(&self, selector: &str) -> Result<FilesystemRetentionPrune> {
        let journal = RetentionJournal::new(self.storage);
        let inventory = RetentionInventoryLoader::new(self.storage, self.repository)?.load()?;
        let target = match RetentionTargetResolver::new(&inventory).resolve(selector) {
            Ok(target) => target,
            Err(error) => {
                journal.append_prune(selector, "failed", None, Some(error.to_string()))?;
                return Err(error);
            }
        };
        match self.prune_target(selector, target) {
            Ok(result) => {
                journal.append_prune(selector, "success", Some(&result), None)?;
                Ok(result)
            }
            Err(error) => {
                journal.append_prune(selector, "failed", None, Some(error.to_string()))?;
                Err(error)
            }
        }
    }

    fn prune_target(
        &self,
        selector: &str,
        target: RetentionTarget,
    ) -> Result<FilesystemRetentionPrune> {
        let plan = RetentionPrunePlan::from_target(selector, target)?;
        let mut pruned_refs = Vec::new();
        let mut skipped_refs = Vec::new();
        for reference in plan.refs {
            match reference.status() {
                FilesystemRetainedArtifactStatus::Present => {
                    self.repository
                        .delete_ref(self.storage.repo_path(), reference.reference())?;
                    pruned_refs.push(reference);
                }
                FilesystemRetainedArtifactStatus::Missing
                | FilesystemRetainedArtifactStatus::Corrupt => skipped_refs.push(reference),
            }
        }

        let mut pruned_local_artifacts = Vec::new();
        let mut skipped_local_artifacts = Vec::new();
        for artifact in plan.local_artifacts {
            if artifact.status() == FilesystemRetainedArtifactStatus::Present {
                self.remove_local_artifact(&artifact)?;
                pruned_local_artifacts.push(artifact);
            } else {
                skipped_local_artifacts.push(artifact);
            }
        }

        let ostree_prune = if pruned_refs.is_empty() {
            FilesystemOstreePrune::empty()
        } else {
            FilesystemOstreePrune::from_summary(self.repository.prune(self.storage.repo_path())?)
        };
        Ok(FilesystemRetentionPrune::new(
            selector,
            pruned_refs,
            skipped_refs,
            pruned_local_artifacts,
            skipped_local_artifacts,
            ostree_prune,
        ))
    }

    fn remove_local_artifact(&self, artifact: &FilesystemRetainedLocalArtifact) -> Result<()> {
        let path = artifact.path();
        if path.is_dir() {
            fs::remove_dir_all(path).context(RetentionIoSnafu {
                action: "remove retention directory",
                path,
            })
        } else {
            fs::remove_file(path).context(RetentionIoSnafu {
                action: "remove retention file",
                path,
            })
        }
    }
}

struct RetentionPrunePlan {
    refs: Vec<FilesystemRetainedRef>,
    local_artifacts: Vec<FilesystemRetainedLocalArtifact>,
}

impl RetentionPrunePlan {
    fn from_target(selector: &str, target: RetentionTarget) -> Result<Self> {
        match target {
            RetentionTarget::Transaction(transaction) => {
                ensure!(
                    transaction.state() == FilesystemRetentionState::Restored,
                    ProtectedRetentionTargetSnafu {
                        target: selector.to_owned(),
                        reason: String::from("transaction has applied rollback or audit artifacts")
                    }
                );
                let mut refs = transaction.refs().to_vec();
                for subtransaction in transaction.subtransactions() {
                    refs.extend(subtransaction.refs().iter().cloned());
                }
                Ok(Self {
                    refs,
                    local_artifacts: transaction
                        .local_artifacts()
                        .iter()
                        .filter(|artifact| Self::is_transaction_local_prunable(artifact.kind()))
                        .cloned()
                        .collect(),
                })
            }
            RetentionTarget::Subtransaction(subtransaction) => {
                ensure!(
                    subtransaction.state() == FilesystemRetentionState::Restored,
                    ProtectedRetentionTargetSnafu {
                        target: selector.to_owned(),
                        reason: String::from("subtransaction still requires rollback artifacts")
                    }
                );
                Ok(Self {
                    refs: subtransaction
                        .refs()
                        .iter()
                        .filter(|reference| {
                            reference.kind() == FilesystemRetainedRefKind::PromotionPreimage
                        })
                        .cloned()
                        .collect(),
                    local_artifacts: subtransaction.local_artifacts().to_vec(),
                })
            }
            RetentionTarget::Ref(reference) => {
                ensure!(
                    !reference.protected(),
                    ProtectedRetentionTargetSnafu {
                        target: selector.to_owned(),
                        reason: String::from("retained ref is required by rollback or audit")
                    }
                );
                Ok(Self {
                    refs: vec![reference],
                    local_artifacts: Vec::new(),
                })
            }
        }
    }

    fn is_transaction_local_prunable(kind: FilesystemRetainedLocalKind) -> bool {
        matches!(
            kind,
            FilesystemRetainedLocalKind::PromotionWorkdir
                | FilesystemRetainedLocalKind::RollbackCheckout
        )
    }
}
