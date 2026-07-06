use std::collections::BTreeSet;

use crate::{
    ostree::{OstreeRepository, OstreeTreeCheckout},
    promotion::{
        catalog::state::{CatalogState, CatalogTargetKey},
        ids::PromotionId,
        io::PromotionManifestCheckout,
        manifest::FilesystemPromotionManifest,
        PromotionWorkspace,
    },
    FilesystemSessionStorage, Result,
};

use super::model::{
    FilesystemRetainedArtifactStatus, FilesystemRetainedLocalArtifact, FilesystemRetainedLocalKind,
    FilesystemRetainedRef, FilesystemRetainedRefKind, FilesystemRetentionInventory,
    FilesystemRetentionState, FilesystemRetentionSubtransaction, FilesystemRetentionTransaction,
};

pub(super) struct RetentionInventoryLoader<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    repository: &'a R,
    metadata: CatalogState,
    refs: BTreeSet<String>,
}

impl<'a, R> RetentionInventoryLoader<'a, R>
where
    R: OstreeRepository,
{
    pub(super) fn new(storage: &'a FilesystemSessionStorage, repository: &'a R) -> Result<Self> {
        Ok(Self {
            storage,
            repository,
            metadata: CatalogState::read(storage)?,
            refs: repository
                .list_refs(storage.repo_path())?
                .into_iter()
                .collect(),
        })
    }

    pub(super) fn load(&self) -> Result<FilesystemRetentionInventory> {
        let transactions = self.transactions()?;
        let loose_refs = self.loose_refs(&transactions);
        Ok(FilesystemRetentionInventory::new(
            transactions,
            loose_refs,
            self.root_local_artifacts(),
        ))
    }

    fn transactions(&self) -> Result<Vec<FilesystemRetentionTransaction>> {
        let mut ids = self
            .refs
            .iter()
            .filter_map(|reference| Self::promotion_id_from_manifest_ref(reference))
            .collect::<Vec<_>>();
        ids.sort();
        ids.reverse();
        ids.dedup();
        ids.iter()
            .enumerate()
            .map(|(index, promotion_id)| self.transaction(index, promotion_id))
            .collect()
    }

    fn transaction(
        &self,
        index: usize,
        promotion_id: &str,
    ) -> Result<FilesystemRetentionTransaction> {
        let manifest_ref = PromotionId::new(promotion_id)?.manifest_ref();
        let mut refs = Vec::new();
        let promotion_manifest = self.promotion_manifest(promotion_id, &manifest_ref, &mut refs)?;
        let Some(promotion_manifest) = promotion_manifest else {
            return Ok(self.corrupt_transaction(index, promotion_id, refs));
        };
        let subtransactions = self.subtransactions(index, promotion_id, &promotion_manifest)?;
        let state = Self::transaction_state(&subtransactions);
        let any_applied = Self::state_has_applied(state);
        refs.push(
            self.ref_artifact(
                FilesystemRetainedRefKind::CheckpointManifest,
                promotion_id,
                None,
                promotion_manifest.checkpoint_ref,
            )
            .protect(any_applied),
        );
        refs.push(
            self.ref_artifact(
                FilesystemRetainedRefKind::PromotionManifest,
                promotion_id,
                None,
                manifest_ref,
            )
            .require_rollback(any_applied)
            .protect(any_applied),
        );
        let key = CatalogTargetKey::transaction(promotion_id);
        Ok(FilesystemRetentionTransaction::new(
            format!("tx@{{{index}}}"),
            promotion_id.to_owned(),
            self.metadata.name_for(&key).map(ToOwned::to_owned),
            state,
            refs,
            self.transaction_local_artifacts(promotion_id, any_applied),
            subtransactions,
        ))
    }

    fn promotion_manifest(
        &self,
        promotion_id: &str,
        manifest_ref: &str,
        refs: &mut Vec<FilesystemRetainedRef>,
    ) -> Result<Option<FilesystemPromotionManifest>> {
        let root = self.checkout_root(promotion_id);
        let manifest_destination = root.join("manifest");
        let checkout = OstreeTreeCheckout::new(
            self.storage.repo_path(),
            manifest_ref,
            &manifest_destination,
            "checkout retention promotion manifest",
        );
        if checkout.checkout(self.repository).is_err() {
            refs.push(
                self.ref_artifact(
                    FilesystemRetainedRefKind::PromotionManifest,
                    promotion_id,
                    None,
                    manifest_ref.to_owned(),
                )
                .with_status(FilesystemRetainedArtifactStatus::Corrupt)
                .require_rollback(true)
                .protect(true),
            );
            return Ok(None);
        }
        match PromotionManifestCheckout::new(&root).read_promotion() {
            Ok(manifest) => Ok(Some(manifest)),
            Err(_) => {
                refs.push(
                    self.ref_artifact(
                        FilesystemRetainedRefKind::PromotionManifest,
                        promotion_id,
                        None,
                        manifest_ref.to_owned(),
                    )
                    .with_status(FilesystemRetainedArtifactStatus::Corrupt)
                    .require_rollback(true)
                    .protect(true),
                );
                Ok(None)
            }
        }
    }

    fn subtransactions(
        &self,
        tx_index: usize,
        promotion_id: &str,
        manifest: &FilesystemPromotionManifest,
    ) -> Result<Vec<FilesystemRetentionSubtransaction>> {
        let any_applied = manifest
            .volumes
            .iter()
            .any(|volume| !self.metadata.is_restored(promotion_id, &volume.volume_id));
        manifest
            .volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| {
                let restored = self.metadata.is_restored(promotion_id, &volume.volume_id);
                let state = if restored {
                    FilesystemRetentionState::Restored
                } else {
                    FilesystemRetentionState::Applied
                };
                let key = CatalogTargetKey::subtransaction(promotion_id, &volume.volume_id);
                Ok(FilesystemRetentionSubtransaction::new(
                    format!("tx@{{{tx_index}}}.sub@{{{index}}}"),
                    promotion_id.to_owned(),
                    volume.volume_id.clone(),
                    self.metadata.name_for(&key).map(ToOwned::to_owned),
                    state,
                    vec![
                        self.ref_artifact(
                            FilesystemRetainedRefKind::CheckpointLayer,
                            promotion_id,
                            Some(volume.volume_id.clone()),
                            volume.layer_ref.clone(),
                        )
                        .protect(any_applied),
                        self.ref_artifact(
                            FilesystemRetainedRefKind::PromotionPreimage,
                            promotion_id,
                            Some(volume.volume_id.clone()),
                            volume.preimage_ref.clone(),
                        )
                        .require_rollback(!restored)
                        .protect(!restored),
                    ],
                    vec![self
                        .cow_artifact(promotion_id, &volume.volume_id)
                        .require_rollback(!restored)
                        .protect(!restored)],
                ))
            })
            .collect()
    }

    fn corrupt_transaction(
        &self,
        index: usize,
        promotion_id: &str,
        refs: Vec<FilesystemRetainedRef>,
    ) -> FilesystemRetentionTransaction {
        let key = CatalogTargetKey::transaction(promotion_id);
        FilesystemRetentionTransaction::new(
            format!("tx@{{{index}}}"),
            promotion_id.to_owned(),
            self.metadata.name_for(&key).map(ToOwned::to_owned),
            FilesystemRetentionState::Corrupt,
            refs,
            self.transaction_local_artifacts(promotion_id, true),
            Vec::new(),
        )
    }

    fn ref_artifact(
        &self,
        kind: FilesystemRetainedRefKind,
        promotion_id: &str,
        volume_id: Option<String>,
        reference: String,
    ) -> FilesystemRetainedRef {
        let status = if self.refs.contains(&reference) {
            FilesystemRetainedArtifactStatus::Present
        } else {
            FilesystemRetainedArtifactStatus::Missing
        };
        FilesystemRetainedRef::new(kind, promotion_id, volume_id, reference).with_status(status)
    }

    fn transaction_local_artifacts(
        &self,
        promotion_id: &str,
        protected: bool,
    ) -> Vec<FilesystemRetainedLocalArtifact> {
        let workspace = PromotionWorkspace::new(self.storage, promotion_id);
        vec![
            FilesystemRetainedLocalArtifact::new(
                FilesystemRetainedLocalKind::PromotionWorkdir,
                Some(promotion_id.to_owned()),
                None,
                workspace.promotion_root(),
            )
            .detect()
            .protect(protected),
            FilesystemRetainedLocalArtifact::new(
                FilesystemRetainedLocalKind::RollbackCheckout,
                Some(promotion_id.to_owned()),
                None,
                workspace.rollback_root(),
            )
            .detect()
            .protect(protected),
        ]
    }

    fn cow_artifact(&self, promotion_id: &str, volume_id: &str) -> FilesystemRetainedLocalArtifact {
        let workspace = PromotionWorkspace::new(self.storage, promotion_id);
        FilesystemRetainedLocalArtifact::new(
            FilesystemRetainedLocalKind::CowPreimageArtifact,
            Some(promotion_id.to_owned()),
            Some(volume_id.to_owned()),
            workspace.cow_preimage_artifact_root(volume_id),
        )
        .detect()
    }

    fn root_local_artifacts(&self) -> Vec<FilesystemRetainedLocalArtifact> {
        let catalog = self
            .storage
            .root()
            .join("transaction-catalog")
            .join("erebor-transaction-catalog.jsonl");
        vec![
            FilesystemRetainedLocalArtifact::new(
                FilesystemRetainedLocalKind::PromotionLock,
                None,
                None,
                self.storage.work_path().join("promotion.lock"),
            )
            .detect()
            .protect(true),
            FilesystemRetainedLocalArtifact::new(
                FilesystemRetainedLocalKind::TransactionCatalogJournal,
                None,
                None,
                catalog,
            )
            .detect()
            .protect(true),
            FilesystemRetainedLocalArtifact::new(
                FilesystemRetainedLocalKind::RetentionJournal,
                None,
                None,
                self.storage
                    .root()
                    .join("retention")
                    .join("erebor-retention.jsonl"),
            )
            .detect()
            .protect(true),
        ]
    }

    fn loose_refs(
        &self,
        transactions: &[FilesystemRetentionTransaction],
    ) -> Vec<FilesystemRetainedRef> {
        let expected = RetentionExpectedRefs::new(transactions).refs();
        self.refs
            .iter()
            .filter(|reference| !expected.contains(reference.as_str()))
            .filter_map(|reference| self.loose_ref(reference))
            .collect()
    }

    fn loose_ref(&self, reference: &str) -> Option<FilesystemRetainedRef> {
        let (kind, promotion_id, volume_id) = Self::parse_retained_ref(reference)?;
        Some(FilesystemRetainedRef::new(
            kind,
            promotion_id,
            volume_id,
            reference.to_owned(),
        ))
    }

    fn parse_retained_ref(
        reference: &str,
    ) -> Option<(FilesystemRetainedRefKind, String, Option<String>)> {
        if let Some(id) = reference
            .strip_prefix("erebor/checkpoints/")?
            .strip_suffix("/manifest")
        {
            return Some((
                FilesystemRetainedRefKind::CheckpointManifest,
                id.to_owned(),
                None,
            ));
        }
        if let Some(rest) = reference.strip_prefix("erebor/checkpoints/") {
            let (id, suffix) = rest.split_once("/volumes/")?;
            let volume_id = suffix.strip_suffix("/layer")?;
            return Some((
                FilesystemRetainedRefKind::CheckpointLayer,
                id.to_owned(),
                Some(volume_id.to_owned()),
            ));
        }
        if let Some(id) = Self::promotion_id_from_manifest_ref(reference) {
            return Some((FilesystemRetainedRefKind::PromotionManifest, id, None));
        }
        let rest = reference.strip_prefix("erebor/promotions/")?;
        let (id, suffix) = rest.split_once("/volumes/")?;
        let volume_id = suffix.strip_suffix("/preimage")?;
        Some((
            FilesystemRetainedRefKind::PromotionPreimage,
            id.to_owned(),
            Some(volume_id.to_owned()),
        ))
    }

    fn promotion_id_from_manifest_ref(reference: &str) -> Option<String> {
        reference
            .strip_prefix("erebor/promotions/")?
            .strip_suffix("/manifest")
            .map(ToOwned::to_owned)
    }

    fn transaction_state(
        subtransactions: &[FilesystemRetentionSubtransaction],
    ) -> FilesystemRetentionState {
        let restored = subtransactions
            .iter()
            .filter(|subtransaction| subtransaction.state() == FilesystemRetentionState::Restored)
            .count();
        match (restored, subtransactions.len()) {
            (0, _) => FilesystemRetentionState::Applied,
            (restored, total) if restored == total => FilesystemRetentionState::Restored,
            _ => FilesystemRetentionState::PartiallyRestored,
        }
    }

    fn state_has_applied(state: FilesystemRetentionState) -> bool {
        matches!(
            state,
            FilesystemRetentionState::Applied
                | FilesystemRetentionState::PartiallyRestored
                | FilesystemRetentionState::Corrupt
        )
    }

    fn checkout_root(&self, promotion_id: &str) -> std::path::PathBuf {
        self.storage
            .work_path()
            .join("retention")
            .join("checkouts")
            .join(promotion_id)
    }
}

struct RetentionExpectedRefs<'a> {
    transactions: &'a [FilesystemRetentionTransaction],
}

impl<'a> RetentionExpectedRefs<'a> {
    const fn new(transactions: &'a [FilesystemRetentionTransaction]) -> Self {
        Self { transactions }
    }

    fn refs(&self) -> BTreeSet<&'a str> {
        let mut refs = BTreeSet::new();
        for transaction in self.transactions {
            refs.extend(
                transaction
                    .refs()
                    .iter()
                    .map(FilesystemRetainedRef::reference),
            );
            for subtransaction in transaction.subtransactions() {
                refs.extend(
                    subtransaction
                        .refs()
                        .iter()
                        .map(FilesystemRetainedRef::reference),
                );
            }
        }
        refs
    }
}
