use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{EncodePromotionManifestSnafu, PromotionIoSnafu},
    manifest::LAYER_MANIFEST_FILE,
    ostree::{OstreeRepository, OstreeTreeCheckout},
    FilesystemLayerManifest, FilesystemLayerOperation, FilesystemSessionStorage, Result,
};

use super::{
    model::{
        FilesystemSubtransaction, FilesystemSubtransactionState, FilesystemTransaction,
        FilesystemTransactionCatalog, FilesystemTransactionChange, FilesystemTransactionState,
    },
    state::{CatalogState, CatalogTargetKey},
};
use crate::promotion::{
    ids::PromotionId, io::PromotionManifestCheckout, journal::PromotionJournalVerifier,
};

pub(super) struct TransactionCatalogLoader<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    repository: &'a R,
    metadata: CatalogState,
}

impl<'a, R> TransactionCatalogLoader<'a, R>
where
    R: OstreeRepository,
{
    pub(super) fn new(storage: &'a FilesystemSessionStorage, repository: &'a R) -> Result<Self> {
        Ok(Self {
            storage,
            repository,
            metadata: CatalogState::read(storage)?,
        })
    }

    pub(super) fn load(&self) -> Result<FilesystemTransactionCatalog> {
        let promotion_ids = self.committed_promotion_ids()?;
        let mut transactions = Vec::new();
        for (index, promotion_id) in promotion_ids.iter().enumerate() {
            transactions.push(self.load_transaction(index, promotion_id)?);
        }
        Ok(FilesystemTransactionCatalog::new(transactions))
    }

    fn committed_promotion_ids(&self) -> Result<Vec<String>> {
        let mut ids = self
            .repository
            .list_refs(self.storage.repo_path())?
            .into_iter()
            .filter_map(|ref_name| Self::promotion_id_from_ref(&ref_name))
            .collect::<Vec<_>>();
        ids.sort();
        ids.reverse();
        ids.dedup();
        Ok(ids)
    }

    fn promotion_id_from_ref(ref_name: &str) -> Option<String> {
        ref_name
            .strip_prefix("erebor/promotions/")?
            .strip_suffix("/manifest")
            .map(ToOwned::to_owned)
    }

    fn load_transaction(&self, index: usize, promotion_id: &str) -> Result<FilesystemTransaction> {
        PromotionId::new(promotion_id)?;
        let root = self.catalog_checkout_root(promotion_id);
        OstreeTreeCheckout::new(
            self.storage.repo_path(),
            &PromotionId::new(promotion_id)?.manifest_ref(),
            &root.join("manifest"),
            "checkout transaction manifest",
        )
        .checkout(self.repository)?;
        let manifest = PromotionManifestCheckout::new(&root).read_promotion()?;
        PromotionJournalVerifier::new(promotion_id).ensure_manifest_applied(&manifest)?;
        let mut subtransactions = Vec::new();
        for (sub_index, volume) in manifest.volumes.iter().enumerate() {
            let layer_root = root.join("layers").join(&volume.volume_id).join("layer");
            OstreeTreeCheckout::new(
                self.storage.repo_path(),
                &volume.layer_ref,
                &layer_root,
                "checkout transaction layer",
            )
            .checkout(self.repository)?;
            let layer = Self::read_layer_manifest(&layer_root)?;
            let key = CatalogTargetKey::subtransaction(promotion_id, &volume.volume_id);
            let state = if self.metadata.is_restored(promotion_id, &volume.volume_id) {
                FilesystemSubtransactionState::Restored
            } else {
                FilesystemSubtransactionState::Applied
            };
            subtransactions.push(FilesystemSubtransaction::new(
                format!("tx@{{{index}}}.sub@{{{sub_index}}}"),
                promotion_id.to_owned(),
                volume.volume_id.clone(),
                self.metadata.name_for(&key).map(ToOwned::to_owned),
                state,
                layer
                    .operations
                    .iter()
                    .map(Self::change_from_operation)
                    .collect(),
            ));
        }
        let change_count = subtransactions
            .iter()
            .map(|subtransaction| subtransaction.changes().len())
            .sum();
        let state = Self::transaction_state(&subtransactions);
        let key = CatalogTargetKey::transaction(promotion_id);
        Ok(FilesystemTransaction::new(
            format!("tx@{{{index}}}"),
            promotion_id.to_owned(),
            self.metadata.name_for(&key).map(ToOwned::to_owned),
            state,
            change_count,
            subtransactions,
        ))
    }

    fn read_layer_manifest(root: &Path) -> Result<FilesystemLayerManifest> {
        let path = root.join(LAYER_MANIFEST_FILE);
        let source = fs::read_to_string(&path).context(PromotionIoSnafu {
            action: "read transaction layer manifest",
            path: path.as_path(),
        })?;
        serde_json::from_str(&source).context(EncodePromotionManifestSnafu { path })
    }

    fn transaction_state(
        subtransactions: &[FilesystemSubtransaction],
    ) -> FilesystemTransactionState {
        let restored = subtransactions
            .iter()
            .filter(|subtransaction| {
                subtransaction.state() == FilesystemSubtransactionState::Restored
            })
            .count();
        match (restored, subtransactions.len()) {
            (0, _) => FilesystemTransactionState::Applied,
            (restored, total) if restored == total => FilesystemTransactionState::Restored,
            _ => FilesystemTransactionState::PartiallyRestored,
        }
    }

    fn change_from_operation(operation: &FilesystemLayerOperation) -> FilesystemTransactionChange {
        match operation {
            FilesystemLayerOperation::Create { path, .. } => {
                FilesystemTransactionChange::new("create", path)
            }
            FilesystemLayerOperation::Replace { path, .. } => {
                FilesystemTransactionChange::new("replace", path)
            }
            FilesystemLayerOperation::Delete { path } => {
                FilesystemTransactionChange::new("delete", path)
            }
            FilesystemLayerOperation::OpaqueReplace { path, .. } => {
                FilesystemTransactionChange::new("opaque_replace", path)
            }
        }
    }

    fn catalog_checkout_root(&self, promotion_id: &str) -> PathBuf {
        self.storage
            .work_path()
            .join("transaction-catalog")
            .join("checkouts")
            .join(promotion_id)
    }
}
