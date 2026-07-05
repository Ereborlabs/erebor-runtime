use std::{fs, path::PathBuf};

use snafu::{ensure, ResultExt};

use crate::{
    error::{EncodePromotionManifestSnafu, OstreeCommandFailedSnafu, PromotionIoSnafu},
    manifest::LAYER_MANIFEST_FILE,
    ostree::OstreeCommandRunner,
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
    checkout::checkout_tree,
    ids::{promotion_manifest_ref, validate_promotion_id},
    io::read_promotion_manifest,
    journal,
};

pub(super) fn load_catalog(
    storage: &FilesystemSessionStorage,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemTransactionCatalog> {
    let metadata = CatalogState::read(storage)?;
    let promotion_ids = committed_promotion_ids(storage, runner)?;
    let mut transactions = Vec::new();
    for (index, promotion_id) in promotion_ids.iter().enumerate() {
        transactions.push(load_transaction(
            storage,
            runner,
            &metadata,
            index,
            promotion_id,
        )?);
    }
    Ok(FilesystemTransactionCatalog::new(transactions))
}

fn committed_promotion_ids(
    storage: &FilesystemSessionStorage,
    runner: &impl OstreeCommandRunner,
) -> Result<Vec<String>> {
    let args = vec![String::from("refs"), String::from("--list")];
    let output = runner.run(storage.repo_path(), &args)?;
    ensure!(
        output.success(),
        OstreeCommandFailedSnafu {
            repo: storage.repo_path().to_path_buf(),
            operation: "list promotion refs",
            code: output.code(),
            stderr: output.stderr().to_owned(),
        }
    );
    let mut ids = output
        .stdout()
        .lines()
        .filter_map(promotion_id_from_ref)
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

fn load_transaction(
    storage: &FilesystemSessionStorage,
    runner: &impl OstreeCommandRunner,
    metadata: &CatalogState,
    index: usize,
    promotion_id: &str,
) -> Result<FilesystemTransaction> {
    validate_promotion_id(promotion_id)?;
    let root = catalog_checkout_root(storage, promotion_id);
    checkout_tree(
        runner,
        storage.repo_path(),
        &promotion_manifest_ref(promotion_id)?,
        &root.join("manifest"),
        "checkout transaction manifest",
    )?;
    let manifest = read_promotion_manifest(&root)?;
    journal::ensure_manifest_applied(promotion_id, &manifest)?;
    let mut subtransactions = Vec::new();
    for (sub_index, volume) in manifest.volumes.iter().enumerate() {
        let layer_root = root.join("layers").join(&volume.volume_id).join("layer");
        checkout_tree(
            runner,
            storage.repo_path(),
            &volume.layer_ref,
            &layer_root,
            "checkout transaction layer",
        )?;
        let layer = read_layer_manifest(&layer_root)?;
        let key = CatalogTargetKey::subtransaction(promotion_id, &volume.volume_id);
        let state = if metadata.is_restored(promotion_id, &volume.volume_id) {
            FilesystemSubtransactionState::Restored
        } else {
            FilesystemSubtransactionState::Applied
        };
        subtransactions.push(FilesystemSubtransaction::new(
            format!("tx@{{{index}}}.sub@{{{sub_index}}}"),
            promotion_id.to_owned(),
            volume.volume_id.clone(),
            metadata.name_for(&key).map(ToOwned::to_owned),
            state,
            layer.operations.iter().map(change_from_operation).collect(),
        ));
    }
    let change_count = subtransactions
        .iter()
        .map(|subtransaction| subtransaction.changes().len())
        .sum();
    let state = transaction_state(&subtransactions);
    let key = CatalogTargetKey::transaction(promotion_id);
    Ok(FilesystemTransaction::new(
        format!("tx@{{{index}}}"),
        promotion_id.to_owned(),
        metadata.name_for(&key).map(ToOwned::to_owned),
        state,
        change_count,
        subtransactions,
    ))
}

fn read_layer_manifest(root: &std::path::Path) -> Result<FilesystemLayerManifest> {
    let path = root.join(LAYER_MANIFEST_FILE);
    let source = fs::read_to_string(&path).context(PromotionIoSnafu {
        action: "read transaction layer manifest",
        path: path.as_path(),
    })?;
    serde_json::from_str(&source).context(EncodePromotionManifestSnafu { path })
}

fn transaction_state(subtransactions: &[FilesystemSubtransaction]) -> FilesystemTransactionState {
    let restored = subtransactions
        .iter()
        .filter(|subtransaction| subtransaction.state() == FilesystemSubtransactionState::Restored)
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

fn catalog_checkout_root(storage: &FilesystemSessionStorage, promotion_id: &str) -> PathBuf {
    storage
        .work_path()
        .join("transaction-catalog")
        .join("checkouts")
        .join(promotion_id)
}
