use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    checkpoint::{CheckpointId, FilesystemCheckpointCommit},
    error::PromotionIoSnafu,
    ostree::{OstreeRepository, OstreeTreeCheckout, OstreeTreeCommit, SystemOstreeRepository},
    FilesystemLayerManifest, FilesystemSessionStorage, Result,
};

mod apply;
mod catalog;
mod ids;
mod io;
mod journal;
mod layer;
mod lock;
mod manifest;
mod path;
mod preimage;
mod preimage_size;
mod rollback;
mod types;

pub use catalog::{
    FilesystemSubtransaction, FilesystemSubtransactionState, FilesystemTransaction,
    FilesystemTransactionCatalog, FilesystemTransactionChange, FilesystemTransactionRename,
    FilesystemTransactionRollback, FilesystemTransactionState, FilesystemTransactionTarget,
};
pub use manifest::{
    FilesystemHostMetadata, FilesystemPreimageEntry, FilesystemPreimageEntryState,
    FilesystemPreimageEntryType, FilesystemPreimageManifest, FilesystemPromotionManifest,
    FilesystemPromotionState, FilesystemPromotionVolume, PREIMAGE_MANIFEST_FILE,
    PREIMAGE_MANIFEST_KIND, PROMOTION_MANIFEST_FILE, PROMOTION_MANIFEST_KIND,
};
pub use types::{FilesystemPromotion, FilesystemPromotionOptions, FilesystemRollback};

use apply::PromotionVolumeApplier;
use ids::{PromotionId, PromotionLayerLookup, PromotionStorageLookup};
use io::PromotionManifestStore;
use journal::{PromotionJournal, PromotionJournalState, PromotionJournalVerifier};
use layer::PromotionLayerGuard;
use lock::PromotionLock;
use preimage::{PromotionPreimageCapture, PromotionPreimageVerifier};

impl FilesystemPromotion {
    pub fn promote_checkpoint(
        storage: &FilesystemSessionStorage,
        promotion_id: &str,
        options: FilesystemPromotionOptions,
    ) -> Result<Self> {
        let manifests = storage.normalize_layers()?;
        let checkpoint = FilesystemCheckpointCommit::commit_normalized_using_repository(
            storage,
            promotion_id,
            &manifests,
            &SystemOstreeRepository,
        )?;
        PromotionWorkflow::new(
            storage,
            promotion_id,
            checkpoint.checkpoint_ref(),
            &manifests,
            options,
            &SystemOstreeRepository,
            &NoopPromotionHook,
        )
        .promote()
    }
}

pub(crate) trait PromotionHook {
    fn before_apply(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct PromotionWorkflow<'a, R, H>
where
    R: OstreeRepository,
    H: PromotionHook,
{
    storage: &'a FilesystemSessionStorage,
    promotion_id: &'a str,
    checkpoint_ref: &'a str,
    manifests: &'a [FilesystemLayerManifest],
    options: FilesystemPromotionOptions,
    repository: &'a R,
    hook: &'a H,
    workspace: PromotionWorkspace<'a>,
}

impl<'a, R, H> PromotionWorkflow<'a, R, H>
where
    R: OstreeRepository,
    H: PromotionHook,
{
    pub(crate) fn new(
        storage: &'a FilesystemSessionStorage,
        promotion_id: &'a str,
        checkpoint_ref: &'a str,
        manifests: &'a [FilesystemLayerManifest],
        options: FilesystemPromotionOptions,
        repository: &'a R,
        hook: &'a H,
    ) -> Self {
        Self {
            storage,
            promotion_id,
            checkpoint_ref,
            manifests,
            options,
            repository,
            hook,
            workspace: PromotionWorkspace::new(storage, promotion_id),
        }
    }

    pub(crate) fn promote(&self) -> Result<FilesystemPromotion> {
        PromotionId::new(self.promotion_id)?;
        let _lock = PromotionLock::acquire(self.storage.work_path())?;
        let root = self.workspace.promotion_root();
        PromotionJournalVerifier::new(self.promotion_id).fail_if_existing_incomplete(&root)?;
        fs::create_dir_all(&root).context(PromotionIoSnafu {
            action: "create promotion work directory",
            path: root.as_path(),
        })?;

        let volumes = self.commit_preimages(&root)?;
        self.commit_promotion_manifest(
            &root,
            FilesystemPromotionState::PreimageCommitted,
            volumes.clone(),
        )?;
        let mut journal = PromotionJournal::new(self.promotion_id);
        journal.write(&root)?;
        self.verify_all_preimages(&root, &volumes)?;
        self.hook.before_apply()?;
        self.verify_all_preimages(&root, &volumes)?;
        self.apply_all_volumes(&root, &volumes, &mut journal)?;
        journal.state = PromotionJournalState::Applied;
        journal.write(&root)?;
        let manifest_path = self.commit_promotion_manifest(
            &root,
            FilesystemPromotionState::Applied,
            volumes.clone(),
        )?;

        Ok(FilesystemPromotion::new(
            self.promotion_id,
            manifest_path,
            volumes,
        ))
    }

    fn commit_preimages(&self, root: &Path) -> Result<Vec<FilesystemPromotionVolume>> {
        let mut volumes = Vec::new();
        for volume in self.storage.volumes() {
            let manifest = PromotionLayerLookup::new(self.manifests).manifest_for_volume(volume)?;
            PromotionLayerGuard::new(manifest).ensure_promotable()?;
            let promotion_id = PromotionId::new(self.promotion_id)?;
            let preimage_ref = promotion_id.preimage_ref(volume.id());
            let stage = PromotionWorkspace::preimage_stage_root(root, volume.id());
            let preimage = PromotionPreimageCapture::new(
                &stage,
                self.promotion_id,
                volume,
                manifest,
                self.options.preimage_size_limit_bytes(),
            )
            .capture()?;
            PromotionManifestStore::new(&stage).write_preimage(&preimage)?;
            let subject = format!(
                "Erebor filesystem promotion {} volume {} preimage",
                self.promotion_id,
                volume.id()
            );
            OstreeTreeCommit::new(
                self.storage.repo_path(),
                &preimage_ref,
                &stage,
                "commit promotion preimage",
                &subject,
            )
            .commit(self.repository)?;
            volumes.push(FilesystemPromotionVolume {
                volume_id: volume.id().to_owned(),
                layer_ref: CheckpointId::new(self.promotion_id)?.volume_layer_ref(volume.id()),
                preimage_ref,
            });
        }
        Ok(volumes)
    }

    fn commit_promotion_manifest(
        &self,
        root: &Path,
        state: FilesystemPromotionState,
        volumes: Vec<FilesystemPromotionVolume>,
    ) -> Result<PathBuf> {
        let manifest_ref = PromotionId::new(self.promotion_id)?.manifest_ref();
        let manifest = FilesystemPromotionManifest::new(
            self.promotion_id,
            self.checkpoint_ref,
            state,
            volumes,
        );
        let stage = root.join("manifest");
        let path = PromotionManifestStore::new(&stage).write_promotion(&manifest)?;
        let subject = format!("Erebor filesystem promotion {} manifest", self.promotion_id);
        OstreeTreeCommit::new(
            self.storage.repo_path(),
            &manifest_ref,
            &stage,
            "commit promotion manifest",
            &subject,
        )
        .commit(self.repository)?;
        Ok(path)
    }

    fn apply_all_volumes(
        &self,
        root: &Path,
        volumes: &[FilesystemPromotionVolume],
        journal: &mut PromotionJournal,
    ) -> Result<()> {
        for volume_ref in volumes {
            let volume = PromotionStorageLookup::new(self.storage).volume(&volume_ref.volume_id)?;
            let manifest = PromotionLayerLookup::new(self.manifests).manifest_for_volume(volume)?;
            let layer_stage = root.join("layers").join(volume.id()).join("layer");
            OstreeTreeCheckout::new(
                self.storage.repo_path(),
                &volume_ref.layer_ref,
                &layer_stage,
                "checkout checkpoint layer",
            )
            .checkout(self.repository)?;
            PromotionVolumeApplier::new(root, &layer_stage, volume, manifest, journal).apply()?;
        }
        Ok(())
    }

    fn verify_all_preimages(
        &self,
        root: &Path,
        volumes: &[FilesystemPromotionVolume],
    ) -> Result<()> {
        for volume_ref in volumes {
            let volume = PromotionStorageLookup::new(self.storage).volume(&volume_ref.volume_id)?;
            let stage = PromotionWorkspace::preimage_stage_root(root, volume.id());
            let preimage = PromotionManifestStore::new(&stage).read_preimage()?;
            PromotionPreimageVerifier::new(volume, &preimage).verify()?;
        }
        Ok(())
    }
}

pub(super) struct PromotionWorkspace<'a> {
    storage: &'a FilesystemSessionStorage,
    promotion_id: &'a str,
}

impl<'a> PromotionWorkspace<'a> {
    pub(super) const fn new(storage: &'a FilesystemSessionStorage, promotion_id: &'a str) -> Self {
        Self {
            storage,
            promotion_id,
        }
    }

    pub(super) fn promotion_root(&self) -> PathBuf {
        self.storage
            .work_path()
            .join("promotions")
            .join(self.promotion_id)
    }

    pub(super) fn rollback_root(&self) -> PathBuf {
        self.storage
            .work_path()
            .join("rollbacks")
            .join(self.promotion_id)
    }

    pub(super) fn preimage_stage_root(root: &Path, volume_id: &str) -> PathBuf {
        root.join("volumes").join(volume_id).join("preimage")
    }
}

struct NoopPromotionHook;

impl PromotionHook for NoopPromotionHook {}

#[cfg(test)]
mod tests;
