use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::{ensure, ResultExt};

use crate::{
    checkpoint::{commit_normalized_session_checkpoint_with_runner, commit_tree},
    error::{IncompletePromotionSnafu, PromotionIoSnafu},
    normalizer::normalize_session_layers,
    ostree::{OstreeCommandRunner, SystemOstreeCommandRunner},
    FilesystemLayerManifest, FilesystemSessionStorage, Result,
};

mod apply;
mod ids;
mod io;
mod journal;
mod lock;
mod manifest;
mod metadata;
mod path;
mod preimage;
mod types;

pub use ids::{promotion_manifest_ref, promotion_preimage_ref};
pub use manifest::{
    FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
    FilesystemPreimageManifest, FilesystemPromotionManifest, FilesystemPromotionState,
    FilesystemPromotionVolume, PREIMAGE_MANIFEST_FILE, PREIMAGE_MANIFEST_KIND,
    PROMOTION_MANIFEST_FILE, PROMOTION_MANIFEST_KIND,
};
pub use types::{FilesystemPromotion, FilesystemPromotionOptions, FilesystemRollback};

use ids::{manifest_for_volume, validate_promotion_id, volume_for_id};
use io::{
    read_preimage_manifest, read_promotion_manifest, write_preimage_manifest,
    write_promotion_manifest,
};
use journal::{PromotionJournal, PromotionJournalState};
use lock::PromotionLock;
use preimage::{capture_volume_preimage, verify_preimage_matches_host};

pub fn promote_session_checkpoint(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
    options: FilesystemPromotionOptions,
) -> Result<FilesystemPromotion> {
    let manifests = normalize_session_layers(storage)?;
    let checkpoint = commit_normalized_session_checkpoint_with_runner(
        storage,
        promotion_id,
        &manifests,
        &SystemOstreeCommandRunner,
    )?;
    promote_normalized_session_checkpoint_with_runner(
        storage,
        promotion_id,
        checkpoint.checkpoint_ref(),
        &manifests,
        options,
        &SystemOstreeCommandRunner,
    )
}

pub fn rollback_promotion(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
) -> Result<FilesystemRollback> {
    validate_promotion_id(promotion_id)?;
    let _lock = PromotionLock::acquire(storage.work_path())?;
    let root = promotion_root(storage, promotion_id);
    let journal = PromotionJournal::read(&root)?;
    ensure!(
        journal.state == PromotionJournalState::Applied,
        IncompletePromotionSnafu {
            promotion_id: promotion_id.to_owned(),
            reason: format!(
                "journal state is {:?} with applied operations {:?}",
                journal.state, journal.applied_operations
            )
        }
    );
    let manifest = read_promotion_manifest(&root)?;
    let mut restored = Vec::new();
    for volume_ref in manifest.volumes.iter().rev() {
        let volume = volume_for_id(storage, &volume_ref.volume_id)?;
        let stage = preimage_stage_root(&root, volume.id());
        let preimage = read_preimage_manifest(&stage)?;
        apply::rollback_volume(&stage, volume, &preimage)?;
        restored.push(volume.id().to_owned());
    }
    Ok(FilesystemRollback::new(promotion_id, restored))
}

pub(crate) fn promote_normalized_session_checkpoint_with_runner(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
    checkpoint_ref: &str,
    manifests: &[FilesystemLayerManifest],
    options: FilesystemPromotionOptions,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemPromotion> {
    promote_with_hook(
        storage,
        promotion_id,
        checkpoint_ref,
        manifests,
        options,
        runner,
        &NoopPromotionHook,
    )
}

pub(crate) trait PromotionHook {
    fn before_apply(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) fn promote_with_hook(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
    checkpoint_ref: &str,
    manifests: &[FilesystemLayerManifest],
    options: FilesystemPromotionOptions,
    runner: &impl OstreeCommandRunner,
    hook: &impl PromotionHook,
) -> Result<FilesystemPromotion> {
    validate_promotion_id(promotion_id)?;
    let _lock = PromotionLock::acquire(storage.work_path())?;
    let root = promotion_root(storage, promotion_id);
    fail_if_existing_incomplete(&root, promotion_id)?;
    fs::create_dir_all(&root).context(PromotionIoSnafu {
        action: "create promotion work directory",
        path: root.as_path(),
    })?;

    let volumes = commit_preimages(storage, promotion_id, manifests, options, runner, &root)?;
    commit_promotion_manifest(
        storage,
        runner,
        &root,
        promotion_id,
        checkpoint_ref,
        FilesystemPromotionState::PreimageCommitted,
        volumes.clone(),
    )?;
    let mut journal = PromotionJournal::new(promotion_id);
    journal.write(&root)?;
    verify_all_preimages(storage, &root, &volumes)?;
    hook.before_apply()?;
    verify_all_preimages(storage, &root, &volumes)?;
    apply_all_volumes(storage, manifests, &root, &mut journal)?;
    journal.state = PromotionJournalState::Applied;
    journal.write(&root)?;
    let manifest_path = commit_promotion_manifest(
        storage,
        runner,
        &root,
        promotion_id,
        checkpoint_ref,
        FilesystemPromotionState::Applied,
        volumes.clone(),
    )?;

    Ok(FilesystemPromotion::new(
        promotion_id,
        manifest_path,
        volumes,
    ))
}

fn commit_preimages(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
    manifests: &[FilesystemLayerManifest],
    options: FilesystemPromotionOptions,
    runner: &impl OstreeCommandRunner,
    root: &Path,
) -> Result<Vec<FilesystemPromotionVolume>> {
    let mut volumes = Vec::new();
    for volume in storage.volumes() {
        let manifest = manifest_for_volume(manifests, volume)?;
        let preimage_ref = promotion_preimage_ref(promotion_id, volume.id())?;
        let stage = preimage_stage_root(root, volume.id());
        let preimage = capture_volume_preimage(
            &stage,
            promotion_id,
            volume,
            manifest,
            options.preimage_size_limit_bytes(),
        )?;
        write_preimage_manifest(&stage, &preimage)?;
        commit_tree(
            runner,
            storage.repo_path(),
            &preimage_ref,
            &stage,
            "commit promotion preimage",
            &format!(
                "Erebor filesystem promotion {promotion_id} volume {} preimage",
                volume.id()
            ),
        )?;
        volumes.push(FilesystemPromotionVolume {
            volume_id: volume.id().to_owned(),
            layer_ref: crate::volume_layer_ref(promotion_id, volume.id())?,
            preimage_ref,
        });
    }
    Ok(volumes)
}

fn commit_promotion_manifest(
    storage: &FilesystemSessionStorage,
    runner: &impl OstreeCommandRunner,
    root: &Path,
    promotion_id: &str,
    checkpoint_ref: &str,
    state: FilesystemPromotionState,
    volumes: Vec<FilesystemPromotionVolume>,
) -> Result<PathBuf> {
    let manifest_ref = promotion_manifest_ref(promotion_id)?;
    let manifest = FilesystemPromotionManifest::new(promotion_id, checkpoint_ref, state, volumes);
    let stage = root.join("manifest");
    let path = write_promotion_manifest(&stage, &manifest)?;
    commit_tree(
        runner,
        storage.repo_path(),
        &manifest_ref,
        &stage,
        "commit promotion manifest",
        &format!("Erebor filesystem promotion {promotion_id} manifest"),
    )?;
    Ok(path)
}

fn apply_all_volumes(
    storage: &FilesystemSessionStorage,
    manifests: &[FilesystemLayerManifest],
    root: &Path,
    journal: &mut PromotionJournal,
) -> Result<()> {
    for volume in storage.volumes() {
        let manifest = manifest_for_volume(manifests, volume)?;
        apply::apply_volume_layer(root, volume, manifest, journal)?;
    }
    Ok(())
}

fn verify_all_preimages(
    storage: &FilesystemSessionStorage,
    root: &Path,
    volumes: &[FilesystemPromotionVolume],
) -> Result<()> {
    for volume_ref in volumes {
        let volume = volume_for_id(storage, &volume_ref.volume_id)?;
        let stage = preimage_stage_root(root, volume.id());
        let preimage = read_preimage_manifest(&stage)?;
        verify_preimage_matches_host(volume, &preimage)?;
    }
    Ok(())
}

fn fail_if_existing_incomplete(root: &Path, promotion_id: &str) -> Result<()> {
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

fn promotion_root(storage: &FilesystemSessionStorage, promotion_id: &str) -> PathBuf {
    storage.work_path().join("promotions").join(promotion_id)
}

fn preimage_stage_root(root: &Path, volume_id: &str) -> PathBuf {
    root.join("volumes").join(volume_id).join("preimage")
}

struct NoopPromotionHook;

impl PromotionHook for NoopPromotionHook {}

#[cfg(test)]
mod tests;
