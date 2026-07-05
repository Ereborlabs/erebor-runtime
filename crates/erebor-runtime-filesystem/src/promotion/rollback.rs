use std::path::PathBuf;

use crate::{
    ostree::{OstreeCommandRunner, SystemOstreeCommandRunner},
    FilesystemSessionStorage, Result,
};

use super::{
    apply,
    checkout::checkout_tree,
    ids::{validate_promotion_id, volume_for_id},
    io::{read_preimage_manifest, read_promotion_manifest},
    journal::{self, PromotionJournal},
    lock::PromotionLock,
    preimage_stage_root, promotion_manifest_ref, promotion_root, FilesystemRollback,
};

pub fn rollback_promotion(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
) -> Result<FilesystemRollback> {
    rollback_promotion_with_runner(storage, promotion_id, &SystemOstreeCommandRunner)
}

pub(crate) fn rollback_promotion_with_runner(
    storage: &FilesystemSessionStorage,
    promotion_id: &str,
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemRollback> {
    validate_promotion_id(promotion_id)?;
    let local_root = promotion_root(storage, promotion_id);
    ensure_local_journal_not_incomplete(promotion_id, &local_root)?;
    let _lock = PromotionLock::acquire(storage.work_path())?;
    let journal = ensure_local_journal_not_incomplete(promotion_id, &local_root)?;
    let root = rollback_root(storage, promotion_id);
    checkout_tree(
        runner,
        storage.repo_path(),
        &promotion_manifest_ref(promotion_id)?,
        &root.join("manifest"),
        "checkout promotion manifest",
    )?;
    let manifest = read_promotion_manifest(&root)?;
    journal::ensure_manifest_or_journal_applied(promotion_id, &manifest, journal.as_ref())?;

    let mut restored = Vec::new();
    for volume_ref in manifest.volumes.iter().rev() {
        let volume = volume_for_id(storage, &volume_ref.volume_id)?;
        let stage = preimage_stage_root(&root, volume.id());
        checkout_tree(
            runner,
            storage.repo_path(),
            &volume_ref.preimage_ref,
            &stage,
            "checkout promotion preimage",
        )?;
        let preimage = read_preimage_manifest(&stage)?;
        apply::rollback_volume(&stage, volume, &preimage)?;
        restored.push(volume.id().to_owned());
    }
    Ok(FilesystemRollback::new(promotion_id, restored))
}

fn ensure_local_journal_not_incomplete(
    promotion_id: &str,
    local_root: &std::path::Path,
) -> Result<Option<PromotionJournal>> {
    let journal = PromotionJournal::read_optional(local_root)?;
    if let Some(journal) = &journal {
        journal::ensure_journal_applied(promotion_id, journal)?;
    }
    Ok(journal)
}

fn rollback_root(storage: &FilesystemSessionStorage, promotion_id: &str) -> PathBuf {
    storage.work_path().join("rollbacks").join(promotion_id)
}
