use crate::{
    ostree::{OstreeRepository, OstreeTreeCheckout, SystemOstreeRepository},
    FilesystemSessionStorage, Result,
};

use super::{
    apply::PromotionVolumeRollback,
    ids::{PromotionId, PromotionStorageLookup},
    io::{PromotionManifestCheckout, PromotionManifestStore},
    journal::{PromotionJournal, PromotionJournalVerifier},
    lock::PromotionLock,
    FilesystemRollback, PromotionWorkspace,
};

impl FilesystemRollback {
    pub fn rollback_promotion(
        storage: &FilesystemSessionStorage,
        promotion_id: &str,
    ) -> Result<Self> {
        Self::rollback_promotion_using_repository(storage, promotion_id, &SystemOstreeRepository)
    }

    pub(crate) fn rollback_promotion_using_repository(
        storage: &FilesystemSessionStorage,
        promotion_id: &str,
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        Self::rollback_promotion_volumes_using_repository(storage, promotion_id, &[], repository)
    }

    pub(crate) fn rollback_promotion_volumes_using_repository(
        storage: &FilesystemSessionStorage,
        promotion_id: &str,
        selected_volume_ids: &[String],
        repository: &impl OstreeRepository,
    ) -> Result<Self> {
        PromotionRollbackWorkflow::new(storage, promotion_id, selected_volume_ids, repository)?
            .rollback()
    }
}

struct PromotionRollbackWorkflow<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    promotion_id: PromotionId<'a>,
    selected_volume_ids: &'a [String],
    repository: &'a R,
    workspace: PromotionWorkspace<'a>,
}

impl<'a, R> PromotionRollbackWorkflow<'a, R>
where
    R: OstreeRepository,
{
    fn new(
        storage: &'a FilesystemSessionStorage,
        promotion_id: &'a str,
        selected_volume_ids: &'a [String],
        repository: &'a R,
    ) -> Result<Self> {
        let promotion_id = PromotionId::new(promotion_id)?;
        Ok(Self {
            storage,
            promotion_id,
            selected_volume_ids,
            repository,
            workspace: PromotionWorkspace::new(storage, promotion_id.as_str()),
        })
    }

    fn rollback(&self) -> Result<FilesystemRollback> {
        let local_root = self.workspace.promotion_root();
        self.ensure_local_journal_not_incomplete(&local_root)?;
        let _lock = PromotionLock::acquire(self.storage.work_path())?;
        let journal = self.ensure_local_journal_not_incomplete(&local_root)?;
        let root = self.workspace.rollback_root();
        OstreeTreeCheckout::new(
            self.storage.repo_path(),
            &self.promotion_id.manifest_ref(),
            &root.join("manifest"),
            "checkout promotion manifest",
        )
        .checkout(self.repository)?;
        let manifest = PromotionManifestCheckout::new(&root).read_promotion()?;
        PromotionJournalVerifier::new(self.promotion_id.as_str())
            .ensure_manifest_or_journal_applied(&manifest, journal.as_ref())?;

        let mut restored = Vec::new();
        let selected = self
            .selected_volume_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        for volume_ref in manifest.volumes.iter().rev() {
            if !selected.is_empty() && !selected.contains(&volume_ref.volume_id.as_str()) {
                continue;
            }
            let volume = PromotionStorageLookup::new(self.storage).volume(&volume_ref.volume_id)?;
            let stage = PromotionWorkspace::preimage_stage_root(&root, volume.id());
            OstreeTreeCheckout::new(
                self.storage.repo_path(),
                &volume_ref.preimage_ref,
                &stage,
                "checkout promotion preimage",
            )
            .checkout(self.repository)?;
            let preimage = PromotionManifestStore::new(&stage).read_preimage()?;
            PromotionVolumeRollback::new(&stage, self.storage.work_path(), volume, &preimage)
                .rollback()?;
            restored.push(volume.id().to_owned());
        }
        Ok(FilesystemRollback::new(
            self.promotion_id.as_str(),
            restored,
        ))
    }

    fn ensure_local_journal_not_incomplete(
        &self,
        local_root: &std::path::Path,
    ) -> Result<Option<PromotionJournal>> {
        let journal = PromotionJournal::read_optional(local_root)?;
        if let Some(journal) = &journal {
            PromotionJournalVerifier::new(self.promotion_id.as_str())
                .ensure_journal_applied(journal)?;
        }
        Ok(journal)
    }
}
