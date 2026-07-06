use std::{fs, path::PathBuf};

use rustix::fs::{lsetxattr, XattrFlags};

use crate::{
    ostree::OstreeTreeCommit,
    promotion::{
        ids::PromotionId, io::PromotionManifestStore, journal::PromotionJournal,
        FilesystemPromotionManifest, FilesystemPromotionOptions, FilesystemPromotionState,
        FilesystemRollback, PromotionHook,
    },
    FilesystemError,
};

use super::{
    support::{
        commit_checkpoint, fixture, FakeOstreeOutcome, FakeOstreeRepository, PromotionTestWorkflow,
        TestResult,
    },
    NoopHook,
};

#[test]
fn metadata_sidecars_are_audited_without_blocking_promotion() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    lsetxattr(
        fixture.upper().join("settings.json").as_path(),
        "user.overlay.origin",
        b"y",
        XattrFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    let manifests = fixture.storage.normalize_layers()?;
    assert!(!manifests[0].metadata_sidecars.is_empty());
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote()?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "changed\n"
    );
    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "original\n"
    );
    Ok(())
}

#[test]
fn promotion_manifest_commit_failure_before_apply_leaves_host_unchanged() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::from_outcomes(vec![
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::failed(Some(44), "pre-apply manifest failed"),
    ]);
    commit_checkpoint(&fixture, &manifests, &runner)?;

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote();

    assert!(matches!(
        result,
        Err(FilesystemError::OstreeCommandFailed {
            operation: "commit promotion manifest",
            ..
        })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "original\n"
    );
    assert!(
        !PromotionJournal::path(&fixture.storage.work_path().join("promotions/session-1")).exists()
    );
    Ok(())
}

#[test]
fn final_manifest_commit_failure_keeps_rollback_possible() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::from_outcomes(vec![
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::failed(Some(45), "final manifest failed"),
    ]);
    commit_checkpoint(&fixture, &manifests, &runner)?;

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote();

    assert!(matches!(
        result,
        Err(FilesystemError::OstreeCommandFailed {
            operation: "commit promotion manifest",
            ..
        })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "changed\n"
    );
    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "original\n"
    );
    Ok(())
}

#[test]
fn promotion_applies_committed_layer_after_upperdir_mutation() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "checkpoint\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;
    let hook = UpperdirDriftHook {
        path: fixture.upper().join("settings.json"),
    };

    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &hook,
    )
    .promote()?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "checkpoint\n"
    );
    Ok(())
}

#[test]
fn rollback_uses_committed_preimage_after_workdir_deleted() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote()?;
    fs::remove_dir_all(fixture.storage.work_path().join("promotions/session-1"))?;

    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "original\n"
    );
    Ok(())
}

#[test]
fn rollback_refuses_preimage_committed_manifest_without_applied_journal() -> TestResult {
    let fixture = fixture()?;
    let root = fixture.storage.work_path().join("promotions/session-1");
    let manifest = FilesystemPromotionManifest::new(
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        FilesystemPromotionState::PreimageCommitted,
        Vec::new(),
    );
    PromotionManifestStore::new(&root.join("manifest")).write_promotion(&manifest)?;
    let runner = FakeOstreeRepository::successful();
    OstreeTreeCommit::new(
        fixture.storage.repo_path(),
        &PromotionId::new("session-1")?.manifest_ref(),
        &root.join("manifest"),
        "commit promotion manifest",
        "test preimage committed promotion manifest",
    )
    .commit(&runner)?;
    let result = FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::IncompletePromotion { .. })
    ));
    Ok(())
}

struct UpperdirDriftHook {
    path: PathBuf,
}

impl PromotionHook for UpperdirDriftHook {
    fn before_apply(&self) -> crate::Result<()> {
        fs::write(&self.path, "tampered\n").map_err(|source| FilesystemError::PromotionIo {
            action: "write upperdir drift hook",
            path: self.path.clone(),
            source,
            location: snafu::Location::default(),
        })
    }
}
