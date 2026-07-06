use std::fs;

use crate::{
    ostree::OstreeRepository,
    promotion::{
        FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemRetentionState,
        FilesystemTransactionRollback, PROMOTION_MANIFEST_FILE,
    },
    FilesystemError, FilesystemRetainedArtifactStatus, FilesystemRetainedRefKind,
};

use super::{
    support::{
        commit_checkpoint, fixture, FakeOstreeRepository, PromotionTestWorkflow, TestResult,
    },
    NoopHook,
};

#[test]
fn retention_inventory_lists_refs_and_writes_audit_event() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;

    let inventory = FilesystemRetentionInventory::load_using_repository(&fixture.storage, &runner)?;

    let transaction = &inventory.transactions()[0];
    assert_eq!(transaction.handle(), "tx@{0}");
    assert_eq!(transaction.state(), FilesystemRetentionState::Applied);
    assert!(transaction.refs().iter().any(|reference| {
        reference.kind() == FilesystemRetainedRefKind::PromotionManifest
            && reference.protected()
            && reference.required_for_rollback()
    }));
    assert!(transaction.subtransactions()[0]
        .refs()
        .iter()
        .any(|reference| reference.kind() == FilesystemRetainedRefKind::CheckpointLayer));
    let journal = fs::read_to_string(
        fixture
            .storage
            .root()
            .join("retention/erebor-retention.jsonl"),
    )?;
    assert!(journal.contains("\"event\":\"list\""));
    Ok(())
}

#[test]
fn retention_prune_refuses_applied_transaction() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;

    let result =
        FilesystemRetentionPrune::prune_using_repository(&fixture.storage, "tx@{0}", &runner);

    assert!(matches!(
        result,
        Err(FilesystemError::ProtectedRetentionTarget { .. })
    ));
    assert!(runner
        .list_refs(fixture.storage.repo_path())?
        .iter()
        .any(|reference| reference == "erebor/promotions/session-1/manifest"));
    Ok(())
}

#[test]
fn retention_prunes_restored_transaction_refs_and_workdirs() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;
    FilesystemTransactionRollback::rollback_using_repository(&fixture.storage, "tx@{0}", &runner)?;

    let prune =
        FilesystemRetentionPrune::prune_using_repository(&fixture.storage, "tx@{0}", &runner)?;

    assert!(prune
        .pruned_refs()
        .iter()
        .any(|reference| { reference.reference() == "erebor/promotions/session-1/manifest" }));
    assert!(!runner
        .list_refs(fixture.storage.repo_path())?
        .iter()
        .any(|reference| reference.contains("session-1")));
    assert!(!fixture
        .storage
        .work_path()
        .join("promotions/session-1")
        .exists());
    assert!(runner
        .commands
        .borrow()
        .iter()
        .any(|command| command.first().is_some_and(|name| name == "prune")));
    let journal = fs::read_to_string(
        fixture
            .storage
            .root()
            .join("retention/erebor-retention.jsonl"),
    )?;
    assert!(journal.contains("\"event\":\"prune\""));
    assert!(journal.contains("\"outcome\":\"success\""));
    Ok(())
}

#[test]
fn retention_prunes_restored_subtransaction_preimage_without_layer_ref() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;
    FilesystemTransactionRollback::rollback_using_repository(&fixture.storage, "tx@{0}", &runner)?;

    let prune = FilesystemRetentionPrune::prune_using_repository(
        &fixture.storage,
        "tx@{0}.sub@{0}",
        &runner,
    )?;

    assert_eq!(prune.pruned_refs().len(), 1);
    assert_eq!(
        prune.pruned_refs()[0].kind(),
        FilesystemRetainedRefKind::PromotionPreimage
    );
    let refs = runner.list_refs(fixture.storage.repo_path())?;
    assert!(refs
        .iter()
        .any(|reference| reference == "erebor/promotions/session-1/manifest"));
    assert!(refs
        .iter()
        .any(|reference| { reference == "erebor/checkpoints/session-1/volumes/project/layer" }));
    assert!(!refs
        .iter()
        .any(|reference| { reference == "erebor/promotions/session-1/volumes/project/preimage" }));
    Ok(())
}

#[test]
fn retention_inventory_reports_missing_expected_ref() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;
    runner.forget_ref("erebor/checkpoints/session-1/volumes/project/layer");

    let inventory = FilesystemRetentionInventory::load_using_repository(&fixture.storage, &runner)?;
    let layer = inventory.transactions()[0].subtransactions()[0]
        .refs()
        .iter()
        .find(|reference| reference.kind() == FilesystemRetainedRefKind::CheckpointLayer)
        .ok_or_else(|| std::io::Error::other("missing checkpoint layer retention ref"))?;

    assert_eq!(layer.status(), FilesystemRetainedArtifactStatus::Missing);
    Ok(())
}

#[test]
fn retention_inventory_reports_corrupt_promotion_manifest() -> TestResult {
    let fixture = fixture()?;
    let runner = RetentionPromotionScenario::new(&fixture).promote()?;
    fs::write(
        runner
            .committed_tree("erebor/promotions/session-1/manifest")
            .join(PROMOTION_MANIFEST_FILE),
        "{",
    )?;

    let inventory = FilesystemRetentionInventory::load_using_repository(&fixture.storage, &runner)?;
    let transaction = &inventory.transactions()[0];

    assert_eq!(transaction.state(), FilesystemRetentionState::Corrupt);
    assert_eq!(
        transaction.refs()[0].status(),
        FilesystemRetainedArtifactStatus::Corrupt
    );
    assert!(transaction.refs()[0].protected());
    Ok(())
}

struct RetentionPromotionScenario<'a> {
    fixture: &'a super::support::Fixture,
}

impl<'a> RetentionPromotionScenario<'a> {
    const fn new(fixture: &'a super::support::Fixture) -> Self {
        Self { fixture }
    }

    fn promote(&self) -> Result<FakeOstreeRepository, Box<dyn std::error::Error>> {
        self.fixture
            .seed_host("settings.json", "{\"theme\":\"light\"}\n")?;
        fs::write(
            self.fixture.upper().join("settings.json"),
            "{\"theme\":\"dark\"}\n",
        )?;
        let manifests = self.fixture.storage.normalize_layers()?;
        let runner = FakeOstreeRepository::successful();
        commit_checkpoint(self.fixture, &manifests, &runner)?;
        PromotionTestWorkflow::new(
            &self.fixture.storage,
            &manifests,
            crate::promotion::FilesystemPromotionOptions::new(1024 * 1024),
            &runner,
            &NoopHook,
        )
        .promote()?;
        Ok(runner)
    }
}
