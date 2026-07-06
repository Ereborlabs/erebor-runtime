use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    checkpoint::FilesystemCheckpointCommit,
    promotion::{
        FilesystemPromotionOptions, FilesystemSubtransactionState, FilesystemTransactionCatalog,
        FilesystemTransactionRename, FilesystemTransactionRollback, FilesystemTransactionState,
        FilesystemTransactionTarget, PromotionHook,
    },
    storage::FilesystemStoragePreparer,
    FilesystemLayerManifest, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};

use super::support::{FakeOstreeRepository, PromotionTestWorkflow, TestResult};

#[test]
fn catalog_lists_renames_and_rolls_back_subtransactions() -> TestResult {
    let fixture = MultiVolumeFixture::new()?;
    fixture.seed_host("project", "settings.txt", "light\n")?;
    fixture.seed_host("project", "old-cache.txt", "old cache\n")?;
    fixture.seed_host("cache", "cache.txt", "cold\n")?;
    write_upper(&fixture, "project", "settings.txt", "dark\n")?;
    fs::write(fixture.upper("project")?.join(".wh.old-cache.txt"), "")?;
    write_upper(&fixture, "cache", "cache.txt", "warm\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture.storage, &manifests, &runner)?;
    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote()?;
    fs::remove_dir_all(fixture.storage.work_path().join("promotions/session-1"))?;

    let catalog = FilesystemTransactionCatalog::load_using_repository(&fixture.storage, &runner)?;

    assert_eq!(catalog.transactions().len(), 1);
    let transaction = &catalog.transactions()[0];
    assert_eq!(transaction.handle(), "tx@{0}");
    assert_eq!(transaction.promotion_id(), "session-1");
    assert_eq!(transaction.state(), FilesystemTransactionState::Applied);
    assert_eq!(transaction.subtransactions().len(), 2);

    let project_handle = transaction
        .subtransactions()
        .iter()
        .find(|subtransaction| subtransaction.volume_id() == "project")
        .ok_or_else(|| std::io::Error::other("missing project subtransaction"))?
        .handle()
        .to_owned();
    FilesystemTransactionRename::rename_using_repository(
        &fixture.storage,
        &project_handle,
        "project restore",
        &runner,
    )?;
    assert_project_show_by_name(&fixture, &runner)?;

    let rollback = FilesystemTransactionRollback::rollback_using_repository(
        &fixture.storage,
        "project restore",
        &runner,
    )?;

    assert_eq!(rollback.restored_volumes(), &[String::from("project")]);
    assert_eq!(
        fs::read_to_string(fixture.host("project")?.join("settings.txt"))?,
        "light\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host("cache")?.join("cache.txt"))?,
        "warm\n"
    );
    let catalog = FilesystemTransactionCatalog::load_using_repository(&fixture.storage, &runner)?;
    assert_eq!(
        catalog.transactions()[0].state(),
        FilesystemTransactionState::PartiallyRestored
    );
    let project = catalog.transactions()[0]
        .subtransactions()
        .iter()
        .find(|subtransaction| subtransaction.volume_id() == "project")
        .ok_or_else(|| std::io::Error::other("missing project subtransaction"))?;
    assert_eq!(project.state(), FilesystemSubtransactionState::Restored);

    let rollback = FilesystemTransactionRollback::rollback_using_repository(
        &fixture.storage,
        "tx@{0}",
        &runner,
    )?;

    assert_eq!(rollback.restored_volumes(), &[String::from("cache")]);
    assert_eq!(
        fs::read_to_string(fixture.host("cache")?.join("cache.txt"))?,
        "cold\n"
    );
    let rollback = FilesystemTransactionRollback::rollback_using_repository(
        &fixture.storage,
        "project restore",
        &runner,
    )?;
    assert!(rollback.restored_volumes().is_empty());
    assert_transaction_journal(&fixture)?;
    Ok(())
}

fn assert_transaction_journal(fixture: &MultiVolumeFixture) -> TestResult {
    let journal = fs::read_to_string(
        fixture
            .storage
            .root()
            .join("transaction-catalog/erebor-transaction-catalog.jsonl"),
    )?;
    assert!(journal.contains("\"event\":\"rename\""));
    assert!(journal.contains("\"event\":\"rollback\""));
    assert!(journal.contains("\"promotion_id\":\"session-1\""));
    assert!(journal.contains("\"outcome\":\"success\""));
    assert!(journal.contains("\"outcome\":\"already_restored\""));
    assert!(journal.contains("erebor/promotions/session-1/manifest"));
    assert!(journal.contains("erebor/promotions/session-1/volumes/project/preimage"));
    assert!(journal.contains("erebor/promotions/session-1/volumes/cache/preimage"));
    Ok(())
}

fn assert_project_show_by_name(
    fixture: &MultiVolumeFixture,
    runner: &FakeOstreeRepository,
) -> TestResult {
    let target = FilesystemTransactionTarget::show_using_repository(
        &fixture.storage,
        "project restore",
        runner,
    )?;
    let FilesystemTransactionTarget::Subtransaction(subtransaction) = target else {
        return Err(std::io::Error::other("expected subtransaction target").into());
    };
    assert_eq!(subtransaction.name(), Some("project restore"));
    assert!(subtransaction
        .changes()
        .iter()
        .any(|change| change.operation() == "replace" && change.path() == "settings.txt"));
    assert!(subtransaction
        .changes()
        .iter()
        .any(|change| change.operation() == "delete" && change.path() == "old-cache.txt"));
    Ok(())
}

struct MultiVolumeFixture {
    storage: FilesystemSessionStorage,
    root: PathBuf,
    host_project: PathBuf,
    host_cache: PathBuf,
}

impl MultiVolumeFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "erebor-filesystem-catalog-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        let host_project = root.join("host/project");
        let host_cache = root.join("host/cache");
        let session_project = root.join("workspace/project");
        let session_cache = root.join("workspace/cache");
        for path in [&host_project, &host_cache, &session_project, &session_cache] {
            fs::create_dir_all(path)?;
        }
        let requests = vec![
            FilesystemVolumeStorageRequest::new(
                "project",
                &host_project,
                &session_project,
                FilesystemVolumeMode::Writable,
            )?,
            FilesystemVolumeStorageRequest::new(
                "cache",
                &host_cache,
                &session_cache,
                FilesystemVolumeMode::Writable,
            )?,
        ];
        let storage =
            FilesystemStoragePreparer::new(&root.join("session"), requests).prepare(|_| Ok(()))?;
        Ok(Self {
            storage,
            root,
            host_project,
            host_cache,
        })
    }

    fn host(&self, volume_id: &str) -> Result<&Path, std::io::Error> {
        match volume_id {
            "project" => Ok(self.host_project.as_path()),
            "cache" => Ok(self.host_cache.as_path()),
            _ => Err(std::io::Error::other(format!("unknown volume {volume_id}"))),
        }
    }

    fn upper(&self, volume_id: &str) -> Result<PathBuf, std::io::Error> {
        self.storage
            .volumes()
            .iter()
            .find(|volume| volume.id() == volume_id)
            .map(|volume| volume.overlay().upper_path().to_path_buf())
            .ok_or_else(|| std::io::Error::other(format!("unknown volume {volume_id}")))
    }

    fn seed_host(&self, volume_id: &str, relative: &str, source: &str) -> TestResult {
        write_file(self.host(volume_id)?.join(relative), source)
    }
}

impl Drop for MultiVolumeFixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

fn commit_checkpoint(
    storage: &FilesystemSessionStorage,
    manifests: &[FilesystemLayerManifest],
    runner: &FakeOstreeRepository,
) -> crate::Result<()> {
    FilesystemCheckpointCommit::commit_normalized_using_repository(
        storage,
        "session-1",
        manifests,
        runner,
    )?;
    Ok(())
}

fn write_upper(
    fixture: &MultiVolumeFixture,
    volume_id: &str,
    relative: &str,
    source: &str,
) -> TestResult {
    write_file(fixture.upper(volume_id)?.join(relative), source)
}

fn write_file(path: PathBuf, source: &str) -> TestResult {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("test path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(path, source)?;
    Ok(())
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

struct NoopHook;

impl PromotionHook for NoopHook {}
