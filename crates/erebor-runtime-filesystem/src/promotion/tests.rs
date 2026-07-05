use std::{fs, os::unix::net::UnixListener, path::PathBuf};

use crate::{
    normalizer::normalize_session_layers,
    promotion::{
        journal::{PromotionJournal, PromotionJournalState},
        promote_with_hook, rollback_promotion, FilesystemPromotionOptions, PromotionHook,
        PREIMAGE_MANIFEST_FILE,
    },
    FilesystemError, FilesystemPreimageEntryState,
};

mod support;

use support::{fixture, FakeOstreeRunner, TestResult};

#[test]
fn promotion_applies_and_rollback_restores_create_replace_delete() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "{\"theme\":\"light\"}\n")?;
    fixture.seed_host("old-cache.txt", "old cache\n")?;
    fs::write(
        fixture.upper().join("settings.json"),
        "{\"theme\":\"dark\"}\n",
    )?;
    fs::write(fixture.upper().join(".wh.old-cache.txt"), "")?;
    fs::create_dir_all(fixture.upper().join("generated"))?;
    fs::write(fixture.upper().join("generated/token.txt"), "token\n")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();

    let promotion = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )?;

    assert_eq!(promotion.promotion_id(), "session-1");
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "{\"theme\":\"dark\"}\n"
    );
    assert!(!fixture.host().join("old-cache.txt").exists());
    assert_eq!(
        fs::read_to_string(fixture.host().join("generated/token.txt"))?,
        "token\n"
    );
    let preimage_path = fixture
        .storage
        .work_path()
        .join("promotions/session-1/volumes/project/preimage")
        .join(PREIMAGE_MANIFEST_FILE);
    let preimage: crate::FilesystemPreimageManifest =
        serde_json::from_str(&fs::read_to_string(preimage_path)?)?;
    assert!(preimage.entries.iter().any(|entry| {
        entry.path == "generated" && matches!(entry.state, FilesystemPreimageEntryState::Absent)
    }));
    assert!(preimage.entries.iter().any(|entry| {
        entry.path == "settings.json"
            && matches!(entry.state, FilesystemPreimageEntryState::Present { .. })
    }));
    assert!(runner.commands.borrow().iter().any(|args| {
        args.iter()
            .any(|arg| arg == "--branch=erebor/promotions/session-1/volumes/project/preimage")
    }));
    assert!(runner.commands.borrow().iter().any(|args| {
        args.iter()
            .any(|arg| arg == "--branch=erebor/promotions/session-1/manifest")
    }));

    let rollback = rollback_promotion(&fixture.storage, "session-1")?;

    assert_eq!(rollback.restored_volumes(), &[String::from("project")]);
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "{\"theme\":\"light\"}\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host().join("old-cache.txt"))?,
        "old cache\n"
    );
    assert!(!fixture.host().join("generated").exists());
    Ok(())
}

#[test]
fn preimage_size_limit_blocks_before_host_mutation() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "too-large\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();

    let result = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(2),
        &runner,
        &NoopHook,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionPreimageTooLarge { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "too-large\n"
    );
    Ok(())
}

#[test]
fn preimage_capture_failure_blocks_before_host_mutation() -> TestResult {
    let fixture = fixture()?;
    let listener = UnixListener::bind(fixture.host().join("old-cache.txt"))?;
    fs::write(fixture.upper().join(".wh.old-cache.txt"), "")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();

    let result = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    );

    drop(listener);
    assert!(matches!(
        result,
        Err(FilesystemError::UnsupportedLayer { .. })
    ));
    assert!(fixture.host().join("old-cache.txt").exists());
    Ok(())
}

#[test]
fn host_drift_after_preimage_commit_blocks_apply() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.json", "original\n")?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();
    let hook = DriftHook {
        path: fixture.host().join("settings.json"),
    };

    let result = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &hook,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionHostDrift { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.json"))?,
        "drift\n"
    );
    Ok(())
}

#[test]
fn rollback_refuses_incomplete_promotion_journal() -> TestResult {
    let fixture = fixture()?;
    let root = fixture.storage.work_path().join("promotions/session-1");
    let mut journal = PromotionJournal::new("session-1");
    journal.state = PromotionJournalState::Applying;
    journal
        .applied_operations
        .push(String::from("project:settings.json"));
    journal.write(&root)?;

    let result = rollback_promotion(&fixture.storage, "session-1");

    assert!(matches!(
        result,
        Err(FilesystemError::IncompletePromotion { .. })
    ));
    Ok(())
}

struct NoopHook;

impl PromotionHook for NoopHook {}

struct DriftHook {
    path: PathBuf,
}

impl PromotionHook for DriftHook {
    fn before_apply(&self) -> crate::Result<()> {
        fs::write(&self.path, "drift\n").map_err(|source| FilesystemError::PromotionIo {
            action: "write drift hook",
            path: self.path.clone(),
            source,
            location: snafu::Location::default(),
        })
    }
}
