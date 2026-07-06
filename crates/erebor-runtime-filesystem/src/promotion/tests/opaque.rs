use std::{fs, os::unix::net::UnixListener};

use crate::{
    promotion::{FilesystemPromotionOptions, FilesystemRollback, PromotionHook},
    FilesystemError, FilesystemLayerOperation, FilesystemPreimageEntryState,
    PREIMAGE_MANIFEST_FILE,
};

use super::support::{
    commit_checkpoint, fixture, FakeOstreeRepository, PromotionTestWorkflow, TestResult,
};

#[test]
fn opaque_replace_promotion_and_rollback_restore_hidden_subtree() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("opaque/old.txt", "old\n")?;
    fixture.seed_host("opaque/common.txt", "old common\n")?;
    fixture.seed_host("opaque/sub/lower.txt", "lower\n")?;
    fs::create_dir_all(fixture.upper().join("opaque/sub"))?;
    fs::write(fixture.upper().join("opaque/.wh..wh..opq"), "")?;
    fs::write(fixture.upper().join("opaque/.wh.old.txt"), "")?;
    fs::write(fixture.upper().join("opaque/common.txt"), "new common\n")?;
    fs::write(fixture.upper().join("opaque/new.txt"), "new\n")?;
    fs::write(fixture.upper().join("opaque/sub/new.txt"), "nested\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    assert!(matches!(
        manifests[0].operations.as_slice(),
        [FilesystemLayerOperation::OpaqueReplace { path, .. }] if path == "opaque"
    ));
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

    assert!(!fixture.host().join("opaque/old.txt").exists());
    assert!(!fixture.host().join("opaque/.wh.old.txt").exists());
    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/common.txt"))?,
        "new common\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/sub/new.txt"))?,
        "nested\n"
    );
    assert!(!fixture.host().join("opaque/sub/lower.txt").exists());
    let preimage = preimage_manifest(&fixture)?;
    assert!(preimage.entries.iter().any(|entry| {
        entry.path == "opaque"
            && matches!(entry.state, FilesystemPreimageEntryState::Present { .. })
    }));

    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/old.txt"))?,
        "old\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/common.txt"))?,
        "old common\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/sub/lower.txt"))?,
        "lower\n"
    );
    assert!(!fixture.host().join("opaque/new.txt").exists());
    Ok(())
}

#[test]
fn opaque_replace_preimage_size_limit_blocks_before_mutation() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("opaque/old.txt", "too-large\n")?;
    fs::create_dir_all(fixture.upper().join("opaque"))?;
    fs::write(fixture.upper().join("opaque/.wh..wh..opq"), "")?;
    fs::write(fixture.upper().join("opaque/new.txt"), "new\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(2),
        &runner,
        &NoopHook,
    )
    .promote();

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionPreimageTooLarge { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("opaque/old.txt"))?,
        "too-large\n"
    );
    assert!(!fixture.host().join("opaque/new.txt").exists());
    Ok(())
}

#[test]
fn opaque_replace_special_hidden_entry_blocks_before_mutation() -> TestResult {
    let fixture = fixture()?;
    fs::create_dir_all(fixture.host().join("opaque"))?;
    let listener = UnixListener::bind(fixture.host().join("opaque/socket"))?;
    fs::create_dir_all(fixture.upper().join("opaque"))?;
    fs::write(fixture.upper().join("opaque/.wh..wh..opq"), "")?;
    fs::write(fixture.upper().join("opaque/new.txt"), "new\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote();

    drop(listener);
    assert!(matches!(
        result,
        Err(FilesystemError::UnsupportedLayer { .. })
    ));
    assert!(fixture.host().join("opaque/socket").exists());
    assert!(!fixture.host().join("opaque/new.txt").exists());
    Ok(())
}

fn preimage_manifest(
    fixture: &super::support::Fixture,
) -> Result<crate::FilesystemPreimageManifest, Box<dyn std::error::Error>> {
    let path = fixture
        .storage
        .work_path()
        .join("promotions/session-1/volumes/project/preimage")
        .join(PREIMAGE_MANIFEST_FILE);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

struct NoopHook;

impl PromotionHook for NoopHook {}
