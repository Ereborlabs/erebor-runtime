use std::{fs, os::unix::net::UnixListener};

use crate::{
    normalizer::normalize_session_layers,
    promotion::{promote_with_hook, FilesystemPromotionOptions, PromotionHook},
    FilesystemError, FilesystemLayerOperation, FilesystemPreimageEntryState,
    PREIMAGE_MANIFEST_FILE,
};

use super::support::{commit_checkpoint, fixture, FakeOstreeRunner, TestResult};

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
    let manifests = normalize_session_layers(&fixture.storage)?;
    assert!(matches!(
        manifests[0].operations.as_slice(),
        [FilesystemLayerOperation::OpaqueReplace { path, .. }] if path == "opaque"
    ));
    let runner = FakeOstreeRunner::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )?;

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

    crate::promotion::rollback_promotion_with_runner(&fixture.storage, "session-1", &runner)?;

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
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

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
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

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
