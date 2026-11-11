use super::*;

#[test]
fn backup_usage_preserves_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    store.checkpoint()?;
    let before = store.storage_usage()?;
    let meta = store.meta()?;
    for invalid in [
        directory.path().join("outside"),
        root.join("fjall"),
        root.join("backups/nested/copy"),
        root.join("backups/../escape"),
        root.join("backups/copy.manifest.json"),
    ] {
        assert!(store.backup(&invalid).is_err());
    }
    let backup = root.join("backups/first");
    let manifest = store.backup(&backup)?;
    let saved = files(&backup)?;
    let usage = store.storage_usage()?;
    assert!(usage.file_bytes >= before.file_bytes + manifest.database_bytes);
    assert!(usage.allocated_bytes > before.allocated_bytes);
    assert_eq!(
        fs::metadata(root.join("backups"))?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(store.meta()?, meta);
    assert_eq!(files(&backup)?, saved);
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let usage = store.storage_usage()?;
    assert_eq!(
        (usage.file_bytes, usage.allocated_bytes),
        charged_files(&root)?
    );
    assert_eq!(store.meta()?, meta);
    assert_eq!(files(&backup)?, saved);
    let external = directory.path().join("external");
    fs::rename(&backup, &external)?;
    let restored = AnalysisStore::restore(&external, &directory.path().join("restored"))?;
    assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
    Ok(())
}
