use super::*;

#[test]
fn bundle_rejects_physical_faults() -> TestResult {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    let backup = root.join("backups/saved");
    let manifest = store.backup(&backup)?;
    let value = serde_json::to_value(&manifest)?;
    assert!(value.get("database_sha256").is_none());
    assert!(value["segments"][0].get("sha256").is_none());
    let segment = backup
        .join("segments")
        .join(&manifest.segments[0].file_name);
    let bytes = fs::read(&segment)?;
    let target = directory.path().join("restored");
    let rejected = || -> TestResult {
        assert!(AnalysisStore::restore(&backup, &target).is_err());
        assert!(!target.exists());
        Ok(())
    };
    let moved = directory.path().join("saved-segment");
    fs::rename(&segment, &moved)?;
    rejected()?;
    symlink(&moved, &segment)?;
    rejected()?;
    fs::remove_file(&segment)?;
    fs::rename(&moved, &segment)?;
    let mut changed = bytes.clone();
    *changed.last_mut().ok_or("segment bytes")? ^= 1;
    fs::write(&segment, &changed)?;
    rejected()?;
    fs::write(&segment, &bytes)?;
    fs::set_permissions(&segment, fs::Permissions::from_mode(0o644))?;
    rejected()?;
    fs::set_permissions(&segment, fs::Permissions::from_mode(0o600))?;
    let unknown = backup.join("segments/unknown");
    fs::write(&unknown, b"do not remove")?;
    rejected()?;
    assert_eq!(fs::read(&unknown)?, b"do not remove");
    fs::remove_file(&unknown)?;
    let path = backup.join("manifest.json");
    let encoded = fs::read(&path)?;
    let mut changed = manifest.clone();
    changed.segments.push(changed.segments[0].clone());
    fs::write(&path, serde_json::to_vec(&changed)?)?;
    rejected()?;
    fs::write(&path, &encoded)?;
    let active_name = format!(
        "{}.open",
        manifest.segments[0]
            .file_name
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".")
    );
    let active = segment.with_file_name(&active_name);
    fs::rename(&segment, &active)?;
    let mut changed = manifest.clone();
    changed.segments[0].file_name = active_name;
    fs::write(&path, serde_json::to_vec(&changed)?)?;
    rejected()?;
    assert_eq!(fs::read(&active)?, bytes);
    fs::rename(&active, &segment)?;
    fs::write(&path, &encoded)?;
    let engine = backup
        .join("fjall")
        .join(&manifest.database_files[0].file_name);
    let engine_bytes = fs::read(&engine)?;
    let moved = directory.path().join("saved-engine-file");
    fs::rename(&engine, &moved)?;
    rejected()?;
    symlink(&moved, &engine)?;
    rejected()?;
    fs::remove_file(&engine)?;
    fs::rename(&moved, &engine)?;
    let mut changed = engine_bytes.clone();
    *changed.last_mut().ok_or("engine bytes")? ^= 1;
    fs::write(&engine, &changed)?;
    rejected()?;
    fs::write(&engine, &engine_bytes)?;
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o644))?;
    rejected()?;
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o600))?;
    let mut changed = manifest.clone();
    changed
        .database_files
        .push(changed.database_files[0].clone());
    fs::write(&path, serde_json::to_vec(&changed)?)?;
    rejected()?;
    fs::write(&path, &encoded)?;
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o400))?;
    fs::set_permissions(&segment, fs::Permissions::from_mode(0o400))?;
    let saved = files(&backup)?;
    let restored = AnalysisStore::restore(&backup, &target)?;
    assert_eq!(
        restored.read_page(&identity(), 1)?.records[0].framed_record,
        b"frame"
    );
    assert_eq!(files(&backup)?, saved);
    assert_eq!(fs::read(&segment)?, bytes);
    assert_eq!(fs::read(&path)?, encoded);
    assert_eq!(fs::read(&engine)?, engine_bytes);
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
    Ok(())
}

#[cfg(feature = "test-fixtures")]
fn inventory(root: &Path) -> TestResult<Vec<araphor_data::AnalysisBackupFileV1>> {
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir() {
                pending.push(path);
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                let bytes = fs::read(&path)?;
                files.push(araphor_data::AnalysisBackupFileV1 {
                    file_name: path
                        .strip_prefix(root)?
                        .to_str()
                        .ok_or("engine path")?
                        .into(),
                    bytes: bytes.len() as u64,
                    crc32c: crc32c::crc32c(&bytes),
                });
            }
        }
    }
    files.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    Ok(files)
}

#[cfg(feature = "test-fixtures")]
#[test]
fn bundle_rejects_semantic_faults() -> TestResult {
    use araphor_data::{
        analysis::native::StorageFault, AnalysisContextKeyV1, AnalysisContextVersionV1,
        ContextSensitivityV1,
    };

    for fault in 0..3 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(identity(), batch(1))?;
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "backup-test".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![3],
        })?;
        let backup = root.join("backups/saved");
        let mut manifest = store.backup(&backup)?;
        let damage = match fault {
            0 => StorageFault::Receipt(identity(), 2),
            1 => StorageFault::RawEnd(manifest.segments[0].segment_id),
            _ => StorageFault::Schema(manifest.schema_version + 1),
        };
        AnalysisStore::corrupt_fixture(&backup, &damage)?;
        manifest.database_files = inventory(&backup.join("fjall"))?;
        manifest.database_bytes = manifest.database_files.iter().map(|file| file.bytes).sum();
        fs::write(backup.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
        let saved = files(&backup)?;
        let target = directory.path().join("restored");
        assert!(
            AnalysisStore::restore(&backup, &target).is_err(),
            "fault {fault}"
        );
        assert!(target.join("restore.pending").exists(), "fault {fault}");
        assert!(AnalysisStore::open(&target).is_err());
        assert!(AnalysisStore::restore(&backup, &target).is_err());
        assert_eq!(files(&backup)?, saved);
        assert_eq!(
            store.read_page(&identity(), 1)?.records[0].framed_record,
            b"frame"
        );
    }
    Ok(())
}
