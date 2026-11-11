#![cfg(feature = "test-fixtures")]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use araphor_data::{
    AnalysisBackupManifestV1, AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore,
    ContextSensitivityV1, EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn batch(cursor: u64) -> ValidatedEvidenceBatchV1 {
    ValidatedEvidenceBatchV1 {
        cpu_id: 7,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 100,
        framed_records: vec![cursor as u8; 3].into(),
        frame_ends: vec![3],
    }
}

fn seed(root: &Path) -> Result<AnalysisStore, Box<dyn std::error::Error>> {
    let store = AnalysisStore::open(root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    store.accept_validated_batch(identity(), batch(2))?;
    store.commit_context(&context())?;
    Ok(store)
}

fn context() -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "crash-fixture".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"native state".to_vec(),
    }
}

fn child(mode: &str, root: &Path, point: &str, backup: &Path) -> TestResult {
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", "crash_process", "--nocapture"])
        .env("ARAPHOR_NATIVE_CHILD", mode)
        .env("ARAPHOR_CRASH_ROOT", root)
        .env("ARAPHOR_CRASH_POINT", point)
        .env("ARAPHOR_NATIVE_BACKUP", backup)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(73),
        "{point}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn bundle_files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn std::error::Error>> {
    let bytes = fs::read(root.join("manifest.json"))?;
    let manifest: AnalysisBackupManifestV1 = serde_json::from_slice(&bytes)?;
    let mut files = BTreeMap::from([(PathBuf::from("manifest.json"), bytes)]);
    for file in &manifest.database_files {
        let path = Path::new("fjall").join(&file.file_name);
        files.insert(path.clone(), fs::read(root.join(path))?);
    }
    for segment in &manifest.segments {
        let path = Path::new("segments").join(&segment.file_name);
        files.insert(path.clone(), fs::read(root.join(path))?);
    }
    Ok(files)
}

#[test]
fn crash_process() -> TestResult {
    let Some(mode) = std::env::var_os("ARAPHOR_NATIVE_CHILD") else {
        return Ok(());
    };
    let root = PathBuf::from(std::env::var_os("ARAPHOR_CRASH_ROOT").ok_or("child root")?);
    let backup = PathBuf::from(std::env::var_os("ARAPHOR_NATIVE_BACKUP").ok_or("child backup")?);
    match mode.to_str() {
        Some("backup") => {
            AnalysisStore::open(&root)?.backup(&backup)?;
        }
        Some("restore") => {
            AnalysisStore::restore(&backup, &root)?;
        }
        _ => return Err("child mode".into()),
    }
    Err("the process did not reach its crash point".into())
}

#[test]
fn backup_crash_boundaries() -> TestResult {
    for point in [
        "backup.sealed",
        "backup.exported",
        "backup.synced",
        "backup.published",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("source");
        let store = seed(&root)?;
        let before = store.meta()?;
        let receipt = store.source_receipt(&identity())?;
        let rows = store.read_page(&identity(), 1)?;
        let native = store.view()?.context(&context().key)?;
        let mut restored_meta = before.clone();
        restored_meta.recovery_epoch += 1;
        drop(store);
        let backup = root.join("backups").join("capture");
        child("backup", &root, point, &backup)?;
        assert_eq!(backup.exists(), point == "backup.published", "{point}");
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?, before);
        assert_eq!(store.source_receipt(&identity())?, receipt);
        assert_eq!(store.read_page(&identity(), 1)?, rows);
        assert_eq!(store.view()?.context(&context().key)?, native);
        if backup.exists() {
            let bytes = bundle_files(&backup)?;
            let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
            assert_eq!(restored.meta()?, restored_meta);
            assert_eq!(restored.read_page(&identity(), 1)?, rows);
            assert_eq!(restored.view()?.context(&context().key)?, native);
            assert_eq!(bundle_files(&backup)?, bytes);
        } else {
            assert!(AnalysisStore::restore(&backup, &directory.path().join("incomplete")).is_err());
        }
        store.accept_validated_batch(identity(), batch(3))?;
        let retry = root.join("backups").join("retry");
        store.backup(&retry)?;
        let restored = AnalysisStore::restore(&retry, &directory.path().join("retry-restore"))?;
        assert_eq!(
            restored.read_page(&identity(), 1)?,
            store.read_page(&identity(), 1)?
        );
        assert_eq!(restored.view()?.context(&context().key)?, native);
        assert_eq!(
            restored.meta()?.commit_revision,
            store.meta()?.commit_revision
        );
    }
    Ok(())
}

#[test]
fn restore_crash_boundaries() -> TestResult {
    for point in [
        "restore.pending",
        "restore.copied",
        "restore.epoch",
        "restore.complete",
    ] {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        let store = seed(&source)?;
        let before = store.meta()?;
        let rows = store.read_page(&identity(), 1)?;
        let native = store.view()?.context(&context().key)?;
        let mut restored_meta = before.clone();
        restored_meta.recovery_epoch += 1;
        let backup = source.join("backups").join("capture");
        store.backup(&backup)?;
        let bytes = bundle_files(&backup)?;
        assert!(AnalysisStore::restore(&backup, &source).is_err());
        assert!(!source.join("restore.pending").exists());
        assert_eq!(store.meta()?, before);
        drop(store);
        let target = directory.path().join("target");
        child("restore", &target, point, &backup)?;
        assert_eq!(
            target.join("restore.pending").exists(),
            point != "restore.complete"
        );
        if point == "restore.complete" {
            for _ in 0..2 {
                let restored = AnalysisStore::open(&target)?;
                assert_eq!(restored.meta()?, restored_meta);
                assert_eq!(restored.read_page(&identity(), 1)?, rows);
                assert_eq!(restored.view()?.context(&context().key)?, native);
            }
        } else {
            for _ in 0..2 {
                assert!(
                    matches!(AnalysisStore::open(&target), Err(araphor_data::Error::AnalysisState { reason, .. })
                    if reason.contains("restore is incomplete")),
                    "{point}"
                );
            }
            assert!(AnalysisStore::restore(&backup, &target).is_err());
            assert!(target.join("restore.pending").exists());
            assert_eq!(target.join("fjall").exists(), point != "restore.pending");
        }
        assert_eq!(bundle_files(&backup)?, bytes);
        let restored = AnalysisStore::restore(&backup, &directory.path().join("alternate"))?;
        assert_eq!(restored.meta()?, restored_meta);
        assert_eq!(restored.read_page(&identity(), 1)?, rows);
        assert_eq!(restored.view()?.context(&context().key)?, native);
        assert_eq!(bundle_files(&backup)?, bytes);
        let original = AnalysisStore::open(&source)?;
        assert_eq!(original.meta()?, before);
        assert_eq!(original.read_page(&identity(), 1)?, rows);
        assert_eq!(original.view()?.context(&context().key)?, native);
    }
    Ok(())
}
