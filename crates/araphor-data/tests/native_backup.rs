use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use araphor_data::{
    AnalysisBackupManifestV1, AnalysisReadControl, AnalysisRecoveryStatusV1, AnalysisStore,
    EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, ValidatedEvidenceBatchV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "native_backup/bundle.rs"]
mod bundle;
#[path = "native_backup/trace.rs"]
mod trace;
#[path = "native_backup/usage.rs"]
mod usage;

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
        cpu_id: 0,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 1_000_000_000,
        framed_records: b"frame".to_vec().into(),
        frame_ends: vec![5],
    }
}

fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let bytes = fs::read(root.join("manifest.json"))?;
    let manifest: AnalysisBackupManifestV1 = serde_json::from_slice(&bytes)?;
    let mut files = BTreeMap::from([(PathBuf::from("manifest.json"), bytes)]);
    for file in manifest.database_files {
        let path = PathBuf::from("fjall").join(file.file_name);
        files.insert(path.clone(), fs::read(root.join(path))?);
    }
    for segment in manifest.segments {
        let path = PathBuf::from("segments").join(segment.file_name);
        files.insert(path.clone(), fs::read(root.join(path))?);
    }
    Ok(files)
}

fn charged_files(root: &Path) -> TestResult<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let mut pending = vec![root.to_owned()];
    let mut bytes = 0;
    let mut allocated = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            let blocks = metadata.blocks() * 512;
            bytes += metadata.len().max(blocks);
            allocated += blocks;
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok((bytes, allocated))
}

#[test]
fn backup_preserves_recovery_floor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("original");
    let store = AnalysisStore::open(&root)?;
    let source = identity();
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let before = store.meta()?;
    let backup = root.join("backups/saved");
    let manifest = store.backup(&backup)?;
    assert_eq!(manifest.commit_revision, 1);
    assert_eq!(manifest.recovery_epoch, 1);
    assert_eq!(manifest.schema_version, before.schema_version);
    assert_eq!(
        manifest.database_bytes,
        manifest
            .database_files
            .iter()
            .map(
                |file| fs::metadata(backup.join("fjall").join(&file.file_name))
                    .map(|meta| meta.len())
            )
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>()
    );
    assert_eq!(manifest.segments.len(), 1);
    assert!(store.backup(&backup).is_err());
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(2))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let target = directory.path().join("restored");
    let restored = AnalysisStore::restore(&backup, &target)?;
    assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
    assert_eq!(restored.meta()?.recovery_epoch, 2);
    assert_eq!(restored.meta()?.commit_revision, 1);
    assert_eq!(
        restored
            .source_receipt(&source)?
            .ok_or("receipt")?
            .contiguous_cursor,
        1
    );
    let expected = AnalysisRecoveryStatusV1::Partial {
        first_cursor: 2,
        last_cursor: 2,
    };
    assert_eq!(restored.record_recovery_floor(&source, 2)?, expected);
    assert_eq!(restored.meta()?.commit_revision, 2);
    assert_eq!(restored.record_recovery_floor(&source, 2)?, expected);
    assert_eq!(restored.meta()?.commit_revision, 2);
    assert_eq!(
        restored
            .source_receipt(&source)?
            .ok_or("receipt")?
            .contiguous_cursor,
        1
    );
    assert!(AnalysisStore::restore(&backup, &target).is_err());
    drop(restored);
    OpenOptions::new()
        .append(true)
        .open(
            backup
                .join("fjall")
                .join(&manifest.database_files[0].file_name),
        )?
        .write_all(b"corrupt")?;
    let corrupt = directory.path().join("corrupt");
    assert!(AnalysisStore::restore(&backup, &corrupt).is_err());
    assert!(!corrupt.exists());
    Ok(())
}

#[test]
fn large_segment_backup_restores() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("original");
    let store = AnalysisStore::open(&root)?;
    let payload = vec![7; 17 * 1_024 * 1_024];
    let mut input = batch(1);
    input.framed_records = payload.clone().into();
    input.frame_ends = vec![payload.len()];
    store.accept_validated_batch(identity(), input)?;
    store.accept_validated_batch(identity(), batch(2))?;
    let positions = store.read_page(&identity(), 1)?;
    assert_eq!(positions.records.len(), 1);
    assert_eq!(positions.records[0].framed_record, payload);
    assert_eq!(positions.next_cursor, Some(2));
    let tail = store.read_page(&identity(), 2)?;
    assert_eq!(tail.records.len(), 1);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.read_page(&identity(), 1)?, positions);
    let backup = root.join("backups/large");
    let manifest = store.backup(&backup)?;
    assert_eq!(manifest.segments.len(), 2);
    assert!(manifest.segments[0].bytes > araphor_data::EVIDENCE_SEGMENT_BYTES as u64);
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    let page = restored.read_page(&identity(), 1)?;
    assert_eq!(page.records, positions.records);
    assert_eq!(page.next_cursor, positions.next_cursor);
    assert_eq!(restored.read_page(&identity(), 2)?.records, tail.records);
    Ok(())
}

#[test]
fn backup_serializes_with_writer() -> TestResult {
    use std::{sync::mpsc, thread, time::Duration};

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    let meta = store.meta()?;
    let held = store.view()?;
    let writer = store.write()?;
    let destination = root.join("backups/saved");
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| -> TestResult {
        let worker = scope.spawn(|| sender.send(store.backup(&destination)));
        let pending = receiver.recv_timeout(Duration::from_millis(50));
        drop(writer);
        assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
        let manifest = receiver.recv_timeout(Duration::from_secs(10))??;
        assert_eq!(manifest.commit_revision, meta.commit_revision);
        worker
            .join()
            .map_err(|_| "backup panicked")?
            .map_err(|_| "backup receiver closed")?;
        Ok(())
    })?;
    assert_eq!(store.meta()?, meta);
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
    let saved = files(&destination)?;
    assert!(AnalysisStore::open(&root).is_err());
    assert!(store.backup(&destination).is_err());
    assert_eq!(store.meta()?, meta);
    store.accept_validated_batch(identity(), batch(2))?;
    let restored = AnalysisStore::restore(&destination, &directory.path().join("restored"))?;
    assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
    assert_eq!(
        store
            .read_page_at(&held, &identity(), 1, &AnalysisReadControl::default())?
            .records
            .len(),
        1
    );
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
    let blocked = root.join("backups/blocked");
    DirBuilder::new().mode(0o700).create(&blocked)?;
    store.checkpoint()?;
    let before = store.meta()?;
    let usage = store.storage_usage()?.file_bytes;
    assert!(store.backup(&blocked).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.storage_usage()?.file_bytes, usage);
    assert_eq!(fs::read_dir(&blocked)?.count(), 0);
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 2);
    assert!(AnalysisStore::restore(&blocked, &directory.path().join("invalid")).is_err());
    assert_eq!(files(&destination)?, saved);
    Ok(())
}

#[test]
fn uncertain_owner_rejects_access() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    store.checkpoint()?;
    let before = store.meta()?;
    let mut tx = store.write()?;
    tx.native().insert(b"rejected", b"absent");
    assert!(tx
        .commit([b"duplicate".to_vec(), b"duplicate".to_vec()])
        .is_err());
    assert!(store.meta().is_err());
    assert!(store.checkpoint().is_err());
    assert!(store.accept_validated_batch(identity(), batch(2)).is_err());
    assert!(store.read_page(&identity(), 1).is_err());
    assert!(!store.storage_health()?.write_ready);
    assert!(AnalysisStore::open(&root).is_err());
    store.recover()?;
    assert_eq!(store.meta()?, before);
    assert_eq!(store.read_page(&identity(), 1)?.records.len(), 1);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.meta()?, before);
    assert_eq!(reopened.read_page(&identity(), 1)?.records.len(), 1);
    Ok(())
}
