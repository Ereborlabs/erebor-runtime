use std::fs;

use super::*;
use crate::{EvidenceIntakeIdentityV1, RetentionLimitsV1, ValidatedEvidenceBatchV1};

#[test]
fn analysis_store_segment_usage() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(100),
        ..Default::default()
    };
    let store = NativeStore::open_with_retention(&root, limits)?;
    let source = EvidenceIntakeIdentityV1 {
        node_id: "capacity-node".into(),
        ..crate::analysis::tests::identity()
    };
    let batch = |cursor| ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 100,
        framed_records: b"frame".to_vec().into(),
        frame_ends: vec![5],
    };
    let check = |store: &NativeStore, count: usize| -> Result<()> {
        let raw = store
            .raw
            .lock()
            .map_err(|_| NativeStateSnafu { field: "raw lock" }.build())?;
        let (_, evidence, diagnostic) = raw.storage_summary()?.ok_or_else(|| {
            NativeStateSnafu {
                field: "segment summary",
            }
            .build()
        })?;
        assert_eq!((evidence, diagnostic), (count, 0));
        let summary = crate::StorageUsageV1::inspect(&root, Some(&raw))?;
        let inspected = crate::StorageUsageV1::at(&root)?;
        assert_eq!(
            (summary.file_bytes, summary.allocated_bytes),
            (inspected.file_bytes, inspected.allocated_bytes)
        );
        Ok(())
    };
    store.accept_validated_batch(source.clone(), batch(1))?;
    check(&store, 1)?;
    store.accept_validated_batch(source.clone(), batch(2))?;
    check(&store, 1)?;
    store.checkpoint()?;
    check(&store, 1)?;
    store
        .raw
        .lock()
        .map_err(|_| NativeStateSnafu { field: "raw lock" }.build())?
        .seal_all()?;
    check(&store, 1)?;
    store.accept_validated_batch(source.clone(), batch(3))?;
    check(&store, 2)?;
    crate::EvidenceRetentionOwner::new(&store).retain(&source, 500)?;
    check(&store, 0)?;
    drop(store);
    let store = NativeStore::open_with_retention(&root, limits)?;
    check(&store, 0)?;
    store.accept_validated_batch(source.clone(), batch(4))?;
    check(&store, 1)?;

    let unknown = root.join("segments/unknown");
    let padding = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&unknown)?;
    padding.set_len(1024 * 1024)?;
    {
        let raw = store
            .raw
            .lock()
            .map_err(|_| NativeStateSnafu { field: "raw lock" }.build())?;
        assert!(raw.storage_summary()?.is_none());
        let summary = crate::StorageUsageV1::inspect(&root, Some(&raw))?;
        let inspected = store.storage_usage()?;
        assert_eq!(
            (summary.file_bytes, summary.allocated_bytes),
            (inspected.file_bytes, inspected.allocated_bytes)
        );
    }
    padding.set_len(2 * 1024 * 1024)?;
    {
        let raw = store
            .raw
            .lock()
            .map_err(|_| NativeStateSnafu { field: "raw lock" }.build())?;
        assert_eq!(
            crate::StorageUsageV1::inspect(&root, Some(&raw))?.file_bytes,
            store.storage_usage()?.file_bytes
        );
    }
    drop(padding);
    fs::remove_file(&unknown)?;
    let before = store.meta()?;
    let link = root.join("segments/link");
    symlink(root.join("fjall"), &link)?;
    assert!(store.storage_usage().is_err());
    assert!(crate::StorageUsageV1::inspect(&root, None).is_err());
    assert_eq!(store.meta()?, before);
    fs::remove_file(link)?;
    store.accept_validated_batch(source, batch(5))?;
    Ok(())
}
