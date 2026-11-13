use araphor_data::{
    analysis::native::NativeStore, EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1,
    ValidatedEvidenceBatchV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        source_id: [3; 16],
        label_epoch: 1,
        source_epoch: 1,
    }
}

fn batch(first: u64, last: u64) -> ValidatedEvidenceBatchV1 {
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for cursor in first..=last {
        bytes.extend(cursor.to_be_bytes());
        ends.push(bytes.len());
    }
    ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: first,
        last_cursor: last,
        intake_utc_ns: 100,
        framed_records: bytes.into(),
        frame_ends: ends,
    }
}

#[test]
fn native_payload_receipt_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = source();
    let before = store.view()?;
    let cursor = store.database().inner().journal_head()?;
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1, 3))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let accepted = store.view()?;
    assert_eq!(accepted.revision(), 1);
    assert_ne!(cursor, store.database().inner().journal_head()?);
    assert_ne!(before.snapshot().revision(), accepted.snapshot().revision());
    assert!(before.source_receipt(&source)?.is_none());
    assert_eq!(
        accepted
            .source_receipt(&source)?
            .ok_or("receipt")?
            .contiguous_cursor,
        3
    );
    assert_eq!(store.source_page(source.tenant_id, None)?, [source.clone()]);
    assert_eq!(store.tenant_page(None)?, [source.tenant_id]);
    assert_eq!(
        store.source_binding(
            source.tenant_id,
            &source.node_id,
            source.source_id,
            source.source_epoch
        )?,
        Some(source.clone())
    );
    assert_eq!(
        accepted
            .snapshot()
            .prefix(b"\0data/evidence/payload/")
            .count(),
        1
    );
    assert_eq!(
        accepted.snapshot().prefix(b"\0data/evidence/span/").count(),
        1
    );
    assert_eq!(
        accepted
            .snapshot()
            .prefix(b"\0data/evidence/position/")
            .count(),
        1
    );
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    let page = store.read_page(&source, 1)?;
    assert_eq!(page.records.len(), 3);
    for (index, record) in page.records.iter().enumerate() {
        assert_eq!(record.cursor, index as u64 + 1);
        assert_eq!(record.framed_record, record.cursor.to_be_bytes());
        assert_eq!(record.position.commit_revision, 1);
        assert_eq!(record.position.ordinal, index as u32);
    }
    let head = store.database().inner().journal_head()?;
    store.accept_validated_batch(source.clone(), batch(1, 3))?;
    assert_eq!(head, store.database().inner().journal_head()?);
    store.checkpoint()?;
    store.database().inner().major_compact()?;
    drop((accepted, before, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.read_page(&source, 1)?, page);
    assert_eq!(
        store
            .read_at(1)?
            .source_receipt(&source)?
            .ok_or("reopened receipt")?
            .contiguous_cursor,
        3
    );
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    Ok(())
}

#[test]
fn native_overlap_spans_positions() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = source();
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(2, 3))?,
        EvidenceStoreOutcomeV1::Pending
    );
    assert_eq!(
        store
            .source_receipt(&source)?
            .ok_or("pending receipt")?
            .contiguous_cursor,
        0
    );
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1, 4))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let page = store.read_page(&source, 1)?;
    assert_eq!(page.records.len(), 4);
    assert_eq!(
        page.records
            .iter()
            .map(|record| (record.position.commit_revision, record.position.ordinal))
            .collect::<Vec<_>>(),
        [(2, 0), (1, 0), (1, 1), (2, 1)]
    );
    for record in &page.records {
        assert_eq!(record.framed_record, record.cursor.to_be_bytes());
    }
    let snapshot = store.view()?;
    assert_eq!(
        snapshot
            .snapshot()
            .prefix(b"\0data/evidence/payload/")
            .count(),
        2
    );
    assert_eq!(
        snapshot.snapshot().prefix(b"\0data/evidence/span/").count(),
        3
    );
    let cursor = store.database().inner().journal_head()?;
    let mut conflict = batch(2, 2);
    conflict.framed_records = vec![9; 8].into();
    assert!(store
        .accept_validated_batch(source.clone(), conflict)
        .is_err());
    let mut cpu = batch(5, 5);
    cpu.cpu_id = 1;
    assert!(store.accept_validated_batch(source.clone(), cpu).is_err());
    let mut rebound = source.clone();
    rebound.node_boot_id = [9; 16];
    assert!(store.accept_validated_batch(rebound, batch(5, 5)).is_err());
    assert_eq!(cursor, store.database().inner().journal_head()?);
    assert_eq!(store.view()?.revision(), 2);
    drop((snapshot, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.read_page(&source, 1)?, page);
    assert_eq!(
        store
            .read_at(1)?
            .source_receipt(&source)?
            .ok_or("old pending receipt")?
            .contiguous_cursor,
        0
    );
    Ok(())
}

#[cfg(feature = "test-fixtures")]
#[test]
fn native_expiry_preserves_overlap_boundaries() -> TestResult {
    use araphor_data::{AnalysisReadControl, EvidenceRetentionOwner, RetentionLimitsV1};
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = NativeStore::open_with_retention(&root, limits)?;
    let source = source();
    store.accept_validated_batch(source.clone(), batch(2, 3))?;
    let mut fill = batch(1, 4);
    fill.intake_utc_ns = 200;
    store.accept_validated_batch(source.clone(), fill)?;
    let before = store.view()?;
    let expired = EvidenceRetentionOwner::new(&store).retain(&source, 151)?;
    assert_eq!(expired.removed_records, 2);
    assert_eq!(expired.retained_floor, 0);
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/evidence/payload/")
            .count(),
        1
    );
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/evidence/span/")
            .count(),
        3
    );
    let cursor = store.database().inner().journal_head()?;
    let mut retry = batch(2, 3);
    retry.framed_records = vec![9; 16].into();
    assert_eq!(
        store.accept_validated_batch(source.clone(), retry)?,
        EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
    );
    let mut mixed = batch(1, 5);
    mixed.framed_records = vec![9; 40].into();
    assert!(
        matches!(store.accept_validated_batch(source.clone(), mixed),
        Err(araphor_data::Error::AnalysisState { reason, .. }) if reason == "an evidence retry crosses an expired range boundary")
    );
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(matches!(
        store.read_page_at(&before, &source, 2, &AnalysisReadControl::default()),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert_eq!(
        store.read_page(&source, 4)?.records[0].framed_record,
        4u64.to_be_bytes()
    );
    store.checkpoint()?;
    store.database().inner().major_compact()?;
    drop((before, store));
    let store = NativeStore::open_with_retention(&root, limits)?;
    assert!(matches!(
        store.read_page(&source, 2),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(2, 3))?,
        EvidenceStoreOutcomeV1::AlreadyAcceptedExpired
    );
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    Ok(())
}

#[cfg(feature = "test-fixtures")]
#[test]
fn native_intake_commit_boundary() -> TestResult {
    use araphor_data::{AnalysisCommitStage, PackageErrorCodeV1};
    for stage in [
        AnalysisCommitStage::BeforeAppend,
        AnalysisCommitStage::AfterSync,
    ] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("data");
        let store = NativeStore::open(&root)?;
        let source = source();
        let before = store.view()?;
        store.set_commit_hook(stage, || {
            Err(PackageErrorCodeV1::Denied.error("intake commit fault"))
        })?;
        assert!(store
            .accept_validated_batch(source.clone(), batch(1, 3))
            .is_err());
        assert!(before.source_receipt(&source)?.is_none());
        if stage == AnalysisCommitStage::BeforeAppend {
            assert!(store.storage_health()?.write_ready);
            assert!(store.source_receipt(&source)?.is_none());
            assert_eq!(
                store
                    .view()?
                    .snapshot()
                    .prefix(b"\0data/evidence/payload/")
                    .count(),
                0
            );
        } else {
            assert!(!store.storage_health()?.write_ready);
            assert!(store.read_page(&source, 1).is_err());
        }
        drop((before, store));
        let store = NativeStore::open(&root)?;
        if stage == AnalysisCommitStage::BeforeAppend {
            assert!(store.source_receipt(&source)?.is_none());
            assert_eq!(store.view()?.revision(), 0);
        } else {
            assert_eq!(
                store
                    .source_receipt(&source)?
                    .ok_or("durable receipt")?
                    .contiguous_cursor,
                3
            );
            let page = store.read_page(&source, 1)?;
            assert_eq!(page.records.len(), 3);
            for row in page.records {
                assert_eq!(row.framed_record, row.cursor.to_be_bytes());
            }
            let head = store.database().inner().journal_head()?;
            assert_eq!(
                store.accept_validated_batch(source.clone(), batch(1, 3))?,
                EvidenceStoreOutcomeV1::Accepted
            );
            assert_eq!(store.database().inner().journal_head()?, head);
        }
        assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    }
    Ok(())
}
