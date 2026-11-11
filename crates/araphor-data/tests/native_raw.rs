use araphor_data::{
    analysis::native::NativeStore, AnalysisReadControl, AnalysisSelectionV1,
    EvidenceIntakeIdentityV1, EvidenceStoreOutcomeV1, StorePositionV1, ValidatedCoverageV1,
    ValidatedEvidenceBatchV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "native_raw/freshness.rs"]
mod freshness;

#[path = "native_raw/recovery.rs"]
mod recovery;

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
        framed_records: vec![cursor as u8].into(),
        frame_ends: vec![1],
    }
}

fn coverage(identity: &EvidenceIntakeIdentityV1, revision: u64) -> ValidatedCoverageV1 {
    ValidatedCoverageV1 {
        identity: identity.clone(),
        cpu_id: 7,
        revision,
        encoded_report: vec![revision as u8],
    }
}

fn selection(source: &EvidenceIntakeIdentityV1) -> AnalysisSelectionV1 {
    AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()])
}

#[test]
fn raw_metadata_revisions_and_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let source = identity();
    let store = NativeStore::open(&root)?;
    let start = store.view()?;
    let cursor = store.database().inner().journal_head()?;
    store.accept_validated_batch(source.clone(), batch(1))?;
    let first = store.view()?;
    assert_eq!(first.revision(), 1);
    assert_eq!(first.snapshot().revision(), start.snapshot().revision());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(start.source_receipt(&source)?.is_none());
    assert_eq!(
        first
            .source_receipt(&source)?
            .ok_or("first receipt")?
            .contiguous_cursor,
        1
    );
    assert!(start
        .source_binding(
            source.tenant_id,
            &source.node_id,
            source.source_id,
            source.source_epoch
        )?
        .is_none());
    assert_eq!(
        first.source_binding(
            source.tenant_id,
            &source.node_id,
            source.source_id,
            source.source_epoch
        )?,
        Some(source.clone())
    );
    let mut feed = store.database().inner().journal_feed(cursor)?;
    store.accept_validated_coverage(coverage(&source, 7))?;
    let published = feed.next_batch()?.ok_or("coverage native batch")?;
    for prefix in [
        b"\0data/source/".as_slice(),
        b"\0data/raw/end/",
        b"\0data/raw/next",
        b"\0data/coverage/report/",
        b"\0data/coverage/change/",
    ] {
        assert!(published
            .items
            .iter()
            .any(|item| item.key.starts_with(prefix)));
    }
    assert!(feed.next_batch()?.is_none());
    drop(feed);
    let covered = store.view()?;
    assert_eq!(covered.revision(), 2);
    assert_ne!(covered.snapshot().revision(), first.snapshot().revision());
    let cursor = store.database().inner().journal_head()?;
    store.accept_validated_batch(source.clone(), batch(2))?;
    let second = store.view()?;
    assert_eq!(second.revision(), 3);
    assert_eq!(second.snapshot().revision(), covered.snapshot().revision());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    for (revision, expected_cursor, expected_coverage) in [(1, 1, 0), (2, 1, 7), (3, 2, 7)] {
        let view = store.read_at(revision)?;
        assert_eq!(view.revision(), revision);
        let receipt = view.source_receipt(&source)?.ok_or("historical receipt")?;
        assert_eq!(
            (receipt.contiguous_cursor, receipt.coverage_revision),
            (expected_cursor, expected_coverage)
        );
        let page = store.read_page_at(&view, &source, 1, &AnalysisReadControl::default())?;
        assert_eq!(page.read_revision, revision);
        assert_eq!(page.records.len(), expected_cursor as usize);
        assert_eq!(
            page.records[0].position,
            StorePositionV1 {
                commit_revision: 1,
                ordinal: 0
            }
        );
    }
    assert_eq!(
        first
            .source_receipt(&source)?
            .ok_or("captured first")?
            .coverage_revision,
        0
    );
    assert_eq!(
        covered
            .source_receipt(&source)?
            .ok_or("captured covered")?
            .contiguous_cursor,
        1
    );
    let mut tx = store.write()?;
    assert_eq!(tx.revision(), 4);
    tx.native().insert(b"result", b"four");
    tx.commit([])?;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((start, first, covered, second));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), 4);
    assert!(!root.join("analysis.duckdb").exists());
    assert_eq!(
        store
            .read_at(1)?
            .source_receipt(&source)?
            .ok_or("reopened old receipt")?
            .coverage_revision,
        0
    );
    assert_eq!(
        store
            .read_at(3)?
            .source_receipt(&source)?
            .ok_or("reopened raw receipt")?
            .contiguous_cursor,
        2
    );
    let page = store.read_page_cancel(&source, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.records.len(), 2);
    assert_eq!(
        page.records[1].position,
        StorePositionV1 {
            commit_revision: 3,
            ordinal: 0
        }
    );
    let status = store
        .view()?
        .source_status(&source)?
        .ok_or("source status")?;
    assert_eq!(status.retained_event_count, 2);
    assert_eq!(status.latest_coverage_report, Some(vec![7]));
    Ok(())
}

#[test]
fn out_of_order_history_and_coverage() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = identity();
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(2))?,
        EvidenceStoreOutcomeV1::Pending
    );
    let pending = store.view()?;
    assert_eq!(
        pending
            .source_receipt(&source)?
            .ok_or("pending")?
            .contiguous_cursor,
        0
    );
    store.accept_validated_coverage(coverage(&source, 7))?;
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(
        store
            .read_at(1)?
            .source_receipt(&source)?
            .ok_or("old pending")?
            .contiguous_cursor,
        0
    );
    assert_eq!(
        store
            .read_at(2)?
            .source_receipt(&source)?
            .ok_or("old covered")?
            .contiguous_cursor,
        0
    );
    let current = store.view()?;
    assert_eq!(
        current
            .source_receipt(&source)?
            .ok_or("current")?
            .contiguous_cursor,
        2
    );
    let head = store.database().inner().journal_head()?;
    store.accept_validated_batch(source.clone(), batch(2))?;
    store.accept_validated_coverage(coverage(&source, 7))?;
    assert_eq!(store.view()?.revision(), current.revision());
    assert_eq!(store.database().inner().journal_head()?, head);
    let mut conflict = batch(2);
    conflict.framed_records = vec![9].into();
    assert!(store
        .accept_validated_batch(source.clone(), conflict)
        .is_err());
    let mut conflict = coverage(&source, 7);
    conflict.encoded_report = vec![9];
    assert!(store.accept_validated_coverage(conflict).is_err());
    assert!(store
        .accept_validated_coverage(coverage(&source, 6))
        .is_err());
    let mut conflict = source.clone();
    conflict.node_boot_id = [9; 16];
    assert!(store
        .accept_validated_batch(conflict.clone(), batch(3))
        .is_err());
    assert!(store
        .accept_validated_coverage(coverage(&conflict, 8))
        .is_err());
    let mut wrong_cpu = batch(3);
    wrong_cpu.cpu_id = 8;
    assert!(store
        .accept_validated_batch(source.clone(), wrong_cpu)
        .is_err());
    assert_eq!(store.view()?.revision(), current.revision());
    let selection = selection(&source);
    let after = StorePositionV1 {
        commit_revision: 0,
        ordinal: u32::MAX,
    };
    let control = AnalysisReadControl::default();
    let changes = current.coverage_changes(&selection, after, &control)?;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].reference.position.commit_revision, 2);
    assert!(pending
        .coverage_changes(&selection, after, &control)?
        .is_empty());
    store.accept_validated_coverage(coverage(&source, 8))?;
    assert_eq!(
        store
            .view()?
            .coverage_changes(&selection, after, &control)?
            .len(),
        2
    );
    assert_eq!(
        current.coverage_changes(&selection, after, &control)?,
        changes
    );
    let foreign = AnalysisSelectionV1::new([9; 16], Vec::new());
    assert!(current
        .coverage_report(&foreign, &changes[0].reference, &control)
        .is_err());
    drop((pending, current));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .read_at(1)?
            .source_receipt(&source)?
            .ok_or("recovered pending")?
            .contiguous_cursor,
        0
    );
    assert_eq!(
        store
            .view()?
            .source_receipt(&source)?
            .ok_or("recovered current")?
            .contiguous_cursor,
        2
    );
    let page = store.read_page_cancel(&source, 1, &control)?;
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.position.commit_revision)
            .collect::<Vec<_>>(),
        [3, 1]
    );
    Ok(())
}

#[test]
fn append_and_commit_failure_recover() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut controls = store.subscribe_control();
    assert!(store.storage_health()?.write_ready);
    let source = identity();
    store.accept_validated_batch(source.clone(), batch(1))?;
    assert!(!controls.has_changed()?);
    let before = store.view()?;
    let segment = std::fs::read_dir(root.join("segments"))?
        .next()
        .ok_or("segment absent")??
        .path();
    let saved = root.join("saved-segment");
    std::fs::rename(&segment, &saved)?;
    std::fs::create_dir(&segment)?;
    assert!(store
        .accept_validated_batch(source.clone(), batch(2))
        .is_err());
    assert!(store.view().is_err());
    assert!(store.write().is_err());
    assert!(controls.has_changed()?);
    controls.borrow_and_update();
    assert!(!store.storage_health()?.write_ready);
    assert!(!controls.has_changed()?);
    assert_eq!(
        before
            .source_receipt(&source)?
            .ok_or("old receipt")?
            .contiguous_cursor,
        1
    );
    std::fs::remove_dir(&segment)?;
    std::fs::rename(&saved, &segment)?;
    drop(before);
    drop(store);
    let store = NativeStore::open(&root)?;
    let controls = store.subscribe_control();
    assert!(store.storage_health()?.write_ready);
    assert_eq!(store.view()?.revision(), 1);
    store.accept_validated_batch(source.clone(), batch(2))?;
    let mut tx = store.write()?;
    tx.coverage(&coverage(&source, 7))?;
    assert!(tx.commit([b"same".to_vec(), b"same".to_vec()]).is_err());
    assert!(store.view().is_err());
    assert!(controls.has_changed()?);
    assert!(!store.storage_health()?.write_ready);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), 2);
    assert_eq!(
        store
            .view()?
            .source_receipt(&source)?
            .ok_or("recovered receipt")?
            .coverage_revision,
        0
    );
    store.accept_validated_coverage(coverage(&source, 7))?;
    assert_eq!(store.view()?.revision(), 3);
    let control = AnalysisReadControl::default();
    control.cancel()?;
    assert!(store.read_page_cancel(&source, 1, &control).is_err());
    Ok(())
}

#[test]
fn metadata_protects_raw_tail() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = identity();
    store.accept_validated_batch(source.clone(), batch(1))?;
    store.accept_validated_coverage(coverage(&source, 7))?;
    let segment = std::fs::read_dir(root.join("segments"))?
        .next()
        .ok_or("segment absent")??
        .path();
    drop(store);
    let file = std::fs::OpenOptions::new().write(true).open(segment)?;
    file.set_len(file.metadata()?.len() - 1)?;
    file.sync_all()?;
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[test]
fn coverage_changes_keep_identity() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("data"))?;
    let source = identity();
    for revision in 1..=16 {
        store.accept_validated_coverage(coverage(&source, revision))?;
    }
    let after = StorePositionV1 {
        commit_revision: store.view()?.revision(),
        ordinal: u32::MAX,
    };
    for revision in 17..=22 {
        store.accept_validated_coverage(coverage(&source, revision))?;
    }
    let view = store.view()?;
    let scope = selection(&source);
    let control = AnalysisReadControl::default();
    let changes = view.coverage_changes(&scope, after, &control)?;
    assert_eq!(changes.len(), 6);
    for (record, revision) in changes.iter().zip(17..=22) {
        assert_eq!(record.reference.source, source);
        assert_eq!(record.reference.revision, revision);
        assert_eq!(
            record.reference.position,
            StorePositionV1 {
                commit_revision: revision,
                ordinal: 0,
            }
        );
        assert_eq!(record.encoded_report, vec![revision as u8]);
        assert_eq!(
            view.coverage_report(&scope, &record.reference, &control)?,
            *record
        );
    }
    let before = store.meta()?;
    let head = store.database().inner().journal_head()?;
    store.accept_validated_coverage(coverage(&source, 22))?;
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, head);
    let mut conflict = coverage(&source, 22);
    conflict.encoded_report = vec![255];
    assert!(store.accept_validated_coverage(conflict).is_err());
    let mut rebound = changes[0].reference.clone();
    rebound.position = changes[1].reference.position;
    assert!(view.coverage_report(&scope, &rebound, &control).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, head);
    assert_eq!(
        store.view()?.coverage_changes(&scope, after, &control)?,
        changes
    );
    Ok(())
}

#[test]
fn coverage_batch_bounds_and_new_sources() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("data"))?;
    let first = identity();
    let mut second = first.clone();
    second.source_id = [4; 16];
    let mut tx = store.write()?;
    tx.coverage(&coverage(&first, 7))?;
    tx.coverage(&coverage(&second, 7))?;
    tx.coverage(&coverage(&first, 8))?;
    tx.commit([])?;
    let view = store.view()?;
    assert!(store.read_at(0)?.source_receipt(&first)?.is_none());
    let scope = AnalysisSelectionV1::new(first.tenant_id, vec![first.clone(), second.clone()]);
    let control = AnalysisReadControl::default();
    let beginning = StorePositionV1 {
        commit_revision: 0,
        ordinal: u32::MAX,
    };
    let changes = view.coverage_changes(&scope, beginning, &control)?;
    assert_eq!(changes.len(), 3);
    assert!(changes
        .iter()
        .all(|record| record.reference.position.commit_revision == 1));
    assert_eq!(
        view.source_status(&first)?
            .ok_or("first source status")?
            .latest_coverage_report,
        Some(vec![8])
    );
    let consumed = StorePositionV1 {
        commit_revision: 1,
        ordinal: u32::MAX,
    };
    assert!(view
        .coverage_changes(&scope, consumed, &control)?
        .is_empty());
    store.accept_validated_coverage(coverage(&second, 8))?;
    let next = store.view()?;
    assert_eq!(next.coverage_changes(&scope, consumed, &control)?.len(), 1);
    assert_eq!(view.coverage_changes(&scope, beginning, &control)?, changes);
    store.accept_validated_batch(first.clone(), batch(1))?;
    assert_eq!(
        store
            .view()?
            .source_receipt(&first)?
            .ok_or("new raw source")?
            .coverage_revision,
        8
    );
    assert_eq!(
        view.source_receipt(&first)?
            .ok_or("captured coverage source")?
            .contiguous_cursor,
        0
    );
    Ok(())
}

#[test]
fn malformed_coverage_change_is_rejected() -> TestResult {
    for bad in [Vec::new(), vec![1], vec![0]] {
        let dir = tempfile::tempdir()?;
        let store = NativeStore::open(&dir.path().join("data"))?;
        let source = identity();
        store.accept_validated_coverage(coverage(&source, 7))?;
        let key = [
            b"\0data/coverage/change/".as_slice(),
            &source.tenant_id,
            &1u64.to_be_bytes(),
            &source.key(),
            &7u64.to_be_bytes(),
        ]
        .concat();
        let mut tx = store.write()?;
        tx.native().insert(key, bad);
        tx.commit([])?;
        assert!(store
            .view()?
            .coverage_changes(
                &selection(&source),
                StorePositionV1 {
                    commit_revision: 0,
                    ordinal: u32::MAX
                },
                &AnalysisReadControl::default()
            )
            .is_err());
    }
    Ok(())
}

#[test]
fn corrupt_raw_controls_are_rejected() -> TestResult {
    for fault in ["allocator", "reduced end", "missing end"] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("data");
        let store = NativeStore::open(&root)?;
        let source = identity();
        store.accept_validated_batch(source.clone(), batch(1))?;
        store.accept_validated_coverage(coverage(&source, 7))?;
        let mut corrupt = store.branch().write_tx()?;
        match fault {
            "allocator" => corrupt.insert(b"\0data/raw/next", 0u64.to_be_bytes()),
            _ => {
                let segment = std::fs::read_dir(root.join("segments"))?
                    .next()
                    .ok_or("segment absent")??;
                let name = segment.file_name();
                let name = name.to_str().ok_or("segment name")?;
                let id = u64::from_str_radix(name.split('.').next().ok_or("segment id")?, 16)?;
                let key = [b"\0data/raw/end/".as_slice(), &id.to_be_bytes()].concat();
                if fault == "missing end" {
                    corrupt.remove(key);
                } else {
                    let end = std::fs::metadata(segment.path())?.len() - 1;
                    corrupt.insert(key, end.to_be_bytes());
                }
            }
        }
        corrupt.insert(b"\0data/head", 3u64.to_be_bytes());
        corrupt.commit_stamped([[b"\0data/cut/".as_slice(), &3u64.to_be_bytes()].concat()])?;
        drop(store);
        assert!(
            matches!(
                NativeStore::open(&root),
                Err(araphor_data::Error::NativeState { .. })
            ),
            "{fault}"
        );
    }
    Ok(())
}
