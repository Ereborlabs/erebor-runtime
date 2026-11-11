#![cfg(feature = "test-fixtures")]

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisStore, AnalysisTableRead, AnalysisTableRequests, EvidenceIntakeIdentityV1,
    EvidenceRetentionOwner, EvidenceStoreOutcomeV1, RetentionLimitsV1, StorePositionV1,
    ValidatedCoverageV1, ValidatedEvidenceBatchV1,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

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
        intake_utc_ns: 100,
        framed_records: vec![cursor as u8].into(),
        frame_ends: vec![1],
    }
}

#[test]
fn captured_roots_survive_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let source = identity();
    let empty = store.raw_index_fixture()?;
    assert_eq!(empty.counts(), (0, 0, 0));
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(2))?,
        EvidenceStoreOutcomeV1::Pending
    );
    let pending = store.raw_index_fixture()?;
    assert_eq!(pending.counts(), (1, 1, 1));
    assert_eq!(
        pending
            .receipt(&source)
            .ok_or("pending receipt absent")?
            .contiguous_cursor,
        0
    );
    assert_eq!(
        store.accept_validated_batch(source.clone(), batch(1))?,
        EvidenceStoreOutcomeV1::Accepted
    );
    let accepted = store.raw_index_fixture()?;
    assert_eq!(accepted.counts(), (2, 2, 2));
    assert_eq!(
        accepted
            .receipt(&source)
            .ok_or("accepted receipt absent")?
            .contiguous_cursor,
        2
    );
    let revision = store.meta()?.commit_revision;
    store.accept_validated_batch(source.clone(), batch(2))?;
    assert_eq!(store.meta()?.commit_revision, revision);
    let mut conflict = batch(2);
    conflict.framed_records = vec![9].into();
    assert!(store
        .accept_validated_batch(source.clone(), conflict)
        .is_err());
    assert_eq!(store.meta()?.commit_revision, revision);
    assert_eq!(store.raw_index_fixture()?.counts(), accepted.counts());
    store.accept_validated_coverage(ValidatedCoverageV1 {
        identity: source.clone(),
        cpu_id: 0,
        revision: 7,
        encoded_report: vec![7],
    })?;
    let covered = store.raw_index_fixture()?;
    let covered_view = store.view()?;
    let segment = std::fs::read_dir(root.join("segments"))?
        .next()
        .ok_or("segment absent")??
        .path();
    assert_eq!(
        covered
            .receipt(&source)
            .ok_or("coverage receipt absent")?
            .coverage_revision,
        7
    );
    assert_eq!(
        accepted
            .receipt(&source)
            .ok_or("old receipt absent")?
            .coverage_revision,
        0
    );
    store.checkpoint()?;
    let removed = EvidenceRetentionOwner::new(&store).retain(&source, 201)?;
    assert_eq!(removed.removed_records, 2);
    assert_eq!(removed.retained_floor, 2);
    assert_eq!(removed.retained_bytes, 0);
    assert!(!segment.exists());
    assert_eq!(store.raw_index_fixture()?.counts(), (2, 2, 2));
    let current = store
        .source_receipt(&source)?
        .ok_or("retained receipt absent")?;
    assert_eq!(current.contiguous_cursor, 2);
    assert_eq!(current.coverage_revision, 7);
    assert_eq!(current.retained_floor, 2);
    assert_eq!(covered.counts(), (2, 2, 2));
    assert_eq!(
        covered
            .receipt(&source)
            .ok_or("captured receipt absent")?
            .retained_floor,
        0
    );
    assert_eq!(pending.counts(), (1, 1, 1));
    assert_eq!(
        pending
            .receipt(&source)
            .ok_or("pending receipt absent")?
            .contiguous_cursor,
        0
    );
    assert_eq!(empty.counts(), (0, 0, 0));
    assert!(empty.receipt(&source).is_none());
    assert!(matches!(
        store.read_page(&source, 1),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert!(matches!(
        store.read_page_at(&covered_view, &source, 1, &AnalysisReadControl::default()),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    let requests = AnalysisTableRequests::from([(
        "events".into(),
        Some(std::collections::BTreeSet::from([
            AnalysisStore::table_schemas()["events"].index_of("source_cursor")?,
        ])),
    )]);
    let selection =
        AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]).project(&requests)?;
    let read = AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        mode: AnalysisReadModeV1::Complete,
        now: 201,
    };
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.read_tables_at(
            &covered_view,
            &selection,
            read,
            Default::default(),
            &control,
            None
        ),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    let latest = store.read_tables(&selection, read, Default::default(), &control)?;
    assert_eq!(
        latest
            .tables
            .get("events")
            .into_iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    let mut beyond = selection.clone();
    beyond.cursor_from = std::ops::Bound::Included(3);
    let outside = store.read_tables_at(
        &covered_view,
        &beyond,
        read,
        Default::default(),
        &control,
        None,
    )?;
    assert_eq!(
        outside
            .tables
            .get("events")
            .into_iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    let excluded = store.read_tables_at(
        &covered_view,
        &selection,
        AnalysisTableRead {
            event_ranges: Some(&[(101, 102)]),
            ..read
        },
        Default::default(),
        &control,
        None,
    )?;
    assert_eq!(
        excluded
            .tables
            .get("events")
            .into_iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    assert_eq!(
        covered_view
            .source_receipt(&source)?
            .ok_or("captured view receipt")?
            .retained_floor,
        0
    );
    drop(covered_view);
    drop(store);
    let reopened = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(reopened.source_receipt(&source)?, Some(current));
    assert_eq!(reopened.raw_index_fixture()?.counts(), (2, 2, 2));
    assert_eq!(covered.counts(), (2, 2, 2));
    assert_eq!(
        covered
            .receipt(&source)
            .ok_or("reopen captured receipt absent")?
            .retained_floor,
        0
    );
    Ok(())
}

#[test]
fn metadata_position_resume() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let source = identity();
    store.accept_validated_batch(source.clone(), batch(2))?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let requests = AnalysisTableRequests::from([("coverage".into(), None)]);
    let read = || AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        mode: AnalysisReadModeV1::Metadata,
        now: 100,
    };
    let pending = store.read_tables(
        &selection,
        read(),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(pending.extraction.sources.len(), 1);
    assert_eq!(pending.extraction.sources[0].pending.len(), 1);
    assert_eq!(
        (
            pending.extraction.sources[0].pending[0].first_cursor,
            pending.extraction.sources[0].pending[0].last_cursor
        ),
        (1, 1)
    );
    store.accept_validated_batch(source.clone(), batch(1))?;
    let mut other = source.clone();
    other.source_id = [4; 16];
    store.accept_validated_batch(other, batch(1))?;
    let complete = store.read_tables(
        &selection,
        read(),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(complete.extraction.sources[0].commit_revision, 2);
    assert!(complete.extraction.sources[0].pending.is_empty());
    assert_eq!(complete.extraction.sources[0].receipt.contiguous_cursor, 2);
    let first = store.read_page(&source, 1)?;
    assert_eq!(first.records.len(), 2);
    assert_eq!(
        first.records[0].position,
        StorePositionV1 {
            commit_revision: 2,
            ordinal: 0
        }
    );
    assert_eq!(
        first.records[1].position,
        StorePositionV1 {
            commit_revision: 1,
            ordinal: 0
        }
    );
    let before = store.meta()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?, before);
    store.accept_validated_batch(source.clone(), batch(3))?;
    let next = store.read_page(&source, 3)?;
    assert_eq!(next.records.len(), 1);
    assert_eq!(next.records[0].framed_record, vec![3]);
    assert_eq!(next.records[0].position.commit_revision, 4);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.read_page(&source, 3)?.records, next.records);
    assert_eq!(reopened.read_page(&source, 1)?.records[..2], first.records);
    let complete = reopened.read_tables(
        &selection,
        read(),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(complete.extraction.sources[0].commit_revision, 4);
    Ok(())
}

#[test]
fn append_failure_keeps_root() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let source = identity();
    store.accept_validated_batch(source.clone(), batch(1))?;
    let captured = store.raw_index_fixture()?;
    let receipt = captured.receipt(&source);
    let segment = std::fs::read_dir(root.join("segments"))?
        .next()
        .ok_or("segment absent")??
        .path();
    let saved = root.join("saved-segment");
    let (moved, backup) = (segment.clone(), saved.clone());
    store.set_commit_hook(araphor_data::AnalysisCommitStage::BeforeAppend, move || {
        std::fs::rename(&moved, &backup).map_err(|source| araphor_data::Error::Io {
            path: moved.clone(),
            source,
            location: snafu::location!(),
        })?;
        std::fs::create_dir(&moved).map_err(|source| araphor_data::Error::Io {
            path: moved,
            source,
            location: snafu::location!(),
        })?;
        Ok(())
    })?;
    let failed = store.accept_validated_batch(source.clone(), batch(2));
    std::fs::remove_dir(&segment)?;
    std::fs::rename(saved, segment)?;
    assert!(failed.is_err());
    assert_eq!(captured.counts(), (1, 1, 1));
    assert_eq!(captured.receipt(&source), receipt);
    assert!(store.view().is_err());
    assert!(store.write().is_err());
    assert!(store.raw_index_fixture().is_err());
    store.recover()?;
    assert_eq!(store.raw_index_fixture()?.counts(), captured.counts());
    assert_eq!(store.raw_index_fixture()?.receipt(&source), receipt);
    assert_eq!(captured.receipt(&source), receipt);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.source_receipt(&source)?, receipt);
    assert_eq!(store.read_page(&source, 1)?.records.len(), 1);
    store.accept_validated_batch(source.clone(), batch(2))?;
    assert_eq!(store.read_page(&source, 1)?.records.len(), 2);
    assert_eq!(captured.counts(), (1, 1, 1));
    assert_eq!(captured.receipt(&source), receipt);
    Ok(())
}
