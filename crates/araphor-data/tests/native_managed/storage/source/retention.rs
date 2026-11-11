use super::*;

#[test]
fn source_history_keeps_headers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open_with_retention(
        &root,
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    SourceFixture::append(&store, 100, 1)?;
    let mut fixture = SourceFixture::new(&store)?;
    fixture.requests = BTreeMap::from([("coverage".into(), Some(BTreeSet::new()))]);
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let frame = first.state.source().ok_or("pending source frame")?;
    assert_eq!(first.page.extraction.sources.len(), 1);
    let pending = &first.page.extraction.sources[0];
    assert_eq!(pending.receipt.contiguous_cursor, 0);
    assert_eq!(
        pending.pending,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 1,
            last_cursor: 99,
            commit_revision: frame.position().commit_revision,
        }]
    );
    assert!(pending.expired.is_empty());
    let first_receipt = fixture.publish(&store, &first.state, "pending-head")?;
    let first_reference = SourceFixture::reference(&first.state, &first_receipt)?;

    SourceFixture::append(&store, 1, 99)?;
    let repaired = fixture.read(
        &store,
        ManagedSourceRead::Changes(first_reference),
        &AnalysisReadControl::default(),
    )?;
    let repaired_source = &repaired.page.extraction.sources[0];
    assert_eq!(repaired_source.receipt.contiguous_cursor, 100);
    assert!(repaired_source.pending.is_empty());
    let repaired_receipt = fixture.publish(&store, &repaired.state, "repaired-head")?;
    let removed =
        araphor_data::EvidenceRetentionOwner::new(&store).retain(&identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 100);
    assert_eq!(removed.retained_bytes, 0);
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    assert_eq!(store.raw_index_fixture()?.range_count(&identity()), 2);
    fixture.execution.clear();
    let assert_headers = |selected: &AnalysisStore| -> TestResult {
        for (receipt, expected) in [
            (&first_receipt, pending),
            (&repaired_receipt, repaired_source),
        ] {
            let page = fixture.restore(
                selected,
                &receipt.selected,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
            )?;
            let source = &page.page.extraction.sources[0];
            assert_eq!(source.receipt, expected.receipt);
            assert_eq!(source.pending, expected.pending);
            assert_eq!(source.expired, expected.expired);
            assert!(!page.page.tables.contains_key("events"));
            let frame = page.state.source().ok_or("historical source headers")?;
            assert_eq!(frame.proof().map(Arc::as_ref), Some(&receipt.selected));
        }
        Ok(())
    };
    assert_headers(&store)?;
    let view = store.view()?;
    let markers = records(&view, b"\0data/@retention/expired/")?;
    assert_eq!(markers.len(), 1);
    let (key, original) = markers.into_iter().next().ok_or("expired marker")?;
    let mut changed: Value = rmp_serde::from_slice(&original[1..])?;
    let Value::Seq(marker) = &mut changed else {
        return Err("expired marker sequence".into());
    };
    assert_eq!(marker.len(), 6);
    let Value::Seq(entries) = &mut marker[4] else {
        return Err("expired entries".into());
    };
    let mut matched = 0;
    for entry in entries {
        let Value::Seq(entry) = entry else {
            return Err("expired entry sequence".into());
        };
        assert_eq!(entry.len(), 6);
        let Value::Seq(commit) = &mut entry[1] else {
            return Err("expired commit sequence".into());
        };
        assert_eq!(commit.len(), 4);
        let Value::Seq(spans) = &mut commit[3] else {
            return Err("expired spans".into());
        };
        for span in spans {
            let Value::Seq(span) = span else {
                return Err("expired span sequence".into());
            };
            assert_eq!(span.len(), 5);
            let first: u64 = span[0].clone().deserialize_into()?;
            let last: u64 = span[1].clone().deserialize_into()?;
            if first == 100 && last == 100 {
                span[0] = Value::U64(99);
                matched += 1;
            }
        }
    }
    assert_eq!(matched, 1);
    drop(view);
    let mut transaction = store.write()?;
    transaction.native().insert(&key, framed(&changed)?);
    transaction.commit([])?;
    assert_headers(&store)?;
    assert!(matches!(
        store.recover(),
        Err(araphor_data::Error::AnalysisState { reason, .. }) if reason == "raw cursor ranges overlap"
    ));
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(araphor_data::Error::AnalysisState { reason, .. }) if reason == "raw cursor ranges overlap"
    ));
    repair(&root, &key, &original)?;
    let reopened = AnalysisStore::open(&root)?;
    assert_headers(&reopened)?;
    Ok(())
}

#[test]
fn source_pending_blocks_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open_with_retention(
        &root,
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    SourceFixture::append(&store, 100, 1)?;
    let mut fixture = SourceFixture::new(&store)?;
    fixture.requests = BTreeMap::from([("coverage".into(), Some(BTreeSet::new()))]);
    let removed =
        araphor_data::EvidenceRetentionOwner::new(&store).retain(&identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 0);
    let positions = pending_rows(&store)?;
    assert_eq!(positions, [(100, 1, 0)]);
    let segment = std::fs::read_dir(root.join("segments"))?
        .next()
        .ok_or("pending segment")??
        .path();
    let bytes = std::fs::read(&segment)?;
    let page = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let frame = page.state.source().ok_or("retained pending source")?;
    assert_eq!(page.page.extraction.sources.len(), 1);
    let source = &page.page.extraction.sources[0];
    assert_eq!(source.receipt.contiguous_cursor, 0);
    assert_eq!(source.receipt.retained_floor, 0);
    assert!(source.expired.is_empty());
    assert_eq!(
        source.pending,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 1,
            last_cursor: 99,
            commit_revision: frame.position().commit_revision,
        }]
    );
    assert!(!page.page.tables.contains_key("events"));
    let metadata = (source.receipt.clone(), source.pending.clone());
    store.recover()?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    reopened.recover()?;
    let page = fixture.read(
        &reopened,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let source = &page.page.extraction.sources[0];
    assert!(!page.page.tables.contains_key("events"));
    assert_eq!((source.receipt.clone(), source.pending.clone()), metadata);
    assert_eq!(pending_rows(&reopened)?, positions);
    assert_eq!(std::fs::read(&segment)?, bytes);
    Ok(())
}

#[test]
fn source_changes_require_raw() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_retention(
        directory.path().join("store"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    SourceFixture::append(&store, 100, 1)?;
    let mut fixture = SourceFixture::new(&store)?;
    fixture.requests.clear();
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &first.state, "accepted-head")?;
    let reference = SourceFixture::reference(&first.state, &receipt)?;
    SourceFixture::append(&store, 1, 99)?;
    let removed =
        araphor_data::EvidenceRetentionOwner::new(&store).retain(&identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 100);
    let before = store.meta()?;
    let page = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference.clone()),
        &AnalysisReadControl::default(),
    )?;
    let frame = page.state.source().ok_or("retired source changes")?;
    assert!(frame.datasets().is_empty());
    let current = fixture.fixture.current(&store)?;
    let none = BTreeMap::from([("events".into(), None)]);
    let page = store.read_tables(
        &current.grant.selection,
        AnalysisTableRead {
            requests: &none,
            event_ranges: None,
            mode: AnalysisReadModeV1::Changes(reference.position),
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.tables.is_empty());
    let cardinality = BTreeMap::from([("events".into(), Some(BTreeSet::new()))]);
    assert!(matches!(
        store.read_tables(
            &current.grant.selection,
            AnalysisTableRead {
                requests: &cardinality,
                event_ranges: None,
                mode: AnalysisReadModeV1::Changes(reference.position),
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        ),
        Err(araphor_data::Error::AnalysisReplayExpired { .. })
    ));
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(store.meta()?, before);
    Ok(())
}
