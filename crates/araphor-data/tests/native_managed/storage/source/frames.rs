use super::*;

#[test]
fn source_frames_commit_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    SourceFixture::append(&store, 1, 3)?;
    let fixture = SourceFixture::new(&store)?;
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let frame = first.state.source().ok_or("initial source frame")?;
    assert_eq!(frame.datasets()[0].rows(), 3);
    assert_eq!(
        first.page.extraction.sources[0].receipt.contiguous_cursor,
        3
    );
    assert!(frame.proof().is_none());
    let input = request("source-first");
    let attempt = store.register_managed_attempt(&first.state, &input, || Ok(()))?;
    let evaluations = [
        fixture.fixture.continued(&input, 10, Some(&first.state))?,
        fixture.fixture.continued(&input, 11, Some(&first.state))?,
    ];
    let outputs = [fixture.fixture.output(2)?, fixture.fixture.output(3)?];
    assert!(fixture
        .fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            Err(araphor_data::Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        })
        .is_err());
    assert!(frame.proof().is_none());
    assert_eq!(fixture.fixture.current(&store)?.progress, 0);
    let receipt = fixture
        .fixture
        .publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(
        frame.proof().ok_or("committed source proof")?.as_ref(),
        &receipt.selected
    );
    let reference = SourceFixture::reference(&first.state, &receipt)?;
    let restored = fixture.restore(
        &store,
        &receipt.selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let restored = restored.state.source().ok_or("restored source frame")?;
    assert!(matches!(restored.read(), ManagedSourceRead::Initial));
    assert_eq!(restored.datasets()[0].batches, frame.datasets()[0].batches);
    assert_eq!(restored.proof(), frame.proof());

    SourceFixture::append(&store, 4, 2)?;
    let next = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference.clone()),
        &AnalysisReadControl::default(),
    )?;
    let changed = next.state.source().ok_or("changed source frame")?;
    assert_eq!(changed.datasets()[0].rows(), 2);
    assert_eq!(next.page.extraction.sources[0].receipt.contiguous_cursor, 5);
    let receipt = fixture.publish(&store, &next.state, "source-next")?;
    let parent = reference;
    let reference = SourceFixture::reference(&next.state, &receipt)?;
    let (saved, _, _) = store.managed_reference(
        &fixture.fixture.current(&store)?,
        &receipt.selected.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        store.managed_parent(&saved, &AnalysisReadControl::default())?,
        Some(parent)
    );
    let idle = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference.clone()),
        &AnalysisReadControl::default(),
    )?;
    let idle = idle.state.source().ok_or("idle source frame")?;
    assert_eq!(idle.datasets()[0].rows(), 0);
    fixture.execution.clear();
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = fixture.restore(
        &reopened,
        &receipt.selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let frame = restored.state.source().ok_or("reopened source frame")?;
    assert!(matches!(frame.read(), ManagedSourceRead::Initial));
    assert_eq!(frame.datasets()[0].rows(), 5);
    assert_eq!(
        frame.proof().ok_or("reopened source proof")?.as_ref(),
        &receipt.selected
    );
    Ok(())
}

#[test]
fn source_rows_keep_selected_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    SourceFixture::append(&store, 1, 3)?;
    let fixture = SourceFixture::new(&store)?;
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let frame = first.state.source().ok_or("initial source frame")?;
    let block = frame.row_handles("events", 0)?;
    assert!(block.select(&[3], std::sync::Arc::new(())).is_err());
    let selected = block.select(&[1, 1], std::sync::Arc::new(()))?;
    assert_eq!(selected.witnesses().len(), 1);
    let concurrent = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    assert!(concurrent
        .state
        .source()
        .ok_or("concurrent frame")?
        .record_rows(&selected)
        .is_err());
    let receipt = fixture.publish(&store, &first.state, "rows-first")?;
    let reference = SourceFixture::reference(&first.state, &receipt)?;
    SourceFixture::append(&store, 4, 2)?;
    let next = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference),
        &AnalysisReadControl::default(),
    )?;
    let changed = next.state.source().ok_or("changed source frame")?;
    changed.record_rows(&selected)?;
    let rows = changed.row_handles("events", 0)?;
    changed.record_rows(&rows.select(&[0, 1], std::sync::Arc::new(()))?)?;
    let mut input = request("rows-next");
    input.witness_expiry = 200;
    let attempt = store.register_managed_attempt(&next.state, &input, || Ok(()))?;
    let evaluations = [
        fixture.fixture.continued(&input, 10, Some(&next.state))?,
        fixture.fixture.continued(&input, 11, Some(&next.state))?,
    ];
    let outputs = [fixture.fixture.output(2)?, fixture.fixture.output(3)?];
    assert!(fixture
        .fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            Err(araphor_data::Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        })
        .is_err());
    assert!(changed.proof().is_none());
    assert_eq!(
        fixture.fixture.current(&store)?.progress,
        receipt.commit_revision
    );
    assert!(changed
        .record_rows(&block.select(&[0], std::sync::Arc::new(()))?)
        .is_err());
    let receipt = fixture
        .fixture
        .publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(
        changed.proof().ok_or("selected row proof")?.as_ref(),
        &receipt.selected
    );
    let saved_witnesses = witnesses(&store, &receipt.selected)?;
    assert_eq!(
        saved_witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [2, 4, 5]
    );
    assert!(saved_witnesses
        .iter()
        .all(|witness| witness.expires_utc_ns == 200));
    let (key, original) =
        super::super::output::result_record(store.view()?.as_ref(), &receipt.selected.result_id)?;
    let mut changed: Value = rmp_serde::from_slice(&original[1..])?;
    let Value::Seq(values) = field(&mut changed, &["body", "Selected", "witnesses"])? else {
        return Err("selected witnesses".into());
    };
    values.push(values[0].clone());
    let mut transaction = store.write()?;
    transaction.native().insert(&key, framed(&changed)?);
    transaction.commit([])?;
    fixture.execution.clear();
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(araphor_data::Error::Package {
            code: Code::Invalid,
            field: "managed source evidence order",
            ..
        })
    ));
    repair(&root, &key, &original)?;
    let reopened = AnalysisStore::open(&root)?;
    let restored = fixture.restore(
        &reopened,
        &receipt.selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let frame = restored.state.source().ok_or("restored selected source")?;
    assert_eq!(frame.datasets()[0].rows(), 5);
    assert_eq!(
        frame.proof().ok_or("restored selected proof")?.as_ref(),
        &receipt.selected
    );
    assert_eq!(witnesses(&reopened, &receipt.selected)?, saved_witnesses);
    Ok(())
}

#[test]
fn source_frames_keep_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("store"))?);
    SourceFixture::append(&store, 1, 3)?;
    let fixture = SourceFixture::new(&store)?;
    let initial = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &initial.state, "source-cut-base")?;
    let reference = SourceFixture::reference(&initial.state, &receipt)?;
    SourceFixture::append(&store, 4, 2)?;
    let expected = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&store);
    control.on_read_step(move || SourceFixture::append(&writer, 6, 1))?;
    let captured = fixture.read(&store, ManagedSourceRead::Changes(reference), &control)?;
    let frame = captured.state.source().ok_or("fixed source frame")?;
    assert_eq!(
        store
            .source_receipt(&identity())?
            .ok_or("appended source")?
            .contiguous_cursor,
        6
    );
    assert_eq!(
        frame.position(),
        StorePositionV1 {
            commit_revision: expected.commit_revision,
            ordinal: u32::MAX
        }
    );
    assert_eq!(frame.datasets()[0].rows(), 2);
    assert_eq!(
        captured.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        5
    );
    assert_eq!(
        fixture.fixture.current(&store)?.progress,
        receipt.commit_revision
    );
    Ok(())
}

#[test]
fn source_frames_reject_basis() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    SourceFixture::append(&store, 1, 3)?;
    let fixture = SourceFixture::new(&store)?;
    let initial = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &initial.state, "source-validation")?;
    let reference = SourceFixture::reference(&initial.state, &receipt)?;
    assert!(fixture
        .read(
            &store,
            ManagedSourceRead::Initial,
            &AnalysisReadControl::default()
        )
        .is_err());
    for case in 0..4 {
        let mut changed = reference.clone();
        match case {
            0 => changed.position.commit_revision += 1,
            1 => changed.position.ordinal = 0,
            2 => changed.result.result_id.push('x'),
            _ => changed.result.commit_revision -= 1,
        }
        assert!(
            fixture
                .read(
                    &store,
                    ManagedSourceRead::Changes(changed),
                    &AnalysisReadControl::default()
                )
                .is_err(),
            "case {case}"
        );
    }
    let mut wrong = fixture.requests.clone();
    wrong
        .get_mut("events")
        .and_then(Option::as_mut)
        .ok_or("source columns")?
        .clear();
    let instance = fixture.fixture.current(&store)?;
    assert!(store
        .read_managed_tables_filtered(
            &instance.grant.selection,
            &ManagedRead {
                source: Some(ManagedSourceRead::Changes(reference.clone())),
                instance: instance.clone(),
                execution: None,
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &wrong,
                event_ranges: None,
                mode: AnalysisReadModeV1::Changes(reference.position),
                now: 10
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )
        .is_err());
    assert_eq!(
        fixture.fixture.current(&store)?.progress,
        receipt.commit_revision
    );
    let stale = initial
        .state
        .source()
        .ok_or("initial source")?
        .row_handles("events", 0)?
        .select(&[0], std::sync::Arc::new(()))?;
    fixture.execution.clear();
    let backup = root.join("backups/basis");
    let restored_root = directory.path().join("restored");
    let manifest = store.backup(&backup)?;
    let restored_store = AnalysisStore::restore(&backup, &restored_root)?;
    assert_eq!(
        restored_store.meta()?.recovery_epoch,
        manifest.recovery_epoch + 1
    );
    let store = restored_store;
    let restored = fixture.restore(
        &store,
        &receipt.selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let fresh = restored.state.source().ok_or("recovered source")?;
    assert_eq!(fresh.datasets()[0].rows(), 3);
    assert_eq!(
        fresh.proof().ok_or("recovered proof")?.as_ref(),
        &receipt.selected
    );
    let fresh = fresh
        .row_handles("events", 0)?
        .select(&[0], std::sync::Arc::new(()))?;
    let next = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference),
        &AnalysisReadControl::default(),
    )?;
    let source = next.state.source().ok_or("recovered continuation")?;
    assert!(matches!(
        source.record_rows(&stale),
        Err(araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Conflict,
            field: "managed source row scope",
            ..
        })
    ));
    source.record_rows(&fresh)?;
    let continued = fixture.publish(&store, &next.state, "source-recovered")?;
    assert!(continued.commit_revision > receipt.commit_revision);
    store.recover()?;
    Ok(())
}

#[test]
fn source_frames_skip_empty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    SourceFixture::append(&store, 1, 3)?;
    let mut fixture = SourceFixture::new(&store)?;
    fixture.requests.insert(
        "context_versions".into(),
        Some(SourceFixture::columns("context_versions")?),
    );
    let captured = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let frame = captured.state.source().ok_or("mixed source frame")?;
    assert_eq!(
        frame
            .datasets()
            .iter()
            .map(|data| (data.name.as_str(), data.rows()))
            .collect::<Vec<_>>(),
        [("context_versions", 0), ("events", 3)]
    );
    let receipt = fixture.publish(&store, &captured.state, "source-mixed")?;
    let reference = SourceFixture::reference(&captured.state, &receipt)?;
    let idle = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference),
        &AnalysisReadControl::default(),
    )?;
    assert!(idle
        .state
        .source()
        .ok_or("idle source frame")?
        .datasets()
        .iter()
        .all(|data| data.batches.is_empty()));
    let receipt = fixture.publish(&store, &idle.state, "source-idle")?;
    let restored = fixture.restore(
        &store,
        &receipt.selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let frame = restored.state.source().ok_or("restored idle source")?;
    assert_eq!(
        frame
            .datasets()
            .iter()
            .map(sdk::Dataset::rows)
            .collect::<Vec<_>>(),
        [0, 3]
    );
    assert!(matches!(frame.read(), ManagedSourceRead::Initial));
    assert_eq!(
        frame.proof().ok_or("restored idle proof")?.as_ref(),
        &receipt.selected
    );
    Ok(())
}
