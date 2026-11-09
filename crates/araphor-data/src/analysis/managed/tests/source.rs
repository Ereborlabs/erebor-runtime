use super::*;
use crate::{EvidenceRecord, StorePositionV1, ValidatedEvidenceBatchV1};

struct SourceFixture {
    fixture: Fixture,
    execution: Arc<ManagedExecution>,
    requests: AnalysisTableRequests,
}

impl SourceFixture {
    fn new(store: &AnalysisStore) -> TestResult<Self> {
        let source = crate::analysis::tests::identity();
        let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
        let columns = Self::columns("events")?;
        Ok(Self {
            fixture: Fixture::admit_scope(store, false, selection)?,
            execution: Arc::default(),
            requests: BTreeMap::from([("events".into(), Some(columns))]),
        })
    }

    fn columns(name: &str) -> TestResult<BTreeSet<usize>> {
        let schema = &AnalysisStore::table_schemas()[name];
        let names = schema.fields()[0].metadata()["araphor.join_keys"].split(',');
        let mut columns = names
            .map(|name| schema.index_of(name))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        for name in ["commit_revision", "ordinal", "received_utc_ns"] {
            if let Ok(index) = schema.index_of(name) {
                columns.insert(index);
            }
        }
        Ok(columns)
    }

    fn append(store: &AnalysisStore, first: u64, count: usize) -> crate::Result<()> {
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..first + count as u64 {
            bytes.extend(Vec::<u8>::try_from(&EvidenceRecord {
                observed_boottime_ns: cursor,
                ..Default::default()
            })?);
            ends.push(bytes.len());
        }
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: first + count as u64 - 1,
                intake_utc_ns: first,
                framed_records: bytes.into(),
                frame_ends: ends,
            },
        )?;
        Ok(())
    }

    fn read(
        &self,
        store: &AnalysisStore,
        source: ManagedSourceRead,
        control: &AnalysisReadControl,
    ) -> TestResult<ManagedPage> {
        self.read_owners(store, source, control, None)
    }

    fn read_owners(
        &self,
        store: &AnalysisStore,
        source: ManagedSourceRead,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> TestResult<ManagedPage> {
        let instance = self.fixture.current(store)?;
        let mode = source
            .after()
            .map_or(AnalysisReadModeV1::Complete, AnalysisReadModeV1::Changes);
        Ok(store.read_managed_tables_filtered(
            &instance
                .spec
                .destination
                .selection(&instance.grant.selection)?
                .project(&self.requests)?,
            &ManagedRead {
                source: Some(source),
                execution: Some(Arc::clone(&self.execution)),
                instance: instance.clone(),
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            control,
            owners,
        )?)
    }

    fn restore(
        &self,
        store: &AnalysisStore,
        result: &crate::analysis::PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> TestResult<ManagedPage> {
        let instance = self.fixture.current(store)?;
        let (reference, call, _) =
            store.managed_reference(&instance, &result.result_id, 10, control)?;
        assert!(call.is_none());
        Ok(store.read_managed_reference(
            &instance
                .spec
                .destination
                .selection(&instance.grant.selection)?
                .project(&self.requests)?,
            &reference,
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: reference.request().time_utc_ns,
            },
            limits,
            control,
            None,
        )?)
    }

    fn publish(
        &self,
        store: &AnalysisStore,
        capture: &ManagedCapture,
        id: &str,
    ) -> TestResult<ManagedReceipt> {
        let request = request(id);
        let attempt = store.register_managed_attempt(capture, &request, || Ok(()))?;
        let evaluations = [
            self.fixture.evaluation(&request, 10, Some(capture))?,
            self.fixture.evaluation(&request, 11, Some(capture))?,
        ];
        self.fixture.publish_checked(
            store,
            &attempt,
            &evaluations,
            &[self.fixture.output(2)?, self.fixture.output(3)?],
            || Ok(()),
        )
    }

    fn reference(
        capture: &ManagedCapture,
        receipt: &ManagedReceipt,
    ) -> TestResult<ManagedSourceRef> {
        Ok(ManagedSourceRef {
            result: receipt.selected.clone(),
            position: capture.source().ok_or("source frame absent")?.position(),
        })
    }
}

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
        fixture.fixture.evaluation(&input, 10, Some(&first.state))?,
        fixture.fixture.evaluation(&input, 11, Some(&first.state))?,
    ];
    let outputs = [fixture.fixture.output(2)?, fixture.fixture.output(3)?];
    assert!(fixture
        .fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            crate::AnalysisReadDeniedSnafu.fail()
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
        fixture.fixture.evaluation(&input, 10, Some(&next.state))?,
        fixture.fixture.evaluation(&input, 11, Some(&next.state))?,
    ];
    let outputs = [fixture.fixture.output(2)?, fixture.fixture.output(3)?];
    assert!(fixture
        .fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            crate::AnalysisReadDeniedSnafu.fail()
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
    let (step, revision) = AnalysisStore::managed_step_header(
        store.writer()?.get_mut()?,
        fixture.fixture.instance.spec.tenant,
        &receipt.selected.result_id,
    )?;
    assert_eq!(
        step.witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [2, 4, 5]
    );
    assert!(step
        .witnesses
        .iter()
        .all(|witness| witness.expires_utc_ns == 200));
    let mut corrupt = step.clone();
    corrupt.witnesses.push(step.witnesses[0].clone());
    assert!(AnalysisStore::validate_selected_header(
        store.writer()?.get_mut()?,
        fixture.fixture.instance.spec.tenant,
        &receipt.selected.result_id,
        &corrupt,
        revision,
    )
    .is_err());
    fixture.execution.clear();
    drop(store);
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
    let (saved, _) = AnalysisStore::managed_step_header(
        reopened.writer()?.get_mut()?,
        fixture.fixture.instance.spec.tenant,
        &receipt.selected.result_id,
    )?;
    assert_eq!(saved.witnesses, step.witnesses);
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
    *control
        .snapshot_step
        .lock()
        .map_err(|_| "source snapshot hook")? =
        Some(Box::new(move || SourceFixture::append(&writer, 6, 1)));
    let captured = fixture.read(&store, ManagedSourceRead::Changes(reference), &control)?;
    let frame = captured.state.source().ok_or("fixed source frame")?;
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
    let store = AnalysisStore::open(directory.path().join("store"))?;
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
    store
        .writer()?
        .get_mut()?
        .execute_batch("UPDATE store_meta SET recovery_epoch = recovery_epoch + 1")?;
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
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Conflict,
            field: "managed source row scope",
            ..
        })
    ));
    source.record_rows(&fresh)?;
    let continued = fixture.publish(&store, &next.state, "source-recovered")?;
    assert!(continued.commit_revision > receipt.commit_revision);
    store.verify_state()?;
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

#[test]
fn source_reads_release_views() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("store"),
        Default::default(),
        crate::StorageLimitsV1 {
            reader_admissions: Some(1),
            ..Default::default()
        },
    )?;
    SourceFixture::append(&store, 1, 3)?;
    let mut context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "source-cut".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"{}".to_vec(),
    };
    store.commit_context(&context)?;
    let fixture = SourceFixture {
        fixture: Fixture::admit_scope(&store, false, AnalysisSelectionV1::tenant([1; 16]))?,
        execution: Arc::default(),
        requests: BTreeMap::from([
            ("events".into(), Some(SourceFixture::columns("events")?)),
            (
                "context_versions".into(),
                Some(SourceFixture::columns("context_versions")?),
            ),
        ]),
    };
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &first.state, "source-view")?;
    let instance = fixture.fixture.current(&store)?;
    let (reference, call, _) = store.managed_reference(
        &instance,
        &receipt.selected.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert!(call.is_none());
    SourceFixture::append(&store, 4, 2)?;
    context.key.owner_revision = 2;
    store.commit_context(&context)?;
    let meta = store.meta()?;
    for case in 0..3 {
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        assert_eq!(
            store.context_head([1; 16], "source-cut", &[1], &[2])?,
            Some(context.clone())
        );
        let current = store.read_tables(
            &instance.grant.selection,
            AnalysisTableRead {
                requests: &fixture.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            current.tables["events"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            5
        );
        assert_eq!(
            current.tables["context_versions"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        let scope = instance
            .spec
            .destination
            .selection(&instance.grant.selection)?
            .project(&fixture.requests)?;
        let read = || AnalysisTableRead {
            requests: &fixture.requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: reference.request().time_utc_ns,
        };
        match case {
            0 => {
                let old = store.read_managed_reference(
                    &scope,
                    &reference,
                    read(),
                    AnalysisExtractLimits::default(),
                    &AnalysisReadControl::default(),
                    None,
                )?;
                let source = old.state.source().ok_or("historical source")?;
                assert_eq!(
                    source
                        .datasets()
                        .iter()
                        .map(sdk::Dataset::rows)
                        .collect::<Vec<_>>(),
                    [1, 3]
                );
                assert_eq!(
                    source.proof().ok_or("historical proof")?.as_ref(),
                    &receipt.selected
                );
            }
            1 => assert!(store
                .read_managed_reference(
                    &scope,
                    &reference,
                    read(),
                    AnalysisExtractLimits {
                        scan_bytes: 1,
                        ..Default::default()
                    },
                    &AnalysisReadControl::default(),
                    None,
                )
                .is_err()),
            _ => {
                let control = Arc::new(AnalysisReadControl::default());
                let cancelled = Arc::clone(&control);
                control.on_read_step(move || cancelled.cancel())?;
                assert!(matches!(
                    store.read_managed_reference(
                        &scope,
                        &reference,
                        read(),
                        AnalysisExtractLimits::default(),
                        &control,
                        None,
                    ),
                    Err(crate::Error::AnalysisReadCancelled { .. })
                ));
            }
        }
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        assert_eq!(
            store.context_head([1; 16], "source-cut", &[1], &[2])?,
            Some(context.clone())
        );
        let current = store.read_tables(
            &instance.grant.selection,
            AnalysisTableRead {
                requests: &fixture.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            current.tables["events"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            5
        );
        assert_eq!(
            current.tables["context_versions"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("source reader slots")?
                .available_permits(),
            1
        );
        assert_eq!(store.meta()?, meta);
    }
    Ok(())
}

#[test]
fn source_history_keeps_headers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open_with_limits(
        &root,
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
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
        [crate::AnalysisGapV1 {
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
    let removed = crate::EvidenceRetentionOwner::new(&store)
        .retain(&crate::analysis::tests::identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 100);
    assert!(store
        .raw
        .lock()
        .map_err(|_| "raw source lock")?
        .index
        .entries
        .is_empty());
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
    let identity = crate::analysis::tests::identity();
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE expired_ranges SET first_cursor = 99
             WHERE stream_key = ? AND first_cursor = 100 AND last_cursor = 100",
            params![identity.key()],
        )?,
        1
    );
    assert!(fixture
        .restore(
            &store,
            &repaired_receipt.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .is_err());
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE expired_ranges SET first_cursor = 100
             WHERE stream_key = ? AND first_cursor = 99 AND last_cursor = 100",
            params![identity.key()],
        )?,
        1
    );
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_headers(&reopened)?;
    Ok(())
}

#[test]
fn source_pending_blocks_retention() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open_with_limits(
        &root,
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
    )?;
    SourceFixture::append(&store, 100, 1)?;
    let mut fixture = SourceFixture::new(&store)?;
    fixture.requests = BTreeMap::from([("coverage".into(), Some(BTreeSet::new()))]);
    let removed = crate::EvidenceRetentionOwner::new(&store)
        .retain(&crate::analysis::tests::identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 0);
    let revision = store.meta()?.commit_revision;
    {
        let raw = store.raw.lock().map_err(|_| "pending raw lock")?;
        let key = crate::analysis::tests::identity().key();
        assert_eq!(raw.record_count(&key, 100, 100, revision), 1);
        assert!(raw.locate_retained(&key, 100, revision).is_some());
    }
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
        [crate::AnalysisGapV1 {
            first_cursor: 1,
            last_cursor: 99,
            commit_revision: frame.position().commit_revision,
        }]
    );
    assert!(!page.page.tables.contains_key("events"));
    let metadata = (source.receipt.clone(), source.pending.clone());
    store.verify_state()?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    reopened.verify_state()?;
    let page = fixture.read(
        &reopened,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let source = &page.page.extraction.sources[0];
    assert!(!page.page.tables.contains_key("events"));
    assert_eq!((source.receipt.clone(), source.pending.clone()), metadata);
    let revision = reopened.meta()?.commit_revision;
    let raw = reopened.raw.lock().map_err(|_| "reopened raw lock")?;
    assert_eq!(
        raw.record_count(
            &crate::analysis::tests::identity().key(),
            100,
            100,
            revision
        ),
        1
    );
    Ok(())
}

#[test]
fn source_changes_require_raw() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("store"),
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
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
    let removed = crate::EvidenceRetentionOwner::new(&store)
        .retain(&crate::analysis::tests::identity(), u64::MAX)?;
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
        Err(crate::Error::AnalysisReplayExpired { .. })
    ));
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn source_references_project_context() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("store"),
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
        Default::default(),
    )?;
    SourceFixture::append(&store, 1, 3)?;
    let mut context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "projection".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: b"first".to_vec(),
    };
    let first_context = store.commit_context(&context)?;
    let mut columns = SourceFixture::columns("context_versions")?;
    columns.insert(AnalysisStore::table_schemas()["context_versions"].index_of("body")?);
    let fixture = SourceFixture {
        fixture: Fixture::admit_scope(&store, false, AnalysisSelectionV1::tenant([1; 16]))?,
        execution: Arc::default(),
        requests: BTreeMap::from([
            ("events".into(), Some(SourceFixture::columns("events")?)),
            ("context_versions".into(), Some(columns.clone())),
        ]),
    };
    let owners = BTreeSet::from(["projection".into(), "unused".into()]);
    let control = AnalysisReadControl::default();
    let initial =
        fixture.read_owners(&store, ManagedSourceRead::Initial, &control, Some(&owners))?;
    let parent_receipt = fixture.publish(&store, &initial.state, "project-parent")?;
    let parent_ref = SourceFixture::reference(&initial.state, &parent_receipt)?;
    let current = fixture.fixture.current(&store)?;
    let (parent, call, _) =
        store.managed_reference(&current, &parent_receipt.selected.result_id, 10, &control)?;
    assert!(call.is_none());
    SourceFixture::append(&store, 4, 2)?;
    context.key.owner_revision = 2;
    context.body = b"second".to_vec();
    let second_context = store.commit_context(&context)?;
    let next = fixture.read_owners(
        &store,
        ManagedSourceRead::Changes(parent_ref.clone()),
        &control,
        Some(&owners),
    )?;
    let frame = next.state.source().ok_or("before source frame")?;
    frame.check_before(&parent)?;
    assert!(initial
        .state
        .source()
        .ok_or("initial source frame")?
        .check_before(&parent)
        .is_err());
    for fault in 0..9 {
        let mut saved = parent.clone();
        match fault {
            0 => saved
                .0
                .receipt
                .as_mut()
                .ok_or("parent receipt")?
                .selected
                .result_id
                .push_str("-foreign"),
            1 => saved.0.capture.revision += 1,
            2 => saved.0.capture.tenant[0] ^= 1,
            3 => saved.0.capture.instance.push_str("-foreign"),
            4 => saved.0.capture.generation += 1,
            5 => saved.0.capture.store = uuid::Uuid::nil(),
            6 => saved.0.capture.schema += 1,
            7 => saved.0.capture.recovery = 0,
            _ => saved.0.capture.recovery = u64::MAX,
        }
        assert!(frame.check_before(&saved).is_err(), "before fault {fault}");
    }
    let child_receipt = fixture.publish(&store, &next.state, "project-child")?;
    let current = fixture.fixture.current(&store)?;
    let (child, call, _) =
        store.managed_reference(&current, &child_receipt.selected.result_id, 10, &control)?;
    assert!(call.is_none());
    for receipt in [&parent_receipt, &child_receipt] {
        let (step, _) = AnalysisStore::managed_step_header(
            store.writer()?.get_mut()?,
            [1; 16],
            &receipt.selected.result_id,
        )?;
        assert!(step.witnesses.is_empty());
    }
    let original = (parent.0.clone(), child.0.clone());
    let removed = crate::EvidenceRetentionOwner::new(&store)
        .retain(&crate::analysis::tests::identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 5);
    let before = store.meta()?;
    let requests = BTreeMap::from([("context_versions".into(), Some(columns))]);
    let selection = current
        .spec
        .destination
        .selection(&current.grant.selection)?
        .project(&requests)?;
    let selected = BTreeSet::from(["projection".into()]);
    let old = store.read_managed_reference(
        &selection,
        &parent,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: parent.request().time_utc_ns,
        },
        AnalysisExtractLimits::default(),
        &control,
        Some(&selected),
    )?;
    let changed = store.read_managed_reference(
        &selection,
        &child,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Changes(parent_ref.position),
            now: child.request().time_utc_ns,
        },
        AnalysisExtractLimits::default(),
        &control,
        Some(&selected),
    )?;
    for (page, reference, version, revision, body) in [
        (&old, &parent, 1, first_context, b"first".as_slice()),
        (&changed, &child, 2, second_context, b"second".as_slice()),
    ] {
        assert_eq!(page.page.extraction.meta, reference.source_meta());
        assert!(page.page.extraction.sources.is_empty());
        assert!(!page.page.tables.contains_key("events"));
        let frame = page.state.source().ok_or("projected native source")?;
        assert_eq!(
            frame.position().commit_revision,
            reference.captured_revision()
        );
        assert_eq!(frame.position().ordinal, u32::MAX);
        assert_eq!(frame.selection(), &selection);
        assert_eq!(frame.projection(), &requests);
        assert_eq!(frame.datasets().len(), 1);
        let data = &frame.datasets()[0];
        assert_eq!(data.name, "context_versions");
        assert_eq!(data.rows(), 1);
        let batch = &data.batches[0];
        let owner = batch
            .column_by_name("owner_revision")
            .ok_or("context owner revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("context owner revision type")?;
        let committed = batch
            .column_by_name("commit_revision")
            .ok_or("context commit revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("context commit revision type")?;
        let value = batch
            .column_by_name("body")
            .ok_or("context body")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::BinaryArray>()
            .ok_or("context body type")?;
        assert_eq!(owner.value(0), version);
        assert_eq!(committed.value(0), revision);
        assert_eq!(value.value(0), body);
    }
    let old = old.state.source().ok_or("parent projected source")?;
    assert_eq!(old.read(), &ManagedSourceRead::Initial);
    assert_eq!(old.proof().map(Arc::as_ref), Some(&parent_receipt.selected));
    let changed = changed.state.source().ok_or("child projected source")?;
    assert_eq!(
        changed.read(),
        &ManagedSourceRead::Changes(parent_ref.clone())
    );
    assert!(changed.proof().is_none());
    let scope = current
        .spec
        .destination
        .selection(&current.grant.selection)?
        .project(&fixture.requests)?;
    let read = |mode, now| AnalysisTableRead {
        requests: &fixture.requests,
        event_ranges: None,
        mode,
        now,
    };
    assert!(matches!(
        store.read_managed_reference(
            &scope,
            &parent,
            read(AnalysisReadModeV1::Complete, parent.request().time_utc_ns),
            AnalysisExtractLimits::default(),
            &control,
            Some(&owners),
        ),
        Err(crate::Error::RetainedRangeExpired { .. })
    ));
    assert!(matches!(
        store.read_managed_reference(
            &scope,
            &child,
            read(
                AnalysisReadModeV1::Changes(parent_ref.position),
                child.request().time_utc_ns
            ),
            AnalysisExtractLimits::default(),
            &control,
            Some(&owners),
        ),
        Err(crate::Error::AnalysisReplayExpired { .. })
    ));
    assert_eq!((parent.0, child.0), original);
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.fixture.current(&store)?, current);
    Ok(())
}
