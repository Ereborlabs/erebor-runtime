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
        let instance = self.fixture.current(store)?;
        let mode = source
            .after()
            .map_or(AnalysisReadModeV1::Complete, AnalysisReadModeV1::Changes);
        Ok(store.read_managed_tables(
            &instance.grant.selection,
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
                inputs: None,
                mode,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            control,
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
    assert_eq!(frame.metadata().len(), 1);
    assert!(matches!(
        frame.metadata()[0].state,
        ManagedSourceState::Initial { .. }
    ));
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
        frame.proof().ok_or("committed source proof")?.result,
        receipt.selected
    );
    let reference = SourceFixture::reference(&first.state, &receipt)?;
    let current = fixture.fixture.current(&store)?;
    let blobs: (u64, u64) = store.writer()?.get_mut()?.query_row(
        "SELECT count(*), count(*) FILTER (WHERE result_id = ?)
         FROM managed_arrow WHERE role = 'source'",
        params![receipt.selected.result_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(blobs, (1, 1));
    let mut restored = Vec::new();
    store.managed_source_history::<crate::Error>(
        &current,
        &reference,
        &AnalysisReadControl::default(),
        |_| Ok(()),
        |frame| {
            restored.push(frame);
            Ok(())
        },
    )?;
    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored[0].datasets()[0].batches,
        frame.datasets()[0].batches
    );
    assert_eq!(restored[0].proof(), frame.proof());

    SourceFixture::append(&store, 4, 2)?;
    let next = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference.clone()),
        &AnalysisReadControl::default(),
    )?;
    let changed = next.state.source().ok_or("changed source frame")?;
    assert_eq!(changed.datasets()[0].rows(), 2);
    assert_eq!(changed.metadata().len(), 1);
    let ManagedSourceState::Changes { accepted } = &changed.metadata()[0].state else {
        return Err("source metadata reset its state".into());
    };
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].first_cursor, 4);
    assert_eq!(accepted[0].last_cursor, 5);
    assert_eq!(changed.metadata()[0].receipt.contiguous_cursor, 5);
    let receipt = fixture.publish(&store, &next.state, "source-next")?;
    let reference = SourceFixture::reference(&next.state, &receipt)?;
    let current = fixture.fixture.current(&store)?;
    let parents: u64 = store.writer()?.get_mut()?.query_row(
        "SELECT count(*) FROM managed_edges WHERE result_id = ? AND kind = 'source'",
        params![receipt.selected.result_id],
        |row| row.get(0),
    )?;
    assert_eq!(parents, 1);
    let idle = fixture.read(
        &store,
        ManagedSourceRead::Changes(reference.clone()),
        &AnalysisReadControl::default(),
    )?;
    let idle = idle.state.source().ok_or("idle source frame")?;
    assert_eq!(idle.datasets()[0].rows(), 0);
    assert!(idle.metadata().is_empty());
    fixture.execution.clear();
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let mut rows = Vec::new();
    reopened.managed_source_history::<crate::Error>(
        &current,
        &reference,
        &AnalysisReadControl::default(),
        |_| Ok(()),
        |frame| {
            rows.push(frame.datasets()[0].rows());
            assert!(frame.proof().is_some());
            Ok(())
        },
    )?;
    assert_eq!(rows, [3, 2]);
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
    assert!(block.select(&[3]).is_err());
    let selected = block.select(&[1, 1])?;
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
    assert!(changed.record_rows(&block.select(&[0])?).is_err());
    let receipt = fixture
        .fixture
        .publish(&store, &attempt, &evaluations, &outputs)?;
    let proof = changed.proof().ok_or("selected row proof")?;
    assert_eq!(
        proof
            .witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [2, 4, 5]
    );
    assert!(proof
        .witnesses
        .iter()
        .all(|witness| witness.expires_utc_ns == 200));
    let (step, _, revision) = AnalysisStore::managed_step_header(
        store.writer()?.get_mut()?,
        fixture.fixture.instance.spec.tenant,
        &receipt.selected.result_id,
    )?;
    assert_eq!(
        step.source
            .as_ref()
            .ok_or("selected source record")?
            .support
            .len(),
        1
    );
    let mut corrupt = step.clone();
    corrupt.source.as_mut().ok_or("source record")?.support[0].witnesses = vec![usize::MAX];
    assert!(
        AnalysisStore::check_source_evidence(store.writer()?.get_mut()?, &attempt.0, &corrupt)
            .is_err()
    );
    let mut corrupt = step.clone();
    corrupt
        .witnesses
        .push(frame.proof().ok_or("first proof")?.witnesses[0].clone());
    assert!(AnalysisStore::validate_selected_header(
        store.writer()?.get_mut()?,
        fixture.fixture.instance.spec.tenant,
        &receipt.selected.result_id,
        &corrupt,
        revision
    )
    .is_err());
    let current = fixture.fixture.current(&store)?;
    let reference = SourceFixture::reference(&next.state, &receipt)?;
    fixture.execution.clear();
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let mut actual = Vec::new();
    reopened.managed_source_history::<crate::Error>(
        &current,
        &reference,
        &AnalysisReadControl::default(),
        |_| Ok(()),
        |frame| {
            actual.push(
                frame
                    .proof()
                    .ok_or_else(|| {
                        crate::PackageErrorCodeV1::Invalid.error("restored source proof")
                    })?
                    .witnesses
                    .iter()
                    .map(|witness| witness.cursor)
                    .collect::<Vec<_>>(),
            );
            Ok(())
        },
    )?;
    assert_eq!(actual, [vec![1, 2, 3], vec![2, 4, 5]]);
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
    assert_eq!(frame.metadata()[0].receipt.contiguous_cursor, 5);
    let ManagedSourceState::Changes { accepted } = &frame.metadata()[0].state else {
        return Err("fixed source metadata reset its state".into());
    };
    assert!(accepted.iter().all(|span| span.last_cursor < 6));
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
        .read_managed_tables(
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
                inputs: None,
                mode: AnalysisReadModeV1::Changes(reference.position),
                now: 10
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .is_err());
    assert_eq!(
        fixture.fixture.current(&store)?.progress,
        receipt.commit_revision
    );
    store
        .writer()?
        .get_mut()?
        .execute_batch("UPDATE store_meta SET recovery_epoch = recovery_epoch + 1")?;
    assert!(fixture
        .read(
            &store,
            ManagedSourceRead::Changes(reference),
            &AnalysisReadControl::default()
        )
        .is_err());
    store
        .writer()?
        .get_mut()?
        .execute_batch("UPDATE store_meta SET recovery_epoch = recovery_epoch - 1")?;
    Ok(())
}

#[test]
fn source_frames_reject_payload() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    SourceFixture::append(&store, 1, 3)?;
    let fixture = SourceFixture::new(&store)?;
    let initial = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &initial.state, "source-corruption")?;
    let reference = SourceFixture::reference(&initial.state, &receipt)?;
    let current = fixture.fixture.current(&store)?;
    let bytes: Vec<u8> = store.writer()?.get_mut()?.query_row(
        "SELECT ipc FROM managed_arrow WHERE result_id = ? AND role = 'source' AND slot = 0",
        params![receipt.selected.result_id],
        |row| row.get(0),
    )?;
    let original: Vec<u8> = store.writer()?.get_mut()?.query_row(
        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
        params![receipt.selected.result_id],
        |row| row.get(0),
    )?;
    for case in 0..4 {
        match case {
            0 => {
                store.writer()?.get_mut()?.execute(
                    "UPDATE managed_arrow SET slot = 1 WHERE result_id = ? AND role = 'source'",
                    params![receipt.selected.result_id],
                )?;
            }
            1 => {
                store.writer()?.get_mut()?.execute(
                    "INSERT INTO managed_arrow VALUES (?, 'source', 1, ?)",
                    params![receipt.selected.result_id, bytes],
                )?;
            }
            2 => {
                store.writer()?.get_mut()?.execute(
                    "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'source'",
                    params![Vec::<u8>::new(), receipt.selected.result_id],
                )?;
            }
            _ => {
                let mut step: super::super::model::Step = ManagedCodec::decode(&original)?;
                let header = step.source.as_mut().ok_or("source header")?;
                header.tables[0].rows = 0;
                header.tables[0].batches = 0;
                let schema =
                    initial.state.source().ok_or("source frame")?.datasets()[0].batches[0].schema();
                let empty = sdk::RecordBatch::new_empty(Arc::clone(&schema));
                let packet = sdk::wire::Dataset::encode(
                    &sdk::Dataset {
                        name: "events".into(),
                        batches: vec![empty.clone(), empty],
                    },
                    &schema,
                )?;
                store.writer()?.get_mut()?.execute(
                    "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                    params![ManagedCodec::encode(&step)?, receipt.selected.result_id],
                )?;
                store.writer()?.get_mut()?.execute(
                    "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'source'",
                    params![packet.arrow_ipc, receipt.selected.result_id],
                )?;
            }
        }
        assert!(
            store
                .managed_source_history::<crate::Error>(
                    &current,
                    &reference,
                    &AnalysisReadControl::default(),
                    |_| Ok(()),
                    |_| Ok(()),
                )
                .is_err(),
            "source payload mutation {case}"
        );
        if case == 0 {
            store.writer()?.get_mut()?.execute(
                "UPDATE managed_arrow SET slot = 0 WHERE result_id = ? AND role = 'source'",
                params![receipt.selected.result_id],
            )?;
        }
        if case == 1 {
            store.writer()?.get_mut()?.execute(
                "DELETE FROM managed_arrow WHERE result_id = ? AND role = 'source' AND slot = 1",
                params![receipt.selected.result_id],
            )?;
        }
        store.writer()?.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'source' AND slot = 0",
            params![bytes, receipt.selected.result_id],
        )?;
        store.writer()?.get_mut()?.execute(
            "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
            params![original, receipt.selected.result_id],
        )?;
    }
    let meta = store.meta()?;
    let control = AnalysisReadControl::default();
    assert!(store
        .managed_source_history::<crate::Error>(
            &current,
            &reference,
            &control,
            |_| Ok(()),
            |_| {
                control.cancel()?;
                Ok(())
            }
        )
        .is_err());
    assert_eq!(store.meta()?, meta);
    let mut count = 0;
    store.managed_source_history::<crate::Error>(
        &current,
        &reference,
        &AnalysisReadControl::default(),
        |_| Ok(()),
        |frame| {
            count += frame.datasets()[0].rows();
            Ok(())
        },
    )?;
    assert_eq!(count, 3);
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
    let count: u64 = store.writer()?.get_mut()?.query_row(
        "SELECT count(*) FROM managed_arrow WHERE result_id = ? AND role = 'source'",
        params![receipt.selected.result_id],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
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
    let reference = SourceFixture::reference(&idle.state, &receipt)?;
    let count: u64 = store.writer()?.get_mut()?.query_row(
        "SELECT count(*) FROM managed_arrow WHERE result_id = ? AND role = 'source'",
        params![receipt.selected.result_id],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    let current = fixture.fixture.current(&store)?;
    let mut rows = Vec::new();
    store.managed_source_history::<crate::Error>(
        &current,
        &reference,
        &AnalysisReadControl::default(),
        |_| Ok(()),
        |frame| {
            rows.push(
                frame
                    .datasets()
                    .iter()
                    .map(sdk::Dataset::rows)
                    .collect::<Vec<_>>(),
            );
            Ok(())
        },
    )?;
    assert_eq!(rows, [vec![0, 3], vec![0, 0]]);
    let empty = sdk::wire::Dataset::encode(
        &sdk::Dataset {
            name: "events".into(),
            batches: Vec::new(),
        },
        frame.datasets()[1].batches[0].schema_ref(),
    )?;
    store.writer()?.get_mut()?.execute(
        "INSERT INTO managed_arrow VALUES (?, 'source', 0, ?)",
        params![receipt.selected.result_id, empty.arrow_ipc],
    )?;
    assert!(store
        .managed_source_history::<crate::Error>(
            &current,
            &reference,
            &AnalysisReadControl::default(),
            |_| Ok(()),
            |_| Ok(())
        )
        .is_err());
    Ok(())
}

#[test]
fn source_frames_accept_reversed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    SourceFixture::append(&store, 1, 3)?;
    let alpha = crate::analysis::tests::identity();
    let beta = crate::EvidenceIntakeIdentityV1 {
        source_epoch: alpha.source_epoch + 1,
        ..alpha.clone()
    };
    let bytes = Vec::<u8>::try_from(&EvidenceRecord {
        observed_boottime_ns: 1,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        beta.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![bytes.len()],
            framed_records: bytes.into(),
        },
    )?;
    let mut sources = vec![alpha, beta];
    sources.sort_by_key(crate::EvidenceIntakeIdentityV1::key);
    let expected = sources
        .iter()
        .map(crate::EvidenceIntakeIdentityV1::key)
        .collect::<Vec<_>>();
    sources.reverse();
    let selection = AnalysisSelectionV1::new([1; 16], sources);
    let fixture = Fixture::admit_scope(&store, false, selection.clone())?;
    let requests = BTreeMap::from([("events".into(), Some(SourceFixture::columns("events")?))]);
    let captured = store.read_managed_tables(
        &selection,
        &ManagedRead {
            source: Some(ManagedSourceRead::Initial),
            instance: fixture.current(&store)?,
            execution: None,
            expected: None,
            rebuild: false,
            follow: false,
            completed: None,
        },
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let frame = captured.state.source().ok_or("reversed source frame")?;
    assert_eq!(frame.datasets()[0].rows(), 4);
    assert_eq!(
        frame
            .metadata()
            .iter()
            .map(|source| source.receipt.identity.key())
            .collect::<Vec<_>>(),
        expected
    );
    Ok(())
}
