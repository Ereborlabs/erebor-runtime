use super::*;

mod follow;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn current_reads_check_storage() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    let baseline = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    let references = |page: &crate::AnalysisPositionPageV1| {
        page.extraction
            .references
            .iter()
            .map(|entry| {
                (
                    entry.context().cloned(),
                    entry.result().cloned(),
                    entry.origins().to_vec(),
                )
            })
            .collect::<Vec<_>>()
    };
    let reference = &saved.receipt.results[&10];
    let (spec, state, head) = {
        let writer = saved.store.writer()?;
        let reader = writer.get()?;
        let spec: Vec<u8> = reader.query_row(
            "SELECT spec FROM managed_versions WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
            params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
            |row| row.get(0),
        )?;
        let (state, head): (u64, Option<String>) = reader.query_row(
            "SELECT state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
            params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        (spec, state, head)
    };
    assert_eq!(state, reference.commit_revision);
    assert_eq!(head.as_deref(), Some(reference.result_id.as_str()));
    let mut wrong: ManagedSpec = ManagedCodec::decode(&spec)?;
    wrong
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("saved call absent")?
        .package
        .revision = "wrong".into();
    let changed = ManagedCodec::encode(&wrong)?;
    for fault in ["revision", "state", "head", "result", "owner"] {
        {
            let mut writer = saved.store.writer()?;
            let writer = writer.get_mut()?;
            let key = params![
                selection.tenant_id.as_slice(),
                saved.fixture.instance.spec.id
            ];
            match fault {
                "revision" => {
                    writer.execute(
                        "UPDATE managed_versions SET spec = ? WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
                        params![changed, selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
                    )?;
                }
                "state" => {
                    writer.execute(
                        "UPDATE managed_calls SET state_revision = state_revision + 1 WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                "head" => {
                    writer.execute(
                        "DELETE FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                "result" => {
                    writer.execute(
                        "UPDATE managed_calls SET result_id = 'absent' WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                _ => {
                    writer.execute(
                        "UPDATE managed_calls SET instance_id = 'absent-instance' WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
            }
        }
        for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
            let result = saved.read(
                selection,
                selection,
                &saved.inputs,
                mode,
                AnalysisExtractLimits::default(),
                &control,
            );
            if fault == "revision" {
                assert!(
                    matches!(result, Err(crate::Error::AnalysisConflict { .. })),
                    "{fault}: {mode:?}"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(crate::Error::Package {
                            code: Code::Incomplete,
                            field: "managed input freshness",
                            ..
                        })
                    ),
                    "{fault}: {mode:?}"
                );
            }
        }
        {
            let mut writer = saved.store.writer()?;
            let writer = writer.get_mut()?;
            writer.execute(
                "UPDATE managed_versions SET spec = ? WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
                params![spec, selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
            )?;
            writer.execute(
                "DELETE FROM managed_calls WHERE tenant_id = ? AND call_id = 10 AND instance_id IN (?, 'absent-instance')",
                params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id],
            )?;
            writer.execute(
                "INSERT INTO managed_calls VALUES (?, ?, 10, ?, ?)",
                params![
                    selection.tenant_id.as_slice(),
                    saved.fixture.instance.spec.id,
                    state,
                    head
                ],
            )?;
        }
        for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
            let restored = saved.read(
                selection,
                selection,
                &saved.inputs,
                mode,
                AnalysisExtractLimits::default(),
                &control,
            )?;
            assert_eq!(references(&restored), references(&baseline));
            if matches!(mode, AnalysisReadModeV1::Complete) {
                assert_eq!(restored.packages, baseline.packages);
            } else {
                assert!(restored.packages.is_empty());
            }
        }
    }
    let mut forged = reference.clone();
    forged.commit_revision += 1;
    assert!(matches!(
        saved.store.managed_input(
            selection,
            &saved.fixture.instance.spec.id,
            &forged,
            "rows",
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Missing,
            field: "managed input result",
            ..
        })
    ));
    let current = saved.fixture.current(&saved.store)?;
    let running = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        current.lifecycle,
        true,
        || Ok(()),
    )?;
    let stopped = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        running.lifecycle,
        false,
        || Ok(()),
    )?;
    assert!(!stopped.running);
    assert_eq!(stopped.progress, saved.receipt.commit_revision);
    let paused = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(references(&paused), references(&baseline));
    assert_eq!(paused.packages, baseline.packages);
    let restarted = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    assert!(restarted.running);
    assert_eq!(restarted.progress, saved.receipt.commit_revision);
    let restored = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(references(&restored), references(&baseline));
    assert_eq!(restored.packages, baseline.packages);
    saved.permits()?;
    Ok(())
}

#[test]
fn retained_record_checks_identity() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    let reference = &saved.receipt.results[&10];
    let metadata: Vec<u8> = saved.store.writer()?.get()?.query_row(
        "SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
        params![selection.tenant_id.as_slice(), reference.result_id],
        |row| row.get(0),
    )?;
    let mut record: model::Record = ManagedCodec::decode(&metadata)?;
    record.instance = "absent-instance".into();
    saved.store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET request_meta = ? WHERE tenant_id = ? AND result_id = ?",
        params![
            ManagedCodec::encode(&record)?,
            selection.tenant_id.as_slice(),
            reference.result_id
        ],
    )?;
    assert!(matches!(
        saved.store.managed_input(
            selection,
            &saved.fixture.instance.spec.id,
            reference,
            "rows",
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Missing,
            field: "managed result attempt",
            ..
        })
    ));
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &saved.inputs,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "captured managed input identity",
            ..
        })
    ));
    saved.store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET request_meta = ? WHERE tenant_id = ? AND result_id = ?",
        params![
            metadata,
            selection.tenant_id.as_slice(),
            reference.result_id
        ],
    )?;
    let (pin, schema) = saved.store.managed_input(
        selection,
        &saved.fixture.instance.spec.id,
        reference,
        "rows",
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(pin.result(), reference);
    assert_eq!(&schema.schema, saved.inputs[0].1.as_ref());
    let restored = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(
        restored.packages[&0].1,
        saved.fixture.output(7)?.datasets[0].batches
    );
    saved.permits()?;
    Ok(())
}

#[derive(Debug, PartialEq)]
struct CommitState {
    meta: crate::AnalysisStoreMetaV1,
    instance: ManagedInstance,
    heads: Vec<(u64, u64, Option<String>)>,
    attempts: Vec<(String, u64, u64, Vec<u8>)>,
    results: Vec<(String, u64, Vec<u8>, Vec<u8>)>,
    arrows: Vec<(String, String, u64, Vec<u8>)>,
    references: (u64, u64, u64),
    history: Vec<ManagedReceipt>,
}

impl Saved {
    fn commit_state(&self) -> TestResult<CommitState> {
        self.fixture.commit_state(&self.store)
    }
}

impl Fixture {
    fn commit_state(&self, store: &AnalysisStore) -> TestResult<CommitState> {
        let (heads, attempts, results, arrows, references) = store.read_snapshot(|reader| {
            let mut statement = reader.prepare(
                "SELECT call_id, state_revision, result_id FROM managed_calls ORDER BY call_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved call heads" })?;
            let heads = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved call heads" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved call heads" })?;
            let mut statement = reader.prepare(
                "SELECT attempt_id, generation, completed, contract FROM managed_attempts ORDER BY attempt_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved attempts" })?;
            let attempts = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved attempts" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved attempts" })?;
            let mut statement = reader.prepare(
                "SELECT result_id, commit_revision, body, request_meta FROM analysis_results ORDER BY result_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved result rows" })?;
            let results = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved result rows" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved result rows" })?;
            let mut statement = reader.prepare(
                "SELECT result_id, role, slot, ipc FROM managed_arrow ORDER BY result_id, role, slot",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare saved IPC rows" })?;
            let arrows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .context(crate::AnalysisDatabaseSnafu { operation: "read saved IPC rows" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode saved IPC rows" })?;
            let references = reader.query_row(
                "SELECT (SELECT count(*) FROM managed_edges), (SELECT count(*) FROM evidence_refs), (SELECT count(*) FROM context_refs)",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).context(crate::AnalysisDatabaseSnafu { operation: "read saved reference counts" })?;
            Ok((heads, attempts, results, arrows, references))
        })?;
        Ok(CommitState {
            meta: store.meta()?,
            instance: self.current(store)?,
            heads,
            attempts,
            results,
            arrows,
            references,
            history: store.managed_history(
                &self.instance.grant.selection,
                &self.instance.spec.id,
                &AnalysisReadControl::default(),
            )?,
        })
    }
}

#[test]
fn source_change_keeps_commit() -> TestResult {
    let saved = Saved::new()?;
    let control = AnalysisReadControl::default();
    let selection = &saved.fixture.instance.grant.selection;
    let current = saved.fixture.current(&saved.store)?;
    let reference = &saved.receipt.results[&10];
    let original = saved
        .store
        .managed_result(&current, &reference.result_id, 10, &control)?;
    assert!(original.current);
    let selected = saved
        .store
        .managed_selected([1; 16], &current.spec.id, &saved.receipt.attempt, &control)?
        .ok_or("saved selected output absent")?;
    let captured = saved.capture()?;
    let input = request("source-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.evaluation(&input, 10, Some(&captured))?,
        saved.fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    Saved::append(&saved.store, 2)?;
    let before = saved.commit_state()?;
    let stale = request("stale-source-registration");
    assert!(matches!(
        saved
            .store
            .register_managed_attempt(&captured, &stale, || Ok(())),
        Err(crate::Error::AnalysisSourceChanged { .. })
    ));
    assert!(saved
        .store
        .managed_attempt([1; 16], &current.spec.id, &stale.id, &control)?
        .is_none());
    assert_eq!(saved.commit_state()?, before);
    let changed = saved
        .store
        .managed_result(&current, &reference.result_id, 10, &control)?;
    assert!(!changed.current);
    assert_eq!(changed.context, original.context);
    assert_eq!(
        sdk::wire::Output::encode_model(&changed.output, &saved.fixture.model)?,
        sdk::wire::Output::encode_model(&original.output, &saved.fixture.model)?
    );
    assert_eq!(changed.commit_revision, original.commit_revision);
    let retained = saved
        .store
        .managed_selected([1; 16], &current.spec.id, &saved.receipt.attempt, &control)?
        .ok_or("retained selected output absent")?;
    assert_eq!(retained.data.name, selected.data.name);
    assert_eq!(retained.data.batches, selected.data.batches);
    assert_eq!(retained.commit_revision, selected.commit_revision);
    assert_eq!(before.history, std::slice::from_ref(&saved.receipt));
    for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
        assert!(matches!(
            saved.read(
                selection,
                selection,
                &saved.inputs,
                mode,
                AnalysisExtractLimits::default(),
                &control
            ),
            Err(crate::Error::Package {
                code: Code::Incomplete,
                field: "managed input freshness",
                ..
            })
        ));
    }
    let failure = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("stale source publication succeeded")?;
    assert!(matches!(
        failure.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisSourceChanged { .. })
    ));
    assert_eq!(saved.commit_state()?, before);
    saved.permits()?;
    Ok(())
}

#[test]
fn trace_revocation_keeps_commit() -> TestResult {
    let saved = Saved::new()?;
    let mut intent = crate::analysis::raw::tests::trace_intent()?;
    intent.accepted_unix_ns = 1;
    let mut trace = saved.store.accept_trace(&intent)?;
    let captured = saved.capture()?;
    assert_eq!(captured.contract.traces, [intent.request_id]);
    let first = request("trace-first");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &first, || Ok(()))?;
    let evaluations = [
        saved.fixture.evaluation(&first, 10, Some(&captured))?,
        saved.fixture.evaluation(&first, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    let receipt = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)?;
    let captured = saved.capture()?;
    assert_eq!(captured.contract.traces, [intent.request_id]);
    let input = request("trace-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.evaluation(&input, 10, Some(&captured))?,
        saved.fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    trace.cancel_requested = true;
    trace.read_revoked = true;
    saved.store.update_trace(&trace)?;
    let before = saved.commit_state()?;
    assert_eq!(before.instance.progress, receipt.commit_revision);
    assert_eq!(before.history, [saved.receipt.clone(), receipt]);
    let mut checked = false;
    assert!(matches!(
        saved
            .store
            .register_managed_attempt(&captured, &request("trace-new"), || {
                checked = true;
                Ok(())
            }),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(!checked);
    assert_eq!(saved.commit_state()?, before);
    let failure = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("revoked trace publication succeeded")?;
    assert!(matches!(
        failure.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(saved.commit_state()?, before);
    assert!(saved.capture()?.contract.traces.is_empty());
    assert_eq!(saved.commit_state()?, before);
    saved.permits()?;
    Ok(())
}

#[test]
fn raw_fault_keeps_commit() -> TestResult {
    use std::os::unix::fs::FileExt as _;

    let saved = Saved::new()?;
    let captured = saved.capture()?;
    let input = request("raw-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.evaluation(&input, 10, Some(&captured))?,
        saved.fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    let next = request("raw-new");
    let before = saved.commit_state()?;
    let path = {
        let raw = saved.store.raw.lock().map_err(|_| "raw lock")?;
        assert_eq!(raw.segments.len(), 1);
        raw.segments
            .values()
            .next()
            .ok_or("raw segment absent")?
            .path
            .clone()
    };
    let segment = crate::SegmentFile::reader(&path)?;
    let length = usize::try_from(segment.length()?)?;
    let bytes = segment.read(0, length)?;
    let file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.set_len(0)?;
    let registration = saved
        .store
        .register_managed_attempt(&captured, &next, || Ok(()));
    let publication = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs);
    file.write_all_at(&bytes, 0)?;
    file.sync_all()?;
    assert_eq!(segment.read(0, length)?, bytes);
    assert!(matches!(
        registration,
        Err(crate::Error::AnalysisState { .. })
    ));
    let failure = publication.err().ok_or("missing raw data published")?;
    assert!(matches!(
        failure.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisState { .. })
    ));
    assert_eq!(saved.commit_state()?, before);
    let restored = saved
        .store
        .register_managed_attempt(&captured, &next, || Ok(()))?;
    assert!(restored.receipt().is_none());
    let receipt = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)?;
    assert_eq!(
        saved.fixture.current(&saved.store)?.progress,
        receipt.commit_revision
    );
    saved.permits()?;
    Ok(())
}

#[test]
fn empty_graph_keeps_capture() -> TestResult {
    use crate::analysis::graph_rows::tests::fixture::CommitFixture;

    for selected in [false, true] {
        let graph = CommitFixture::new()?;
        let store = graph.store.as_ref();
        let mut selection = AnalysisSelectionV1::new(
            graph.snapshot.scope.identity.tenant_id,
            vec![graph.snapshot.scope.identity.clone()],
        );
        selection.select_graphs(
            if selected {
                crate::Selection::All
            } else {
                crate::Selection::Exact(Vec::new())
            },
            None,
        )?;
        let fixture = Fixture::admit_scope(store, false, selection.clone())?;
        let requests = if selected {
            let schema = &AnalysisStore::table_schemas()["graph_manifest"];
            AnalysisTableRequests::from([(
                "graph_manifest".into(),
                Some((0..schema.fields().len()).collect()),
            )])
        } else {
            AnalysisTableRequests::new()
        };
        let control = AnalysisReadControl::default();
        let capture = || -> TestResult<_> {
            let instance = fixture.current(store)?;
            Ok(store.read_managed_tables(
                &selection,
                &ManagedRead {
                    execution: None,
                    follow: false,
                    instance,
                    expected: None,
                    rebuild: false,
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
                &control,
            )?)
        };
        let initial = capture()?;
        assert_eq!(initial.page.next_change, None);
        assert_eq!(
            initial
                .page
                .tables
                .get("graph_manifest")
                .into_iter()
                .flatten()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            0
        );
        let first = request("unchanged-empty");
        let first_attempt = store.register_managed_attempt(&initial.state, &first, || Ok(()))?;
        let seeded = fixture.publish(
            store,
            &first_attempt,
            &[
                fixture.evaluation(&first, 10, Some(&initial.state))?,
                fixture.evaluation(&first, 11, Some(&initial.state))?,
            ],
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        assert_eq!(fixture.current(store)?.progress, seeded.commit_revision);
        let empty = capture()?;
        assert_eq!(empty.page.next_change, None);
        assert_eq!(
            empty
                .page
                .tables
                .get("graph_manifest")
                .into_iter()
                .flatten()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            0
        );
        let pending = request("empty-pending");
        let attempt = store.register_managed_attempt(&empty.state, &pending, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&pending, 10, Some(&empty.state))?,
            fixture.evaluation(&pending, 11, Some(&empty.state))?,
        ];
        let outputs = [fixture.output(8)?, fixture.output(9)?];
        let committed = store.commit_graph(&graph.request, true, || Ok(()))?;
        if !selected {
            let receipt = fixture.publish(store, &attempt, &evaluations, &outputs)?;
            assert!(receipt.commit_revision > committed.commit_revision);
            assert_eq!(fixture.current(store)?.progress, receipt.commit_revision);
            continue;
        }
        let before = fixture.commit_state(store)?;
        assert_eq!(before.history, [seeded]);
        let mut checked = false;
        assert!(
            matches!(
                store.register_managed_attempt(&empty.state, &request("empty-stale"), || {
                    checked = true;
                    Ok(())
                }),
                Err(crate::Error::AnalysisSourceChanged { .. })
            ),
            "late Graph did not invalidate empty capture"
        );
        assert!(!checked);
        assert_eq!(fixture.commit_state(store)?, before);
        let failure = fixture
            .publish(store, &attempt, &evaluations, &outputs)
            .err()
            .ok_or("late Graph accepted stale empty publication")?;
        assert!(matches!(
            failure.downcast_ref::<crate::Error>(),
            Some(crate::Error::AnalysisSourceChanged { .. })
        ));
        assert_eq!(fixture.commit_state(store)?, before);
        let fresh = capture()?;
        assert_eq!(
            fresh.page.tables["graph_manifest"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        assert_eq!(
            fresh.page.next_change,
            Some(graph.snapshot.witness_deadline_utc_ns)
        );
        assert!(fresh.page.extraction.references.iter().any(|entry| entry
            .result()
            .is_some_and(|result| result.result_id == graph.request.result_id
                && result.commit_revision == committed.commit_revision)));
        assert_eq!(fixture.commit_state(store)?, before);
    }
    Ok(())
}
