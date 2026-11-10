use super::*;

#[test]
fn reference_keeps_trace_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let intent = crate::analysis::trace::tests::intent(3)?;
    let state = store.accept_trace(&intent)?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.traces = crate::Selection::All;
    let fixture = Fixture::admit_scope(&store, false, selection.clone())?;
    let fields = ["request_revision", "cancel_requested", "last_sequence"];
    let requests = BTreeMap::from([(
        "traces".into(),
        Some(
            fields
                .iter()
                .map(|name| crate::AnalysisStore::table_schemas()["traces"].index_of(name))
                .collect::<std::result::Result<BTreeSet<_>, _>>()?,
        ),
    )]);
    let read = || AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        mode: AnalysisReadModeV1::Metadata,
        now: 10,
    };
    let control = AnalysisReadControl::default();
    let captured = store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            source: None,
            execution: None,
            follow: false,
            expected: None,
            instance: fixture.instance.clone(),
            rebuild: false,
            completed: None,
        },
        read(),
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let input = request("trace-cut");
    let attempt = store.register_managed_attempt(&captured.state, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured.state))?,
        fixture.evaluation(&input, 11, Some(&captured.state))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let (reference, _, _) = store.managed_reference(
        &fixture.current(&store)?,
        &receipt.selected.result_id,
        10,
        &control,
    )?;
    let identity = &intent.bindings[0].identity;
    store.append_trace(
        identity,
        &crate::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![crate::TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: crate::TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        },
        100,
    )?;
    let cancelled = store.update_trace(&crate::TraceStateV1 {
        cancel_requested: true,
        ..state.clone()
    })?;
    store.accept_trace(&crate::analysis::trace::tests::intent(4)?)?;
    let before = store.meta()?;
    for historical in [false, true, false] {
        let page = if historical {
            store
                .read_managed_reference(
                    &selection,
                    &reference,
                    read(),
                    AnalysisExtractLimits::default(),
                    &control,
                    None,
                )?
                .page
        } else {
            store.read_tables(
                &selection,
                read(),
                AnalysisExtractLimits::default(),
                &control,
            )?
        };
        let batches = &page.tables["traces"];
        assert_eq!(
            batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            if historical { 1 } else { 2 }
        );
        if historical {
            let batch = batches
                .iter()
                .find(|batch| batch.num_rows() != 0)
                .ok_or("trace row")?;
            assert_eq!(
                batch
                    .column_by_name("request_revision")
                    .ok_or("request revision")?
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .ok_or("request type")?
                    .value(0),
                state.revision
            );
            assert!(!batch
                .column_by_name("cancel_requested")
                .ok_or("cancellation")?
                .as_any()
                .downcast_ref::<sdk::arrow_array::BooleanArray>()
                .ok_or("cancel type")?
                .value(0));
            assert_eq!(
                batch
                    .column_by_name("last_sequence")
                    .ok_or("sequence")?
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .ok_or("sequence type")?
                    .value(0),
                0
            );
        }
    }
    assert_eq!(store.meta()?, before);
    store.update_trace(&crate::TraceStateV1 {
        read_revoked: true,
        ..cancelled
    })?;
    let before = store.meta()?;
    assert!(matches!(
        store.read_managed_reference(
            &selection,
            &reference,
            read(),
            AnalysisExtractLimits::default(),
            &control,
            None
        ),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    assert_eq!(store.meta()?, before);
    store.verify_state()?;
    Ok(())
}

#[test]
fn references_require_no_payloads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_inputs(&store, true)?;
    let captured = fixture.capture(&store, false)?;
    let request = request("reference");
    let attempt = store.register_managed_attempt(&captured, &request, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&request, 10, Some(&captured))?,
        fixture.evaluation(&request, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    let before = store.meta()?;
    for (id, expected) in receipt
        .results
        .iter()
        .map(|(call, reference)| (reference.result_id.as_str(), Some(*call)))
        .chain(std::iter::once((receipt.selected.result_id.as_str(), None)))
    {
        let (reference, call, _) = store.managed_reference(&current, id, 10, &control)?;
        assert_eq!(call, expected);
        assert_eq!(reference.request(), &request);
        assert_eq!(reference.receipt(), Some(&receipt));
        assert_eq!(reference.captured_revision(), captured.revision());
        assert_eq!(reference.instance().spec, current.spec);
        let mut foreign = current.clone();
        foreign.spec.id = "another-instance".into();
        assert!(store.managed_reference(&foreign, id, 10, &control).is_err());
    }
    assert_eq!(store.meta()?, before);
    control.cancel()?;
    assert!(store
        .managed_reference(&current, &receipt.selected.result_id, 10, &control)
        .is_err());
    Ok(())
}

#[test]
fn references_keep_input_metadata() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit_inputs(&store, true)?;
    let mut saved = Vec::new();
    for (index, id) in ["initial", "continued", "rebuild", "parameters"]
        .into_iter()
        .enumerate()
    {
        let captured = fixture.capture(&store, index == 2)?;
        let mut input = request(id);
        input.rebuild = index == 2;
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let mut evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        if index == 0 {
            evaluations[0].inputs.reverse();
            let source = evaluations[0]
                .inputs
                .iter_mut()
                .find(|input| input.data.name == "source")
                .ok_or("source input")?;
            let batch = source.data.batches[0].clone();
            source.data.batches = vec![
                sdk::RecordBatch::new_empty(batch.schema()),
                batch.clone(),
                sdk::RecordBatch::new_empty(batch.schema()),
            ];
            source.revision.window = Some(sdk::SourceWindow {
                source: vec![1, 2, 3],
                start_utc_ns: 1,
                end_utc_ns: 9,
            });
            source.coverage = sdk::Coverage {
                state: sdk::CoverageState::Gapped,
                limits: vec!["fixture gap".into()],
            };
            evaluations[1].inputs[1].data.batches = vec![sdk::RecordBatch::new_empty(Arc::new(
                fixture.model.inputs[1].port.schema.clone(),
            ))];
        }
        if index == 3 {
            evaluations[0].parameters = Some(Fixture::batch(&fixture.model.parameters, 9)?);
            evaluations[0].checkpoint = None;
        }
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let current = fixture.current(&store)?;
        for (call, expected) in [10, 11].into_iter().zip(evaluations) {
            let reference = receipt.results[&call].clone();
            let actual = store.managed_result(
                &current,
                &reference.result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert!(
                matches!(&actual.kind, crate::InstanceResultKindV1::Call { call: id, .. } if *id == call)
            );
            assert_eq!(actual.generation, current.generation);
            assert_eq!(actual.source.commit_revision, captured.revision());
            assert_eq!(call_context(&actual)?.context, expected.context);
            assert!(call_context(&actual)?.matches(&expected.inputs));
            saved.push(actual);
        }
    }
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let current = fixture.current(&store)?;
    for mut expected in saved {
        let actual = store.managed_result(
            &current,
            &expected.result.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        expected.current = expected.receipt.commit_revision == current.progress;
        assert_eq!(
            serde_json::to_value(&actual)?,
            serde_json::to_value(&expected)?
        );
        let mut foreign = current.clone();
        foreign.spec.id = "another-instance".into();
        assert!(store
            .managed_result(
                &foreign,
                &expected.result.result_id,
                10,
                &AnalysisReadControl::default()
            )
            .is_err());
        foreign.spec.tenant = [2; 16];
        assert!(store
            .managed_result(
                &foreign,
                &expected.result.result_id,
                10,
                &AnalysisReadControl::default()
            )
            .is_err());
    }
    assert_eq!(store.meta()?.commit_revision, before.commit_revision);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.managed_result(&current, "absent", 10, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn call_references_commit_atomically() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("atomic-input");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let returns = evaluations
        .iter()
        .zip(&outputs)
        .enumerate()
        .map(|(index, (evaluation, output))| ManagedReturn {
            graph: None,
            retained: None,
            changes: None,
            call: 10 + index as u64,
            evaluation,
            output,
        })
        .collect::<Vec<_>>();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    let before = store.meta()?;
    let mut checked = false;
    assert!(Fixture::publish(
        &store,
        &ManagedCommit {
            control: &crate::AnalysisReadControl::default(),
            budget: &crate::analysis::managed::tests::TestBudget,
            completed: true,
            attempt: &attempt,
            now_utc_ns: 10,
            returns: &returns,
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema
        },
        || {
            checked = true;
            Err(crate::PackageErrorCodeV1::Denied.error("saved input final authority"))
        }
    )
    .is_err());
    assert!(checked);
    assert_eq!(store.meta()?, before);
    let count: usize = store.read_snapshot(|reader| {
        reader
            .query_row(
                "SELECT count(*) FROM analysis_results WHERE processor_id LIKE 'managed-%'",
                [],
                |row| row.get(0),
            )
            .context(crate::AnalysisDatabaseSnafu {
                operation: "check reference rollback",
            })
    })?;
    assert_eq!(count, 0);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    for (call, expected) in [10, 11].into_iter().zip(evaluations) {
        let actual = store.managed_result(
            &current,
            &receipt.results[&call].result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(call_context(&actual)?.context, expected.context);
        assert_eq!(actual.result, receipt.results[&call]);
        assert_eq!(
            fixture.checkpoint(&store, &actual.result)?.datasets[0].batches,
            outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("declared checkpoint")?
                .datasets[0]
                .batches
        );
    }
    Ok(())
}

#[test]
fn prior_state_rejects_corruption() -> TestResult {
    for case in 0..3 {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = Fixture::admit(&store)?;
        let mut receipts = Vec::new();
        for name in ["initial", "continued"] {
            let capture = fixture.capture(&store, false)?;
            let input = request(name);
            let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
            let evaluations = [
                fixture.evaluation(&input, 10, Some(&capture))?,
                fixture.evaluation(&input, 11, Some(&capture))?,
            ];
            receipts.push(fixture.publish(
                &store,
                &attempt,
                &evaluations,
                &[fixture.output(2)?, fixture.output(3)?],
            )?);
        }
        let id = &receipts[1].results[&10].result_id;
        let current = fixture.current(&store)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            if case == 2 {
                let prior = &receipts[1].results[&10];
                let (_, mut state, _) =
                    AnalysisStore::managed_state_from(writer, [1; 16], &prior.result_id)?;
                state.as_mut().ok_or("prior checkpoint")?.version += 1;
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                        params![ManagedCodec::encode(&state)?, prior.result_id]
                    )?,
                    1
                );
            } else {
                let metadata: Vec<u8> = writer.query_row(
                    "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                    params![id],
                    |row| row.get(0),
                )?;
                let mut record: super::super::model::Record = ManagedCodec::decode(&metadata)?;
                if case == 0 {
                    record.context.context.time_utc_ns += 1;
                } else {
                    record.call = 11;
                }
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                        params![ManagedCodec::encode(&record)?, id],
                    )?,
                    1
                );
            }
        }
        let before = store.meta()?;
        if case == 2 {
            assert!(fixture.capture(&store, false).is_err(), "case {case}");
        } else {
            assert!(
                store
                    .managed_result(&current, id, 10, &AnalysisReadControl::default())
                    .is_err(),
                "case {case}"
            );
        }
        assert_eq!(store.meta()?, before);
    }
    Ok(())
}
