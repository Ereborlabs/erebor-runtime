use super::*;

fn same_evaluation(actual: &sdk::Evaluation, expected: &sdk::Evaluation) {
    assert_eq!(actual.export, expected.export);
    assert_eq!(actual.context, expected.context);
    assert_eq!(actual.parameters, expected.parameters);
    assert_eq!(actual.inputs.len(), expected.inputs.len());
    for (actual, expected) in actual.inputs.iter().zip(&expected.inputs) {
        assert_eq!(actual.data.name, expected.data.name);
        assert_eq!(actual.data.batches, expected.data.batches);
        assert_eq!(actual.revision, expected.revision);
        assert_eq!(actual.coverage, expected.coverage);
    }
    assert_eq!(actual.checkpoint.is_some(), expected.checkpoint.is_some());
    if let (Some(actual), Some(expected)) = (&actual.checkpoint, &expected.checkpoint) {
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.datasets.len(), expected.datasets.len());
        for (actual, expected) in actual.datasets.iter().zip(&expected.datasets) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.batches, expected.batches);
        }
    }
}

#[test]
fn saved_evaluation_keeps_inputs() -> TestResult {
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
            let (saved_call, saved_generation, bound) = store.managed_evaluation_bytes(
                &current,
                &reference.result_id,
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(saved_call, call);
            assert_eq!(saved_generation, current.generation);
            let actual = store.managed_evaluation(
                &current,
                &reference.result_id,
                &AnalysisReadControl::default(),
            )?;
            same_evaluation(&actual, &expected);
            assert!(actual.allocated_bytes() <= bound);
            saved.push((reference, expected));
        }
    }
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let current = fixture.current(&store)?;
    for (reference, expected) in saved {
        let actual = store.managed_evaluation(
            &current,
            &reference.result_id,
            &AnalysisReadControl::default(),
        )?;
        same_evaluation(&actual, &expected);
        let mut foreign = current.clone();
        foreign.spec.id = "another-instance".into();
        assert!(store
            .managed_evaluation(
                &foreign,
                &reference.result_id,
                &AnalysisReadControl::default()
            )
            .is_err());
        foreign.spec.tenant = [2; 16];
        assert!(store
            .managed_evaluation_bytes(
                &foreign,
                &reference.result_id,
                &AnalysisReadControl::default()
            )
            .is_err());
    }
    assert_eq!(store.meta()?.commit_revision, before.commit_revision);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .managed_evaluation_bytes(&current, "absent", &cancelled)
        .is_err());
    assert!(store
        .managed_evaluation(&current, "absent", &cancelled)
        .is_err());
    Ok(())
}

#[test]
fn saved_evaluation_rejects_corruption() -> TestResult {
    for case in 0..7 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit_inputs(&store, case == 6)?;
        let captured = fixture.capture(&store, false)?;
        let input = request("saved-input");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        let receipt = fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        let id = &receipt.results[&10].result_id;
        let current = fixture.current(&store)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            match case {
                0 => {
                    writer.execute(
                        "DELETE FROM managed_arrow WHERE result_id = ? AND role = 'input'",
                        params![id],
                    )?;
                }
                1 => {
                    writer.execute(
                        "UPDATE managed_arrow SET slot = 9 WHERE result_id = ? AND role = 'input'",
                        params![id],
                    )?;
                }
                2 => {
                    let schema = sdk::Schema::new(vec![sdk::Field::new(
                        "value",
                        sdk::DataType::Utf8,
                        false,
                    )]);
                    let data = sdk::Dataset {
                        name: "source".into(),
                        batches: vec![sdk::RecordBatch::try_new(
                            Arc::new(schema.clone()),
                            vec![Arc::new(sdk::arrow_array::StringArray::from(vec!["wrong"]))],
                        )?],
                    };
                    let encoded = sdk::wire::Dataset::encode(&data, &schema)?;
                    writer.execute(
                        "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'input'",
                        params![encoded.arrow_ipc, id],
                    )?;
                }
                6 => {
                    let schema = &fixture.model.inputs[1].port.schema;
                    let packet = sdk::wire::Dataset::encode(
                        &sdk::Dataset {
                            name: "aux".into(),
                            batches: vec![sdk::RecordBatch::new_empty(Arc::new(schema.clone()))],
                        },
                        schema,
                    )?;
                    writer.execute(
                        "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'input' AND slot = 1",
                        params![packet.arrow_ipc, id],
                    )?;
                }
                _ => {
                    let metadata: Vec<u8> = writer.query_row(
                        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                        params![id],
                        |row| row.get(0),
                    )?;
                    let mut record: super::super::model::Record =
                        serde_json::from_slice(&metadata)?;
                    match case {
                        3 => record.inputs[0].rows += 1,
                        4 => record.inputs[0].batches = 0,
                        _ => record.inputs[0].name = "absent".into(),
                    }
                    writer.execute(
                        "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                        params![serde_json::to_vec(&record)?, id],
                    )?;
                }
            }
        }
        let error = store
            .managed_evaluation(&current, id, &AnalysisReadControl::default())
            .err()
            .ok_or_else(|| format!("corrupt saved evaluation accepted: {case}"))?;
        if case == 6 {
            assert!(
                matches!(
                    error,
                    crate::Error::Package {
                        code: crate::PackageErrorCodeV1::Invalid,
                        field: "saved evaluation input shape",
                        ..
                    }
                ),
                "{error:?}"
            );
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "case {case}");
    }
    Ok(())
}

#[test]
fn saved_inputs_commit_atomically() -> TestResult {
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
            retained: None,
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
    assert!(store
        .commit_managed(
            &ManagedCommit {
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
                "SELECT count(*) FROM managed_arrow WHERE role = 'input'",
                [],
                |row| row.get(0),
            )
            .context(crate::AnalysisDatabaseSnafu {
                operation: "check saved input rollback",
            })
    })?;
    assert_eq!(count, 0);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    for (call, expected) in [10, 11].into_iter().zip(evaluations) {
        let actual = store.managed_evaluation(
            &current,
            &receipt.results[&call].result_id,
            &AnalysisReadControl::default(),
        )?;
        same_evaluation(&actual, &expected);
    }
    Ok(())
}

#[test]
fn saved_history_rejects_corruption() -> TestResult {
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
                writer.execute("UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'checkpoint'", params![receipts[0].results[&10].result_id])?;
            } else {
                let metadata: Vec<u8> = writer.query_row(
                    "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                    params![id],
                    |row| row.get(0),
                )?;
                let mut record: super::super::model::Record = serde_json::from_slice(&metadata)?;
                if case == 0 {
                    record.context.context.time_utc_ns += 1;
                } else {
                    record.declaration.image.digest =
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into();
                }
                writer.execute(
                    "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                    params![serde_json::to_vec(&record)?, id],
                )?;
            }
        }
        let before = store.meta()?;
        assert!(
            store
                .managed_evaluation_bytes(&current, id, &AnalysisReadControl::default())
                .is_err(),
            "case {case}"
        );
        assert!(
            store
                .managed_evaluation(&current, id, &AnalysisReadControl::default())
                .is_err(),
            "case {case}"
        );
        assert_eq!(store.meta()?, before);
    }
    Ok(())
}
