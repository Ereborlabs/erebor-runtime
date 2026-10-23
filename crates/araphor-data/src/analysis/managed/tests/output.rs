use super::*;

impl Fixture {
    fn selected_receipt(&self, store: &AnalysisStore, id: &str) -> TestResult<ManagedReceipt> {
        let capture = self.capture(store, false)?;
        let request = request(id);
        let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
        self.publish(
            store,
            &attempt,
            &[
                self.evaluation(&request, 10, Some(&capture))?,
                self.evaluation(&request, 11, Some(&capture))?,
            ],
            &[self.output(2)?, self.output(3)?],
        )
    }
}

#[test]
fn raw_output_keeps_packet() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let mut receipts = Vec::new();
    for id in ["first", "second"] {
        let capture = fixture.capture(&store, false)?;
        let request = request(id);
        let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&request, 10, Some(&capture))?,
            fixture.evaluation(&request, 11, Some(&capture))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        receipts.push(fixture.publish(&store, &attempt, &evaluations, &outputs)?);
    }
    let control = AnalysisReadControl::default();
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    for (call, reference) in &receipts[0].results {
        let expected = {
            let mut reader = store.reader_until(&control)?;
            control.run(&mut reader, |reader| {
                AnalysisStore::managed_record_from(reader, [1; 16], &reference.result_id)
            })?
        };
        let ManagedOutput::Call { result, .. } =
            store.managed_output(&current, &reference.result_id, 10, &control)?
        else {
            return Err("package output variant".into());
        };
        assert_eq!(result.output, expected.1);
        assert_eq!(result.instance_id, current.spec.id);
        assert_eq!(result.result_id, reference.result_id);
        assert_eq!(result.commit_revision, reference.commit_revision);
        assert_eq!(result.commit_revision, expected.2);
        assert_eq!(result.context, expected.0.context);
        assert_eq!(result.image, current.spec.manifest.calls[call].image);
        assert_eq!(result.package, current.spec.manifest.calls[call].package);
        assert_eq!(result.export, "count");
        assert_eq!(result.context.target, "sql");
        assert_eq!(result.context.artifact, None);
        assert_eq!(result.context.context.id, "first");
        assert!(!result.current);
        assert_eq!(result.output.datasets.len(), 1);
        assert_eq!(result.output.evidence.len(), 1);
        assert_eq!(result.output.reasons.len(), 1);
        assert_eq!(result.output.checkpoint.as_ref().ok_or("state")?.version, 1);
        let decoded = result.output.decode_model(&fixture.model)?;
        assert_eq!(decoded.datasets[0].batches[0].num_rows(), 1);
        assert_eq!(
            decoded.checkpoint.as_ref().ok_or("decoded state")?.datasets[0].batches,
            decoded.datasets[0].batches
        );
        let encoded = crate::PackageResponseV1::Result(result.clone()).encode()?;
        assert!(!encoded
            .windows(b"definition-grant".len())
            .any(|bytes| bytes == b"definition-grant"));
        let crate::PackageResponseV1::Result(returned) =
            crate::PackageResponseV1::from_bytes(&encoded)?
        else {
            return Err("retained packet variant".into());
        };
        assert_eq!(returned.output, result.output);
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.managed_output(&current, &reference.result_id, 10, &cancelled),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_output_keeps_packet() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let receipt = fixture.selected_receipt(&store, "original")?;
    fixture.selected_receipt(&store, "later")?;
    let control = AnalysisReadControl::default();
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    let expected = {
        let mut reader = store.reader_until(&control)?;
        control.run(&mut reader, |reader| {
            AnalysisStore::managed_step_from(reader, [1; 16], &receipt.selected.result_id)
        })?
    };
    let ManagedOutput::Selected { packet, data } =
        store.managed_output(&current, &receipt.selected.result_id, 10, &control)?
    else {
        return Err("selected output variant".into());
    };
    assert_eq!(packet, expected.1);
    assert_eq!(data.rows(), expected.0.rows);
    assert_eq!(
        data.batches[0].schema_ref().as_ref(),
        &current.spec.manifest.selected_schema
    );
    let encoded = crate::PackageResponseV1::Output(packet.clone()).encode()?;
    let crate::PackageResponseV1::Output(returned) =
        crate::PackageResponseV1::from_bytes(&encoded)?
    else {
        return Err("selected wire variant".into());
    };
    assert_eq!(returned, packet);
    assert!(store
        .managed_output(&current, "missing", 10, &control)
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_scope_precedes_payload() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_scope(&store, false, AnalysisSelectionV1::tenant([1; 16]))?;
    let receipt = fixture.selected_receipt(&store, "scoped")?;
    let control = AnalysisReadControl::default();
    let mut current = fixture.current(&store)?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ?",
            params![receipt.selected.result_id],
        )?;
    }
    let before = store.meta()?;
    current.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    assert!(matches!(
        store.managed_output(&current, &receipt.selected.result_id, 10, &control),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    current.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    assert!(store
        .managed_output(&current, &receipt.selected.result_id, 10, &control)
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_rejects_corruption() -> TestResult {
    for corruption in [
        "ipc",
        "role",
        "schema",
        "rows",
        "receipt",
        "generation",
        "edges",
        "call",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let receipt = fixture.selected_receipt(&store, "corrupt")?;
        let control = AnalysisReadControl::default();
        let current = fixture.current(&store)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            match corruption {
                "ipc" => {
                    writer.execute(
                        "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ?",
                        params![receipt.selected.result_id],
                    )?;
                }
                "role" => {
                    writer.execute(
                        "UPDATE managed_arrow SET role = 'output' WHERE result_id = ?",
                        params![receipt.selected.result_id],
                    )?;
                }
                "edges" => {
                    writer.execute(
                        "DELETE FROM managed_edges WHERE result_id = ?",
                        params![receipt.selected.result_id],
                    )?;
                }
                "schema" => {
                    let schema = sdk::Schema::new(vec![sdk::Field::new(
                        "other",
                        sdk::DataType::UInt64,
                        false,
                    )]);
                    let data = sdk::Dataset {
                        name: "selected".into(),
                        batches: vec![Fixture::batch(&schema, 2)?],
                    };
                    let packet = AnalysisStore::encode_selected(&data, &schema)?;
                    writer.execute(
                        "UPDATE managed_arrow SET ipc = ? WHERE result_id = ?",
                        params![packet.arrow_ipc, receipt.selected.result_id],
                    )?;
                }
                "rows" => {
                    let bytes: Vec<u8> = writer.query_row(
                        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                        params![receipt.selected.result_id],
                        |row| row.get(0),
                    )?;
                    let mut step: model::Step = serde_json::from_slice(&bytes)?;
                    step.rows += 1;
                    writer.execute(
                        "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                        params![serde_json::to_vec(&step)?, receipt.selected.result_id],
                    )?;
                }
                _ => {
                    let bytes: Vec<u8> = writer.query_row("SELECT contract FROM managed_attempts WHERE instance_id = 'counter' AND attempt_id = 'corrupt'", [], |row| row.get(0))?;
                    let mut attempt: model::Attempt = serde_json::from_slice(&bytes)?;
                    if corruption == "receipt" {
                        attempt
                            .receipt
                            .as_mut()
                            .ok_or("receipt")?
                            .selected
                            .commit_revision += 1;
                    } else if corruption == "generation" {
                        attempt.capture.generation += 1;
                    } else {
                        let receipt = attempt.receipt.as_mut().ok_or("receipt")?;
                        let reference = receipt.results.remove(&10).ok_or("call result")?;
                        receipt.results.insert(99, reference);
                    }
                    writer.execute("UPDATE managed_attempts SET contract = ? WHERE instance_id = 'counter' AND attempt_id = 'corrupt'", params![serde_json::to_vec(&attempt)?])?;
                }
            }
        }
        assert!(
            store
                .managed_output(&current, &receipt.selected.result_id, 10, &control)
                .is_err(),
            "{corruption}"
        );
        assert!(
            store
                .managed_query_output(
                    &current.grant.selection,
                    &current.spec.id,
                    None,
                    10,
                    &control
                )
                .is_err(),
            "latest {corruption}"
        );
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{corruption}");
    }
    Ok(())
}

#[test]
fn selected_uses_saved_schema() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let original = fixture.selected_receipt(&store, "original-schema")?;
    let current = fixture.current(&store)?;
    let mut spec = super::version::target(&store, &current, "Change the selected schema.")?;
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "changed",
        sdk::DataType::UInt64,
        false,
    )]);
    spec.manifest.selected_schema = schema.clone();
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let capture = super::version::capture(&store, &current, &target, false)?;
    let request = request("changed-schema");
    let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![Fixture::batch(&schema, 5)?],
    };
    let commit = ManagedCommit {
        completed: true,
        attempt: &attempt,
        now_utc_ns: 10,
        returns: &[],
        selected: &selected,
        selected_schema: &current.spec.manifest.selected_schema,
    };
    assert!(matches!(
        store.commit_managed(&commit, || Ok(())),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "managed selected schema",
            ..
        })
    ));
    let changed = store.commit_managed(
        &ManagedCommit {
            selected_schema: &schema,
            ..commit
        },
        || Ok(()),
    )?;
    let current = fixture.current(&store)?;
    assert_eq!(current.generation, target.generation);
    for (reference, schema) in [
        (&original.selected, &fixture.model.outputs[0].schema),
        (&changed.selected, &schema),
    ] {
        let ManagedOutput::Selected { data, .. } = store.managed_output(
            &current,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?
        else {
            return Err("selected output variant".into());
        };
        assert_eq!(data.batches[0].schema_ref().as_ref(), schema);
    }
    Ok(())
}

#[test]
fn selected_rejects_call_swap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let receipt = fixture.selected_receipt(&store, "swapped-calls")?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.managed_output(&current, &receipt.selected.result_id, 10, &control)?,
        ManagedOutput::Selected { .. }
    ));
    {
        let mut writer = store.writer()?;
        let writer = writer.get_mut()?;
        let bytes: Vec<u8> = writer.query_row(
            "SELECT contract FROM managed_attempts WHERE instance_id = 'counter' AND attempt_id = 'swapped-calls'",
            [], |row| row.get(0),
        )?;
        let mut attempt: model::Attempt = serde_json::from_slice(&bytes)?;
        let saved = attempt.receipt.as_mut().ok_or("saved receipt")?;
        let first = saved.results.remove(&10).ok_or("first call")?;
        let second = saved.results.remove(&11).ok_or("second call")?;
        assert_ne!(first.result_id, second.result_id);
        saved.results.insert(10, second);
        saved.results.insert(11, first);
        assert_eq!(
            saved.results.keys().collect::<Vec<_>>(),
            receipt.results.keys().collect::<Vec<_>>()
        );
        let mut original = receipt.results.values().cloned().collect::<Vec<_>>();
        let mut swapped = saved.results.values().cloned().collect::<Vec<_>>();
        original.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        swapped.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        assert_eq!(swapped, original);
        let edges = AnalysisStore::managed_edges(writer, [1; 16], &receipt.selected.result_id)?;
        assert_eq!(edges, original);
        writer.execute(
            "UPDATE managed_attempts SET contract = ? WHERE instance_id = 'counter' AND attempt_id = 'swapped-calls'",
            params![serde_json::to_vec(&attempt)?],
        )?;
    }
    for corrupt in [false, true] {
        if corrupt {
            let mut writer = store.writer()?;
            writer.get_mut()?.execute(
                "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'selected'",
                params![receipt.selected.result_id],
            )?;
        }
        let before = store.meta()?;
        assert!(matches!(
            store.managed_output(&current, &receipt.selected.result_id, 10, &control),
            Err(crate::Error::Package {
                code: crate::PackageErrorCodeV1::Invalid,
                field: "managed selected call binding",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn latest_output_binds_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let control = AnalysisReadControl::default();
    let selection = &fixture.instance.grant.selection;
    let name = &fixture.instance.spec.id;
    let before = store.meta()?;
    assert!(matches!(
        store.managed_query_output(selection, name, None, 10, &control),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Missing,
            field: "managed current result",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let mut receipts = Vec::new();
    for (id, value) in [("first", 2), ("later", 7)] {
        let capture = fixture.capture(&store, false)?;
        let request = request(id);
        let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
        let receipt = fixture.publish(
            &store,
            &attempt,
            &[
                fixture.evaluation(&request, 10, Some(&capture))?,
                fixture.evaluation(&request, 11, Some(&capture))?,
            ],
            &[fixture.output(value)?, fixture.output(value + 1)?],
        )?;
        let before = store.meta()?;
        let ManagedOutput::Selected { data, .. } =
            store.managed_query_output(selection, name, None, 10, &control)?
        else {
            return Err("latest selected output variant".into());
        };
        assert_eq!(data.rows(), 1);
        assert_eq!(
            data.batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("latest value")?
                .value(0),
            value
        );
        assert!(matches!(
            store.managed_query_output(selection, name, Some(""), 10, &control),
            Err(crate::Error::Package {
                code: crate::PackageErrorCodeV1::Missing,
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        receipts.push(receipt);
    }
    let capture = fixture.capture(&store, false)?;
    let failed = store.register_managed_attempt(&capture, &request("failed"), || Ok(()))?;
    store.finish_managed(
        &failed,
        ManagedExit::Failed(crate::PackageErrorCodeV1::Incomplete),
        || Ok(()),
    )?;
    let status = store.managed_status(selection, name, &control)?;
    assert_eq!(status.status_progress, receipts[1].commit_revision);
    assert!(matches!(
        status.readiness,
        crate::PackageReadinessV1::Failed {
            code: crate::PackageErrorCodeV1::Incomplete,
            ..
        }
    ));
    let before = store.meta()?;
    let ManagedOutput::Selected { data, .. } =
        store.managed_query_output(selection, name, None, 10, &control)?
    else {
        return Err("failed latest selected output variant".into());
    };
    assert_eq!(
        data.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("retained latest value")?
            .value(0),
        7
    );
    let retained = store.managed_status(selection, name, &control)?;
    assert_eq!(retained.instance, status.instance);
    assert_eq!(retained.status_progress, status.status_progress);
    assert!(matches!(
        retained.readiness,
        crate::PackageReadinessV1::Failed {
            code: crate::PackageErrorCodeV1::Incomplete,
            ..
        }
    ));
    assert_eq!(store.meta()?, before);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.managed_query_output(selection, name, None, 10, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    {
        let mut writer = store.writer()?;
        let writer = writer.get_mut()?;
        let bytes: Vec<u8> = writer.query_row(
            "SELECT contract FROM managed_attempts WHERE instance_id = ? AND attempt_id = 'later'",
            params![name],
            |row| row.get(0),
        )?;
        let mut attempt: model::Attempt = serde_json::from_slice(&bytes)?;
        let receipt = attempt.receipt.as_mut().ok_or("current receipt")?;
        assert_eq!(*receipt, receipts[1]);
        receipt.selected.result_id = receipts[0].selected.result_id.clone();
        writer.execute(
            "UPDATE managed_attempts SET contract = ? WHERE instance_id = ? AND attempt_id = 'later'",
            params![serde_json::to_vec(&attempt)?, name],
        )?;
    }
    assert!(matches!(
        store.managed_query_output(selection, name, None, 10, &control),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "managed current receipt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}
