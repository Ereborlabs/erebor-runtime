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
fn call_reference_keeps_pin() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let first = fixture.selected_receipt(&store, "first")?;
    fixture.selected_receipt(&store, "second")?;
    let control = AnalysisReadControl::default();
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    for (call, reference) in &first.results {
        let result = store.managed_result(&current, &reference.result_id, 10, &control)?;
        let crate::InstanceResultKindV1::Call {
            image,
            package,
            export,
            context,
            call: id,
        } = &result.kind
        else {
            return Err("call reference kind".into());
        };
        assert_eq!(id, call);
        assert_eq!(result.instance_id, current.spec.id);
        assert_eq!(&result.result, reference);
        assert_eq!(result.receipt, first);
        assert_eq!(image, &current.spec.manifest.calls[call].image);
        assert_eq!(package, &current.spec.manifest.calls[call].package);
        assert_eq!(export, "count");
        assert_eq!(context.target, "sql");
        assert_eq!(context.artifact, None);
        assert_eq!(context.context.id, "first");
        assert_eq!(
            result.definition_revision,
            current.spec.manifest.definition.to_string()
        );
        assert_eq!(result.generation, current.generation);
        assert_eq!(result.source.store_uuid, before.store_uuid);
        assert!(result.source.commit_revision < result.result.commit_revision);
        assert!(!result.current);
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.managed_result(&current, &reference.result_id, 10, &cancelled),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_reference_keeps_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let receipt = fixture.selected_receipt(&store, "original")?;
    fixture.selected_receipt(&store, "later")?;
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    let result = store.managed_result(
        &current,
        &receipt.selected.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(result.result, receipt.selected);
    assert_eq!(result.receipt, receipt);
    assert!(matches!(
        &result.kind,
        crate::InstanceResultKindV1::Selected
    ));
    assert_eq!(Fixture::rows(&store, &receipt.selected)?, 1);
    assert!(!result.current);
    assert!(store
        .managed_result(&current, "missing", 10, &AnalysisReadControl::default())
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_scope_precedes_integrity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_scope(&store, false, AnalysisSelectionV1::tenant([1; 16]))?;
    let receipt = fixture.selected_receipt(&store, "scoped")?;
    let control = AnalysisReadControl::default();
    let mut current = fixture.current(&store)?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE analysis_results SET commit_revision = commit_revision + 1 WHERE result_id = ?",
            params![receipt.selected.result_id],
        )?;
    }
    let before = store.meta()?;
    current.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    assert!(matches!(
        store.managed_result(&current, &receipt.selected.result_id, 10, &control),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    current.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    assert!(store
        .managed_result(&current, &receipt.selected.result_id, 10, &control)
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_rejects_corruption() -> TestResult {
    for corruption in [
        "revision",
        "instance",
        "attempt",
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
            let mut guard = store.writer()?;
            let writer = guard.get_mut()?;
            match corruption {
                "revision" => {
                    assert_eq!(writer.execute("UPDATE analysis_results SET commit_revision = commit_revision + 1 WHERE result_id = ?", params![receipt.selected.result_id])?, 1);
                }
                "edges" => {
                    assert_eq!(
                        writer.execute(
                            "DELETE FROM managed_edges WHERE result_id = ?",
                            params![receipt.selected.result_id]
                        )?,
                        2
                    );
                }
                "instance" | "attempt" => {
                    let bytes: Vec<u8> = writer.query_row(
                        "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                        params![receipt.selected.result_id],
                        |row| row.get(0),
                    )?;
                    let mut step: model::Step = ManagedCodec::decode(&bytes)?;
                    if corruption == "instance" {
                        step.instance = "foreign".into();
                    } else {
                        step.attempt = "missing".into();
                    }
                    assert_eq!(
                        writer.execute(
                            "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                            params![ManagedCodec::encode(&step)?, receipt.selected.result_id]
                        )?,
                        1
                    );
                }
                _ => {
                    let bytes: Vec<u8> = writer.query_row("SELECT contract FROM managed_attempts WHERE instance_id = 'counter' AND attempt_id = 'corrupt'", [], |row| row.get(0))?;
                    let mut attempt: model::Attempt = ManagedCodec::decode(&bytes)?;
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
                        let reference = receipt.results.remove(&10).ok_or("call")?;
                        receipt.results.insert(99, reference);
                    }
                    assert_eq!(writer.execute("UPDATE managed_attempts SET contract = ? WHERE instance_id = 'counter' AND attempt_id = 'corrupt'", params![ManagedCodec::encode(&attempt)?])?, 1);
                }
            }
        }
        assert!(
            store
                .managed_result(&current, &receipt.selected.result_id, 10, &control)
                .is_err(),
            "{corruption}"
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
    for (reference, expected) in [
        (&original.selected, &fixture.model.outputs[0].schema),
        (&changed.selected, &schema),
    ] {
        let result = store.managed_result(
            &current,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        let version = store.managed_version(
            [1; 16],
            &current.spec.id,
            result.generation,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(&version.manifest.selected_schema, expected);
        assert_eq!(&result.result, reference);
        assert_eq!(
            result.definition_revision,
            version.manifest.definition.to_string()
        );
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
        store
            .managed_result(&current, &receipt.selected.result_id, 10, &control)?
            .kind,
        crate::InstanceResultKindV1::Selected
    ));
    {
        let mut writer = store.writer()?;
        let writer = writer.get_mut()?;
        let bytes: Vec<u8> = writer.query_row(
            "SELECT contract FROM managed_attempts WHERE instance_id = 'counter' AND attempt_id = 'swapped-calls'",
            [], |row| row.get(0),
        )?;
        let mut attempt: model::Attempt = ManagedCodec::decode(&bytes)?;
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
            params![ManagedCodec::encode(&attempt)?],
        )?;
    }
    let before = store.meta()?;
    assert!(matches!(
        store.managed_result(&current, &receipt.selected.result_id, 10, &control),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "managed selected call binding",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn successful_receipt_keeps_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let control = AnalysisReadControl::default();
    let selection = &fixture.instance.grant.selection;
    let name = &fixture.instance.spec.id;
    assert!(Fixture::receipt(&store, [1; 16], name, "first", &control)?.is_none());
    let mut receipts = Vec::new();
    for (id, value) in [("first", 2), ("later", 7)] {
        let capture = fixture.capture(&store, false)?;
        let input = request(id);
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let receipt = fixture.publish(
            &store,
            &attempt,
            &[
                fixture.evaluation(&input, 10, Some(&capture))?,
                fixture.evaluation(&input, 11, Some(&capture))?,
            ],
            &[fixture.output(value)?, fixture.output(value + 1)?],
        )?;
        let current = fixture.current(&store)?;
        let before = store.meta()?;
        let result = store.managed_result(&current, &receipt.selected.result_id, 10, &control)?;
        assert_eq!(result.result, receipt.selected);
        assert_eq!(result.receipt, receipt);
        assert_eq!(Fixture::rows(&store, &receipt.selected)?, 1);
        assert_eq!(
            fixture.checkpoint(&store, &receipt.results[&10])?.datasets[0].batches,
            fixture.output(value)?.checkpoint.ok_or("state")?.datasets[0].batches
        );
        assert!(matches!(
            store.managed_result(&current, "", 10, &control),
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
    let result = store.managed_result(
        &status.instance,
        &receipts[1].selected.result_id,
        10,
        &control,
    )?;
    assert_eq!(result.receipt, receipts[1]);
    assert_eq!(
        Fixture::receipt(&store, [1; 16], name, "later", &control)?,
        Some(receipts[1].clone())
    );
    assert!(Fixture::receipt(&store, [1; 16], name, "failed", &control)?.is_none());
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
        store.managed_result(
            &status.instance,
            &receipts[1].selected.result_id,
            10,
            &cancelled
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    {
        let mut guard = store.writer()?;
        let writer = guard.get_mut()?;
        let bytes: Vec<u8> = writer.query_row(
            "SELECT contract FROM managed_attempts WHERE instance_id = ? AND attempt_id = 'later'",
            params![name],
            |row| row.get(0),
        )?;
        let mut attempt: model::Attempt = ManagedCodec::decode(&bytes)?;
        assert_eq!(attempt.receipt.as_ref(), Some(&receipts[1]));
        attempt
            .receipt
            .as_mut()
            .ok_or("receipt")?
            .selected
            .result_id = receipts[0].selected.result_id.clone();
        assert_eq!(writer.execute("UPDATE managed_attempts SET contract = ? WHERE instance_id = ? AND attempt_id = 'later'", params![ManagedCodec::encode(&attempt)?, name])?, 1);
    }
    assert!(matches!(
        store.managed_result(
            &status.instance,
            &receipts[1].selected.result_id,
            10,
            &control
        ),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn selected_edges_reject_corruption() -> TestResult {
    for fault in ["missing", "revision", "replacement", "extra"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let first = fixture.selected_receipt(&store, "first")?;
        let second = fixture.selected_receipt(&store, "second")?;
        let current = fixture.current(&store)?;
        let control = AnalysisReadControl::default();
        let original = &first.results[&10];
        let replacement = &second.results[&10];
        assert_ne!(original.result_id, replacement.result_id);
        assert_ne!(original.commit_revision, replacement.commit_revision);
        let call = store.managed_result(&current, &original.result_id, 10, &control)?;
        assert!(!call.current);
        assert_eq!(&call.result, original);
        let selected = store.managed_result(&current, &first.selected.result_id, 10, &control)?;
        assert_eq!(selected.result, first.selected);
        assert_eq!(selected.receipt, first);
        let mut expected = first.results.values().cloned().collect::<Vec<_>>();
        expected.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        let before = store.meta()?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            assert_eq!(
                AnalysisStore::managed_edges(writer, [1; 16], &first.selected.result_id)?,
                expected
            );
            match fault {
                "missing" => {
                    assert_eq!(
                        writer.execute(
                            "DELETE FROM managed_edges WHERE result_id = ? AND dependency_id = ?",
                            params![first.selected.result_id, original.result_id],
                        )?,
                        1
                    );
                }
                "revision" => {
                    assert_eq!(writer.execute(
                        "UPDATE managed_edges SET commit_revision = ? WHERE result_id = ? AND dependency_id = ?",
                        params![replacement.commit_revision, first.selected.result_id, original.result_id],
                    )?, 1);
                }
                "replacement" => {
                    assert_eq!(writer.execute(
                        "UPDATE managed_edges SET dependency_id = ?, commit_revision = ? WHERE result_id = ? AND dependency_id = ?",
                        params![replacement.result_id, replacement.commit_revision, first.selected.result_id, original.result_id],
                    )?, 1);
                }
                _ => {
                    assert_eq!(
                        writer.execute(
                            "INSERT INTO managed_edges VALUES (?, ?, ?, ?)",
                            params![
                                [1u8; 16].as_slice(),
                                first.selected.result_id,
                                replacement.result_id,
                                replacement.commit_revision
                            ],
                        )?,
                        1
                    );
                }
            }
            let expected_count = if fault == "missing" {
                1
            } else if fault == "extra" {
                3
            } else {
                2
            };
            assert_eq!(
                AnalysisStore::managed_edges(writer, [1; 16], &first.selected.result_id)?.len(),
                expected_count
            );
            if matches!(fault, "replacement" | "extra") {
                let valid: bool = writer.query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_edges e JOIN analysis_results r ON e.tenant_id = r.tenant_id AND e.dependency_id = r.result_id AND e.commit_revision = r.commit_revision WHERE e.result_id = ? AND e.dependency_id = ?)",
                    params![first.selected.result_id, replacement.result_id],
                    |row| row.get(0),
                )?;
                assert!(valid);
            }
        }
        assert!(
            matches!(
                store.managed_result(&current, &first.selected.result_id, 10, &control),
                Err(crate::Error::Package {
                    code: crate::PackageErrorCodeV1::Invalid,
                    field: "managed selected edges",
                    ..
                })
            ),
            "{fault}"
        );
        let retained = store.managed_result(&current, &original.result_id, 10, &control)?;
        assert_eq!(
            serde_json::to_value(&retained)?,
            serde_json::to_value(&call)?
        );
        assert_eq!(store.meta()?, before);
        drop(store);
        let reopened = AnalysisStore::open(&root);
        if fault == "revision" {
            assert!(
                matches!(
                    reopened,
                    Err(crate::Error::AnalysisState {
                        reason,
                        ..
                    }) if reason == "the managed references are invalid"
                ),
                "{fault}"
            );
        } else {
            assert!(
                matches!(
                    reopened,
                    Err(crate::Error::Package {
                        code: crate::PackageErrorCodeV1::Invalid,
                        field: "managed selected edges",
                        ..
                    })
                ),
                "{fault}"
            );
        }
    }
    Ok(())
}
