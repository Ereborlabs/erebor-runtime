use super::super::output::result_record;
use super::*;

#[test]
fn managed_recovery_checks_references() -> TestResult {
    for corruption in ["body", "checkpoint", "edge", "context"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = fixture(&store)?;
        let capture = fixture.capture(&store)?;
        let input = request("corrupt");
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let evaluations = [
            fixture.continued(&input, 10, None)?,
            fixture.continued(&input, 11, None)?,
        ];
        let receipt = fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        let id = &receipt.results[&10].result_id;
        let view = store.view()?;
        let (mut key, bytes) = result_record(&view, id)?;
        let mut tx = store.write()?;
        if corruption == "edge" {
            let (selected, _) = result_record(&view, &receipt.selected.result_id)?;
            let prefix = [b"\0data/ref/dependency/".as_slice(), &selected[7..]].concat();
            let edges = records(&view, &prefix)?;
            assert_eq!(edges.len(), 2);
            for key in edges.keys() {
                tx.native().remove(key.clone());
            }
        } else if corruption == "checkpoint" {
            key[6] = b'U';
            let bytes = view.snapshot().get(&key)?.ok_or("checkpoint")?;
            assert_eq!(bytes.first(), Some(&0));
            let mut state: Option<sdk::wire::Checkpoint> = rmp_serde::from_slice(&bytes[1..])?;
            state.as_mut().ok_or("checkpoint")?.version += 1;
            tx.native().insert(key, framed(&state)?);
        } else {
            let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
            if corruption == "body" {
                *mut_field(&mut record, &["body"])? = serde_value::to_value(0u8)?;
            } else {
                *mut_field(&mut record, &["body", "Call", "context", "target"])? =
                    serde_value::to_value("wasm32-wasip2")?;
            }
            tx.native().insert(key, framed(&record)?);
        }
        tx.commit([])?;
        let before = store.meta()?;
        if matches!(corruption, "body" | "checkpoint") {
            assert!(fixture.capture(&store).is_err(), "{corruption}");
        } else {
            let reference = if corruption == "edge" {
                &receipt.selected
            } else {
                &receipt.results[&10]
            };
            assert!(
                store
                    .managed_result(
                        &fixture.instance,
                        &reference.result_id,
                        10,
                        &AnalysisReadControl::default(),
                    )
                    .is_err(),
                "{corruption}"
            );
        }
        assert_eq!(store.meta()?, before);
        drop((view, store));
        assert!(AnalysisStore::open(&root).is_err(), "{corruption}");
    }
    Ok(())
}

#[test]
fn managed_commit_crashes() -> TestResult {
    if let Some(root) = std::env::var_os("ARAPHOR_MANAGED_ROOT") {
        let store = AnalysisStore::open(std::path::PathBuf::from(root))?;
        let fixture = fixture(&store)?;
        let upgrade = std::env::var("ARAPHOR_MANAGED_UPGRADE")? == "true";
        let mut capture = if upgrade {
            let current = fixture.current(&store)?;
            let spec = version::target(&store, &current, "Prepare the crash version.")?;
            let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
            version::capture(&store, &current, &target, false)?
        } else {
            fixture.capture(&store)?
        };
        let input = request("crash");
        for call in [10, 11] {
            if capture.prior(call).is_some() {
                let evaluation = fixture.evaluation(&input, call)?;
                capture.hydrate_prior(
                    call,
                    &fixture.model,
                    evaluation.parameters.map(|batch| sdk::Dataset {
                        name: "parameters".into(),
                        batches: vec![batch],
                    }),
                    None,
                )?;
            }
        }
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let eval = [
            fixture.continued(&input, 10, Some(&capture))?,
            fixture.continued(&input, 11, Some(&capture))?,
        ];
        if upgrade {
            for (evaluation, value) in eval.iter().zip([12, 103]) {
                assert_eq!(
                    evaluation
                        .checkpoint
                        .as_ref()
                        .ok_or("old checkpoint absent")?
                        .datasets[0]
                        .batches,
                    fixture
                        .output(value)?
                        .checkpoint
                        .ok_or("expected old checkpoint absent")?
                        .datasets[0]
                        .batches,
                );
            }
        }
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        fixture.publish(&store, &attempt, &eval, &outputs)?;
        return Err("the requested managed crash did not occur".into());
    }
    for upgrade in [false, true] {
        for point in ["managed.before", "managed.after"] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("store");
            let store = AnalysisStore::open(&root)?;
            let fixture = fixture(&store)?;
            let original = if upgrade {
                let capture = fixture.capture(&store)?;
                let input = request("original");
                let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
                let eval = [
                    fixture.continued(&input, 10, Some(&capture))?,
                    fixture.continued(&input, 11, Some(&capture))?,
                ];
                Some(fixture.publish(
                    &store,
                    &attempt,
                    &eval,
                    &[fixture.output(12)?, fixture.output(103)?],
                )?)
            } else {
                None
            };
            let prior = fixture.current(&store)?;
            let target = if upgrade {
                let spec = version::target(&store, &prior, "Prepare the crash version.")?;
                Some(store.prepare_managed_version(&prior, &spec, || Ok(()))?)
            } else {
                None
            };
            assert_eq!(fixture.current(&store)?, prior);
            let view = store.view()?;
            let prior_heads = call_heads(&view, "counter")?;
            let prior_rows = records(&view, b"\0data/X")?;
            let prior_states = records(&view, b"\0data/U")?;
            let prior_links = records(&view, b"\0data/ref/dependency/")?;
            drop(view);
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "storage::control::recovery::managed_commit_crashes",
                ])
                .env("ARAPHOR_MANAGED_ROOT", &root)
                .env("ARAPHOR_MANAGED_UPGRADE", upgrade.to_string())
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}, upgrade={upgrade}");
            let store = AnalysisStore::open(&root)?;
            let control = AnalysisReadControl::default();
            let pending = store
                .managed_attempt([1; 16], "counter", "crash", &control)?
                .ok_or("crash attempt absent")?;
            assert!(pending.terminal().is_none());
            if let Some(target) = &target {
                assert_eq!(pending.instance().generation, target.generation);
                assert_eq!(pending.instance().spec, target.spec);
                assert_eq!(
                    store.managed_version([1; 16], "counter", target.generation, &control)?,
                    target.spec
                );
            }
            let current = fixture.current(&store)?;
            let captured = fixture.capture(&store)?;
            let view = store.view()?;
            let retained_rows = records(&view, b"\0data/X")?;
            let retained_states = records(&view, b"\0data/U")?;
            let retained_links = records(&view, b"\0data/ref/dependency/")?;
            if point == "managed.after" {
                let receipt = pending.receipt().ok_or("committed receipt absent")?.clone();
                assert_eq!(pending.receipt(), Some(&receipt));
                assert_eq!(receipt.results.len(), 2);
                assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
                assert_eq!(current.progress, receipt.commit_revision);
                assert_eq!(captured.instance().progress, receipt.commit_revision);
                assert_eq!(
                    current.generation,
                    target
                        .as_ref()
                        .map_or(prior.generation, |target| target.generation)
                );
                assert_eq!(
                    &current.spec,
                    target.as_ref().map_or(&prior.spec, |target| &target.spec)
                );
                assert_eq!(
                    current.lifecycle,
                    if upgrade {
                        receipt.commit_revision
                    } else {
                        prior.lifecycle
                    }
                );
                let heads = call_heads(&view, "counter")?;
                assert_eq!(heads.len(), 2);
                for (key, bytes) in heads {
                    assert_eq!(key.len(), 23);
                    let call = u64::from_be_bytes(key[15..].try_into()?);
                    let head: super::super::CallHead = rmp_serde::from_slice(&bytes[1..])?;
                    assert_eq!(head.revision, receipt.commit_revision);
                    assert_eq!(
                        head.result.as_deref(),
                        Some(receipt.results[&call].result_id.as_str())
                    );
                }
                let mut expected_shapes = BTreeMap::new();
                for (call, value) in [(10, 2), (11, 3)] {
                    let reference = &receipt.results[&call];
                    assert_eq!(reference.commit_revision, receipt.commit_revision);
                    let saved = captured.prior(call).ok_or("new checkpoint absent")?;
                    assert_eq!(saved.result, reference.result_id);
                    assert_eq!(saved.revision, reference.commit_revision);
                    assert_eq!(
                        saved
                            .checkpoint
                            .as_ref()
                            .ok_or("new state absent")?
                            .datasets[0]
                            .batches,
                        fixture
                            .output(value)?
                            .checkpoint
                            .ok_or("expected new state absent")?
                            .datasets[0]
                            .batches,
                    );
                    let result =
                        store.managed_result(&current, &reference.result_id, 10, &control)?;
                    assert!(result.current);
                    assert_eq!(result.result, *reference);
                    assert_eq!(result.receipt, receipt);
                    let expected = fixture.continued(&request("crash"), call, None)?;
                    assert_eq!(call_context(&result)?.context, expected.context);
                    assert!(call_context(&result)?.matches(&expected.inputs));
                    assert_eq!(
                        result.prior.get(&call).and_then(Option::as_ref),
                        original.as_ref().map(|receipt| &receipt.results[&call])
                    );
                    expected_shapes
                        .insert(reference.result_id.clone(), (b'C', receipt.commit_revision));
                }
                expected_shapes.insert(
                    receipt.selected.result_id.clone(),
                    (b'S', receipt.commit_revision),
                );
                for (before, after) in [
                    (&prior_rows, &retained_rows),
                    (&prior_states, &retained_states),
                    (&prior_links, &retained_links),
                ] {
                    for (key, bytes) in before {
                        assert_eq!(after.get(key), Some(bytes));
                    }
                }
                let mut shapes = BTreeMap::new();
                for (key, bytes) in &retained_rows {
                    if prior_rows.contains_key(key) {
                        continue;
                    }
                    assert_eq!(key.len(), 15);
                    assert_eq!(bytes.first(), Some(&0));
                    let row: super::super::Stored = rmp_serde::from_slice(&bytes[1..])?;
                    let kind = match row.body {
                        super::super::Body::Call {
                            instance,
                            call,
                            attempt,
                        } => {
                            assert_eq!(instance, "counter");
                            assert!(matches!(call, 10 | 11));
                            assert_eq!(attempt, "crash");
                            b'C'
                        }
                        super::super::Body::Selected {
                            instance,
                            attempt,
                            rows,
                            dependencies,
                        } => {
                            assert_eq!(instance, "counter");
                            assert_eq!(attempt, "crash");
                            assert_eq!(rows, 1);
                            assert_eq!(
                                dependencies,
                                receipt.results.values().cloned().collect::<Vec<_>>()
                            );
                            b'S'
                        }
                    };
                    assert!(shapes.insert(row.id, (kind, row.revision)).is_none());
                }
                assert_eq!(shapes, expected_shapes);
                assert_eq!(retained_states.len(), prior_states.len() + 2);
                let (selected, _) = result_record(&view, &receipt.selected.result_id)?;
                let mut links = prior_links.clone();
                for reference in receipt.results.values() {
                    let (call, _) = result_record(&view, &reference.result_id)?;
                    let key = [
                        b"\0data/ref/dependency/".as_slice(),
                        &selected[7..],
                        &call[7..],
                    ]
                    .concat();
                    assert!(links
                        .insert(key, reference.commit_revision.to_be_bytes().to_vec())
                        .is_none());
                }
                assert_eq!(retained_links, links);
                assert_eq!(
                    Fixture::receipt(&store, [1; 16], "counter", "crash", &control)?,
                    Some(receipt.clone())
                );
                assert_eq!(Fixture::rows(&store, &receipt.selected)?, 1);
                let mut history = original.iter().cloned().collect::<Vec<_>>();
                history.push(receipt);
                assert_eq!(
                    store.managed_history(&current.grant.selection, "counter", &control)?,
                    history
                );
            } else {
                assert!(pending.receipt().is_none());
                assert_eq!(current, prior);
                assert_eq!(call_heads(&view, "counter")?, prior_heads);
                assert_eq!(retained_rows, prior_rows);
                assert_eq!(retained_states, prior_states);
                assert_eq!(retained_links, prior_links);
                assert!(Fixture::receipt(&store, [1; 16], "counter", "crash", &control)?.is_none());
                assert_eq!(
                    store.managed_history(&current.grant.selection, "counter", &control)?,
                    original.iter().cloned().collect::<Vec<_>>()
                );
                for (call, value) in [(10, 12), (11, 103)] {
                    if let Some(original) = &original {
                        let saved = captured.prior(call).ok_or("original checkpoint absent")?;
                        assert_eq!(saved.result, original.results[&call].result_id);
                        assert_eq!(saved.revision, original.results[&call].commit_revision);
                        assert_eq!(
                            saved
                                .checkpoint
                                .as_ref()
                                .ok_or("original state absent")?
                                .datasets[0]
                                .batches,
                            fixture
                                .output(value)?
                                .checkpoint
                                .ok_or("expected original state absent")?
                                .datasets[0]
                                .batches
                        );
                    } else {
                        assert!(captured.prior(call).is_none());
                    }
                }
            }
            if let Some(original) = &original {
                let retained = store
                    .managed_attempt([1; 16], "counter", "original", &control)?
                    .ok_or("original receipt absent")?;
                assert_eq!(retained.receipt(), Some(original));
                for (call, value) in [(10, 12), (11, 103)] {
                    let result = store.managed_result(
                        &current,
                        &original.results[&call].result_id,
                        10,
                        &control,
                    )?;
                    assert_eq!(result.result, original.results[&call]);
                    assert_eq!(result.receipt, *original);
                    assert_eq!(
                        fixture.checkpoint(&store, &result.result)?.datasets[0].batches,
                        fixture
                            .output(value)?
                            .checkpoint
                            .ok_or("original checkpoint")?
                            .datasets[0]
                            .batches
                    );
                    assert_eq!(result.current, point == "managed.before");
                }
                assert_eq!(
                    Fixture::receipt(&store, [1; 16], "counter", "original", &control)?,
                    Some(original.clone())
                );
                assert_eq!(Fixture::rows(&store, &original.selected)?, 1);
            }
            if point == "managed.before" && !upgrade {
                assert!(captured.prior(10).is_none());
                assert!(captured.prior(11).is_none());
                assert_eq!(captured.instance().progress, 0);
                let input = request("recovered");
                let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
                let eval = [
                    fixture.continued(&input, 10, None)?,
                    fixture.continued(&input, 11, None)?,
                ];
                let outputs = [fixture.output(2)?, fixture.output(3)?];
                fixture.publish(&store, &attempt, &eval, &outputs)?;
            }
        }
    }
    Ok(())
}
