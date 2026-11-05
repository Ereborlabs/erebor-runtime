use super::*;

#[test]
fn execution_retains_only_committed_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let declaration = &fixture.instance.spec.manifest.calls[&10];
    let bundle = store
        .retained_package_image([1; 16], &declaration.image, &AnalysisReadControl::default())?
        .ok_or("execution package image")?;
    let context = crate::AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &declaration.package,
        &declaration.export,
        "rows",
    )?;
    let reference = store.intern_context(&context)?;
    let mut captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    captured.contract.contexts.push(reference.clone());
    let input = request("retained-first");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    assert!(fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    let unchanged = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(unchanged.prior(10).is_none());
    assert_eq!(execution.metadata_bytes(), 0);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let mut warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(
        execution
            .packages(&warm.instance, &warm.contract)
            .metadata_bytes()
            > 0
    );
    let mut recovered = warm.contract.clone();
    recovered.recovery += 1;
    assert_eq!(
        execution
            .packages(&warm.instance, &recovered)
            .metadata_bytes(),
        0
    );
    warm.contract.contexts.push(reference.clone());
    let cold = fixture.capture(&store, false)?;
    for call in [10, 11] {
        let warm = warm.prior(call).ok_or("warm prior")?;
        let cold = cold.prior(call).ok_or("cold prior")?;
        assert_eq!(warm.result, receipt.results[&call].result_id);
        assert_eq!(warm.context, cold.context);
        assert!(cold.retained.is_none());
        let checkpoint = warm.checkpoint.as_ref().ok_or("warm checkpoint")?;
        let stored = cold.checkpoint.as_ref().ok_or("cold checkpoint")?;
        assert_eq!(
            sdk::wire::Checkpoint::encode(checkpoint, &fixture.model)?,
            sdk::wire::Checkpoint::encode(stored, &fixture.model)?
        );
        let warm = warm.retained.as_ref().ok_or("warm output")?;
        assert!(Arc::ptr_eq(
            outputs[(call - 10) as usize].datasets[0].batches[0].column(0),
            warm.output.datasets[0].batches[0].column(0)
        ));
        assert!(!Arc::ptr_eq(
            checkpoint.datasets[0].batches[0].column(0),
            stored.datasets[0].batches[0].column(0)
        ));
        assert!(warm.evaluation.checkpoint.is_none());
        assert!(warm.evaluation.previous_outputs.is_empty());
        assert_eq!(
            warm.output.datasets[0].batches,
            outputs[(call - 10) as usize].datasets[0].batches
        );
    }
    let idle = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let proofs = execution.packages(&idle.instance, &idle.contract);
    assert!(proofs.metadata_bytes() > 0);
    let attempt = store.register_managed_attempt(&idle, &request("retained-empty"), || Ok(()))?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![sdk::RecordBatch::new_empty(Arc::new(
            fixture.model.outputs[0].schema.clone(),
        ))],
    };
    let empty = Fixture::publish(&store,
        &ManagedCommit {
            control: &crate::AnalysisReadControl::default(),
            budget: &crate::analysis::managed::tests::TestBudget,
            completed: true,
            attempt: &attempt,
            now_utc_ns: 10,
            returns: &[],
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema,
        },
        || Ok(()),
    )?;
    assert!(empty.results.is_empty());
    warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(proofs.shares_roots(&execution.packages(&warm.instance, &warm.contract)));
    for removed in [false, true] {
        let mut changed = warm.instance.clone();
        if removed {
            changed.spec.manifest.calls.remove(&10);
        } else {
            changed
                .spec
                .manifest
                .calls
                .get_mut(&10)
                .ok_or("active call")?
                .image
                .image
                .revision
                .push_str("-changed");
        }
        assert_eq!(
            execution
                .packages(&changed, &warm.contract)
                .metadata_bytes(),
            0
        );
    }
    warm.contract.contexts.push(reference.clone());
    let next = request("retained-next");
    let attempt = store.register_managed_attempt(&warm, &next, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&next, 10, Some(&warm))?,
        fixture.evaluation(&next, 11, Some(&warm))?,
    ];
    assert!(evaluations
        .iter()
        .all(|evaluation| evaluation.checkpoint.is_some()));
    let changed = Fixture::batch(&fixture.model.parameters, 99)?;
    assert!(warm
        .prior(10)
        .ok_or("parameter prior")?
        .state(
            &fixture.model,
            &evaluations[0].inputs,
            Some(&changed),
            false
        )?
        .0
        .is_none());
    let outputs = [fixture.output(4)?, fixture.output(5)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let mut current = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(proofs.shares_roots(&execution.packages(&current.instance, &current.contract)));
    assert_eq!(
        current.prior(10).ok_or("current prior")?.result,
        receipt.results[&10].result_id
    );
    assert!(current
        .prior(10)
        .and_then(|prior| prior.retained.as_ref())
        .is_some_and(|retained| retained.evaluation.previous_outputs.is_empty()));
    current.contract.contexts.push(reference);
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact=? WHERE package_id='managed-fixture'",
        params![b"changed".as_slice()],
    )?;
    assert!(store
        .register_managed_attempt(&current, &request("retained-tampered"), || Ok(()))
        .is_err());
    execution.clear();
    assert_eq!(execution.metadata_bytes(), 0);
    Ok(())
}

#[test]
fn execution_checks_heads_and_recovery_epoch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let mut receipts = Vec::new();
    for value in [2, 4] {
        let captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
        let input = request(&format!("retained-{value}"));
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        receipts.push(fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(value)?, fixture.output(value + 1)?],
        )?);
    }
    let warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let last = warm.prior(10).ok_or("last prior")?;
    let first = &receipts[0].results[&10];
    store.writer()?.get_mut()?.execute(
        "UPDATE managed_calls SET state_revision=?,result_id=? WHERE tenant_id=? AND instance_id=? AND call_id=10",
        params![first.commit_revision, first.result_id, fixture.instance.spec.tenant.as_slice(), fixture.instance.spec.id],
    )?;
    let changed = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let previous = changed.prior(10).ok_or("changed prior")?;
    assert_eq!(previous.result, first.result_id);
    assert_ne!(previous.result, last.result);
    assert!(previous.retained.is_none());
    assert!(previous.checkpoint.is_some());
    let before = changed.prior(11).ok_or("retained prior")?;
    assert!(before.retained.is_some());
    let latest = &receipts[1].results[&10];
    store.writer()?.get_mut()?.execute(
        "UPDATE managed_calls SET state_revision=?,result_id=? WHERE tenant_id=? AND instance_id=? AND call_id=10",
        params![latest.commit_revision, latest.result_id, fixture.instance.spec.tenant.as_slice(), fixture.instance.spec.id],
    )?;
    drop(store);
    let reopened = AnalysisStore::open(directory.path().join("store"))?;
    let mut meta = reopened.meta()?;
    meta.recovery_epoch += 1;
    assert!(execution
        .calls(
            &ManagedRead {
                source: None,
                execution: Some(Arc::clone(&execution)),
                instance: fixture.current(&reopened)?,
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
            &meta
        )
        .is_empty());
    let recovered = fixture.capture_execution(
        &reopened,
        false,
        Some(Arc::new(ManagedExecution::default())),
    )?;
    let after = recovered.prior(11).ok_or("recovered prior")?;
    assert!(after.retained.is_none());
    let before = before.checkpoint.as_ref().ok_or("prior checkpoint")?;
    let after = after.checkpoint.as_ref().ok_or("recovered checkpoint")?;
    assert_eq!(
        sdk::wire::Checkpoint::encode(before, &fixture.model)?,
        sdk::wire::Checkpoint::encode(after, &fixture.model)?
    );
    assert!(!Arc::ptr_eq(
        before.datasets[0].batches[0].column(0),
        after.datasets[0].batches[0].column(0)
    ));
    Ok(())
}

#[test]
fn execution_checks_package_restore() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let input = request("retained-package");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let artifact = store.read_snapshot(|reader| {
        reader
            .query_row(
                "SELECT artifact FROM package_revisions WHERE package_id='managed-fixture'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read retained test artifact",
            })
    })?;
    let changed = b"invalid".to_vec();
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact=? WHERE package_id='managed-fixture'",
        params![changed],
    )?;
    let warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(Arc::ptr_eq(
        outputs[0].datasets[0].batches[0].column(0),
        warm.prior(10)
            .and_then(|prior| prior.retained.as_ref())
            .ok_or("retained output")?
            .output
            .datasets[0]
            .batches[0]
            .column(0)
    ));
    let pin = fixture
        .instance
        .spec
        .definition
        .images
        .first()
        .ok_or("managed image pin")?;
    let control = AnalysisReadControl::default();
    assert!(store
        .retained_package_image([1; 16], pin, &control)
        .is_err());
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact=? WHERE package_id='managed-fixture'",
        params![artifact],
    )?;
    assert_eq!(
        store
            .retained_package_image([1; 16], pin, &control)?
            .ok_or("restored package image")?
            .digest(),
        pin.digest
    );
    store.writer()?.get_mut()?.execute(
        "DELETE FROM package_revisions WHERE package_id='managed-fixture'",
        [],
    )?;
    assert!(fixture.capture(&store, false).is_err());
    Ok(())
}
