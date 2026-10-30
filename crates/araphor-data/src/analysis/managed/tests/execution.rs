use super::*;

#[test]
fn execution_retains_only_committed_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
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
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let cold = fixture.capture(&store, false)?;
    for call in [10, 11] {
        let warm = warm.prior(call).ok_or("warm prior")?;
        let cold = cold.prior(call).ok_or("cold prior")?;
        assert_eq!(warm.result, receipt.results[&call].result_id);
        assert_eq!(warm.context, cold.context);
        let warm = warm.retained.as_ref().ok_or("warm output")?;
        let cold = cold.retained.as_ref().ok_or("cold output")?;
        assert!(Arc::ptr_eq(
            outputs[(call - 10) as usize].datasets[0].batches[0].column(0),
            warm.output.datasets[0].batches[0].column(0)
        ));
        assert!(!Arc::ptr_eq(
            warm.output.datasets[0].batches[0].column(0),
            cold.output.datasets[0].batches[0].column(0)
        ));
        assert!(warm.matches(&cold.evaluation));
        assert!(warm.evaluation.checkpoint.is_none());
        assert!(warm.evaluation.previous_outputs.is_empty());
        assert_eq!(
            warm.output.datasets[0].batches,
            cold.output.datasets[0].batches
        );
    }
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
    let current = fixture.capture_execution(&store, false, Some(execution))?;
    assert_eq!(
        current.prior(10).ok_or("current prior")?.result,
        receipt.results[&10].result_id
    );
    assert!(current
        .prior(10)
        .and_then(|prior| prior.retained.as_ref())
        .is_some_and(|retained| retained.evaluation.previous_outputs.is_empty()));
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
    let last = warm
        .prior(10)
        .ok_or("last prior")?
        .retained
        .as_ref()
        .ok_or("last output")?;
    let first = &receipts[0].results[&10];
    store.writer()?.get_mut()?.execute(
        "UPDATE managed_calls SET state_revision=?,result_id=? WHERE tenant_id=? AND instance_id=? AND call_id=10",
        params![first.commit_revision, first.result_id, fixture.instance.spec.tenant.as_slice(), fixture.instance.spec.id],
    )?;
    let changed = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let previous = changed.prior(10).ok_or("changed prior")?;
    assert_eq!(previous.result, first.result_id);
    assert!(!Arc::ptr_eq(
        previous.retained.as_ref().ok_or("changed output")?,
        last
    ));
    let before = changed
        .prior(11)
        .ok_or("retained prior")?
        .retained
        .as_ref()
        .ok_or("retained output")?;
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
    let after = recovered
        .prior(11)
        .ok_or("recovered prior")?
        .retained
        .as_ref()
        .ok_or("recovered output")?;
    assert!(!Arc::ptr_eq(before, after));
    assert!(before.matches(&after.evaluation));
    Ok(())
}

#[test]
fn execution_checks_current_package_bytes() -> TestResult {
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
    let mut changed = artifact.clone();
    changed.push(0);
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact=? WHERE package_id='managed-fixture'",
        params![changed],
    )?;
    assert!(fixture
        .capture_execution(&store, false, Some(Arc::clone(&execution)))
        .is_err());
    store.writer()?.get_mut()?.execute(
        "UPDATE package_revisions SET artifact=? WHERE package_id='managed-fixture'",
        params![artifact],
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
    store.writer()?.get_mut()?.execute(
        "DELETE FROM package_revisions WHERE package_id='managed-fixture'",
        [],
    )?;
    assert!(fixture
        .capture_execution(&store, false, Some(execution))
        .is_err());
    Ok(())
}
