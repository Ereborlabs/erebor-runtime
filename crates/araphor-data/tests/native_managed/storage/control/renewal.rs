use super::*;
use araphor_data::PackageErrorCodeV1 as Code;

#[tokio::test]
async fn renewal_cas_is_inert() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store)?;
    let expected = &fixture.instance;
    let mut grant = expected.grant.clone();
    grant.revision += 1;
    let before = store.meta()?;
    let mut notices = store.subscribe_activations()?;
    let mut checked = 0;
    assert!(matches!(
        store.renew_managed(expected, &grant, || {
            checked += 1;
            Err(Code::Denied.error("renewal fixture authority"))
        }),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(checked, 1);
    assert_eq!(fixture.current(&store)?, *expected);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    assert!(store
        .renew_managed(expected, &expected.grant, || {
            checked += 1;
            Err(Code::Denied.error("renewal no-op authority"))
        })
        .is_err());
    assert_eq!(checked, 2);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let mut changed = grant.clone();
    changed.selection.contexts = araphor_data::Selection::All;
    assert!(store.renew_managed(expected, &changed, || Ok(())).is_err());
    assert_eq!(fixture.current(&store)?, *expected);
    assert_eq!(store.meta()?, before);
    let renewed = store.renew_managed(expected, &grant, || {
        checked += 1;
        Ok(())
    })?;
    assert_eq!(checked, 3);
    assert_eq!(renewed.spec, expected.spec);
    assert_eq!(renewed.grant, grant);
    assert_eq!(renewed.generation, expected.generation);
    assert_eq!(renewed.progress, expected.progress);
    assert!(!renewed.running);
    assert!(renewed.lifecycle > expected.lifecycle);
    notices.changed().await?;
    assert_eq!(notices.position(), renewed.lifecycle);
    let before = store.meta()?;
    assert!(store.renew_managed(expected, &grant, || Ok(())).is_err());
    assert!(store
        .admit_managed(&expected.spec, &expected.grant, || Ok(()))
        .is_err());
    assert_eq!(
        store.admit_managed(&renewed.spec, &renewed.grant, || Ok(()))?,
        renewed
    );
    assert_eq!(
        store.renew_managed(&renewed, &grant, || {
            checked += 1;
            Ok(())
        })?,
        renewed
    );
    assert_eq!(checked, 4);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    Ok(())
}

#[test]
fn renewal_keeps_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let captured = fixture.capture(&store)?;
    let input = request("before-renewal");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let committed = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("committed attempt")?;
    assert_eq!(committed.receipt(), Some(&receipt));
    let contract = attempt_record(&store, &input.id)?.1;
    let captured_fields = capture_record(&store, &input.id)?;
    let current = fixture.current(&store)?;
    let original = store.managed_result(
        &current,
        &receipt.results[&10].result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    let running =
        store.set_managed_running([1; 16], "counter", current.lifecycle, true, || Ok(()))?;
    let stopped = store.suspend_managed(&running, || Ok(()))?;
    let status = store.managed_status(
        &stopped.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?;
    assert!(matches!(
        &status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let stale = fixture.capture(&store)?;
    let mut grant = stopped.grant.clone();
    grant.revision += 1;
    let renewed = store.renew_managed(&stopped, &grant, || Ok(()))?;
    assert_eq!(renewed.progress, receipt.commit_revision);
    assert_eq!(renewed.generation, current.generation);
    assert_eq!(
        serde_json::to_value(
            store
                .managed_status(&grant.selection, "counter", &AnalysisReadControl::default())?
                .readiness
        )?,
        serde_json::to_value(&status.readiness)?
    );
    let before = store.meta()?;
    assert!(store
        .register_managed_attempt(&stale, &request("stale-capture"), || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("retained attempt")?;
    assert_eq!(loaded.instance().grant, attempt.instance().grant);
    assert_eq!(attempt_record(&store, &input.id)?.1, contract);
    let mut after = fixture.capture(&store)?;
    for (call, evaluation) in [10, 11].into_iter().zip(&evaluations) {
        after.hydrate_prior(
            call,
            &fixture.model,
            evaluation.parameters.as_ref().map(|batch| sdk::Dataset {
                name: "parameters".into(),
                batches: vec![batch.clone()],
            }),
            None,
        )?;
    }
    assert_eq!(after.instance().grant, grant);
    let continued = request("continued-renewal");
    let pending = store.register_managed_attempt(&after, &continued, || Ok(()))?;
    let saved = capture_record(&store, &continued.id)?;
    assert_eq!(saved.grant, grant);
    assert_eq!(
        saved.prior,
        captured_fields
            .prior
            .keys()
            .map(|call| (*call, receipt.results.get(call).cloned()))
            .collect()
    );
    for call in [10, 11] {
        assert!(fixture
            .continued(&request("continue"), call, Some(&after))?
            .checkpoint
            .is_some());
    }
    store.finish_managed(&pending, ManagedExit::Cancelled, || Ok(()))?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&store)?, renewed);
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("reopened attempt")?;
    assert_eq!(attempt_record(&store, &input.id)?.1, contract);
    assert_eq!(loaded.instance().grant, attempt.instance().grant);
    assert_eq!(
        store.managed_history(&grant.selection, "counter", &AnalysisReadControl::default())?,
        std::slice::from_ref(&receipt)
    );
    let retained = store.managed_result(
        &renewed,
        &receipt.results[&10].result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(call_context(&retained)?, call_context(&original)?);
    assert_eq!(retained.result, original.result);
    assert_eq!(retained.source, original.source);
    assert_eq!(retained.prior, original.prior);
    assert_eq!(retained.receipt, original.receipt);
    assert_eq!(
        serde_json::to_value(
            store
                .managed_status(&grant.selection, "counter", &AnalysisReadControl::default())?
                .readiness
        )?,
        serde_json::to_value(&status.readiness)?
    );
    Ok(())
}

#[test]
fn renewal_requires_finished_work() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let mut grant = fixture.instance.grant.clone();
    grant.revision += 1;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let before = store.meta()?;
    assert!(store.renew_managed(&running, &grant, || Ok(())).is_err());
    assert_eq!(store.meta()?, before);
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let captured = fixture.capture(&store)?;
    let input = request("pending-renewal");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let contract = attempt_record(&store, &input.id)?.1;
    let before = store.meta()?;
    assert!(matches!(
        store.renew_managed(&stopped, &grant, || Ok(())),
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert!(matches!(
        store.renew_managed(&stopped, &grant, || Ok(())),
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt")?;
    assert_eq!(attempt_record(&store, &input.id)?.1, contract);
    assert_eq!(loaded.instance(), attempt.instance());
    assert_eq!(loaded.request(), attempt.request());
    assert_eq!(loaded.captured_revision(), attempt.captured_revision());
    assert!(loaded.receipt().is_none());
    assert!(loaded.terminal().is_none());
    assert!(store
        .finish_managed(&loaded, ManagedExit::Cancelled, || Ok(()))
        .is_err());
    assert_eq!(fixture.current(&store)?, stopped);
    Ok(())
}
