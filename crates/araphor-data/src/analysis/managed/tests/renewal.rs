use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn renewal_cas_is_inert() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let expected = &fixture.instance;
    let mut grant = expected.grant.clone();
    grant.revision += 1;
    let before = store.meta()?;
    let mut notices = store.subscribe_activations();
    let mut checked = 0;
    assert!(matches!(
        store.renew_managed(expected, &grant, || {
            checked += 1;
            Err(Code::Denied.error("renewal fixture authority"))
        }),
        Err(crate::Error::Package {
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
    changed.selection.contexts = crate::Selection::All;
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
    assert_eq!(*notices.borrow_and_update(), renewed.lifecycle);
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
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("before-renewal");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
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
    let current = fixture.current(&store)?;
    let original = store.managed_output(
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
    let stale = fixture.capture(&store, false)?;
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
    assert_eq!(loaded.0, committed.0);
    let after = fixture.capture(&store, false)?;
    assert_eq!(after.contract.grant, grant);
    assert_eq!(
        after.contract.prior,
        captured
            .contract
            .prior
            .iter()
            .map(|(call, _)| (*call, receipt.results.get(call).cloned()))
            .collect()
    );
    for call in [10, 11] {
        assert!(fixture
            .evaluation(&request("continue"), call, Some(&after))?
            .checkpoint
            .is_some());
    }
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
    assert_eq!(loaded.0, committed.0);
    assert_eq!(loaded.instance().grant, attempt.instance().grant);
    assert_eq!(
        store.managed_history(&grant.selection, "counter", &AnalysisReadControl::default())?,
        [receipt.clone()]
    );
    let retained = store.managed_output(
        &renewed,
        &receipt.results[&10].result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(retained.context, original.context);
    assert_eq!(retained.output, original.output);
    assert_eq!(retained.commit_revision, original.commit_revision);
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
    let fixture = Fixture::admit(&store)?;
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
    let captured = fixture.capture(&store, false)?;
    let input = request("pending-renewal");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.renew_managed(&stopped, &grant, || Ok(())),
        Err(crate::Error::Package {
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
        Err(crate::Error::Package {
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
    assert_eq!(loaded.0, attempt.0);
    assert!(store
        .finish_managed(&loaded, ManagedExit::Cancelled, || Ok(()))
        .is_err());
    assert_eq!(fixture.current(&store)?, stopped);
    Ok(())
}
