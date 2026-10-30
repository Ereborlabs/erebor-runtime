use super::*;
use crate::PackageErrorCodeV1 as Code;

pub(super) fn target(
    store: &AnalysisStore,
    current: &ManagedInstance,
    description: &str,
) -> TestResult<ManagedSpec> {
    let mut spec = current.spec.clone();
    spec.definition.definition.description = description.into();
    spec.manifest.definition = spec.definition.digest()?;
    store.admit_definition(spec.tenant, &spec.definition, || Ok(()))?;
    Ok(spec)
}

pub(super) fn capture(
    store: &AnalysisStore,
    current: &ManagedInstance,
    target: &ManagedInstance,
    rebuild: bool,
) -> TestResult<ManagedCapture> {
    Ok(store
        .read_managed_tables(
            &current.grant.selection,
            &ManagedRead {
                execution: None,
                follow: false,
                instance: target.clone(),
                expected: Some(current.clone()),
                rebuild,
                completed: None,
            },
            AnalysisTableRead {
                requests: &AnalysisTableRequests::new(),
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?
        .state)
}

#[test]
fn versions_keep_state_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let first = request("original");
    let original = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&original, &first, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&first, 10, Some(&original))?,
        fixture.evaluation(&first, 11, Some(&original))?,
    ];
    let outputs = [fixture.output(12)?, fixture.output(103)?];
    let first_receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    let spec = target(&store, &current, "Keep the same call state.")?;
    let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    assert_ne!(next.generation, current.generation);
    assert_eq!(fixture.current(&store)?, current);
    let selected = capture(&store, &current, &next, false)?;
    for call in [10, 11] {
        assert_eq!(
            selected.prior(call).ok_or("retained call state")?.result,
            first_receipt.results[&call].result_id
        );
    }
    let second = request("updated");
    let next_attempt = store.register_managed_attempt(&selected, &second, || Ok(()))?;
    let next_evaluations = [
        fixture.evaluation(&second, 10, Some(&selected))?,
        fixture.evaluation(&second, 11, Some(&selected))?,
    ];
    let next_outputs = [fixture.output(22)?, fixture.output(203)?];
    let before = store.meta()?;
    assert!(fixture
        .publish_checked(
            &store,
            &next_attempt,
            &next_evaluations,
            &next_outputs,
            || Err(Code::Denied.error("version final authority"))
        )
        .is_err());
    assert_eq!(fixture.current(&store)?, current);
    assert_eq!(store.meta()?, before);
    let receipt = fixture.publish(&store, &next_attempt, &next_evaluations, &next_outputs)?;
    let changed = fixture.current(&store)?;
    assert_eq!(changed.spec, spec);
    assert_eq!(changed.grant, current.grant);
    assert_eq!(changed.generation, next.generation);
    assert_eq!(changed.lifecycle, receipt.commit_revision);
    assert_eq!(changed.progress, receipt.commit_revision);
    let old = store
        .managed_attempt(
            [1; 16],
            "counter",
            &first.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("old attempt")?;
    assert_eq!(old.instance().spec, current.spec);
    assert_eq!(old.receipt(), Some(&first_receipt));
    assert_eq!(
        store.managed_history(
            &changed.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![first_receipt.clone(), receipt.clone()]
    );
    let old_result = &first_receipt.results[&10].result_id;
    assert!(
        !store
            .managed_result(&changed, old_result, 10, &AnalysisReadControl::default())?
            .current
    );
    let saved = store.managed_evaluation(&changed, old_result, &AnalysisReadControl::default())?;
    assert_eq!(saved.inputs.len(), evaluations[0].inputs.len());
    for (saved, original) in saved.inputs.iter().zip(&evaluations[0].inputs) {
        assert_eq!(saved.data.name, original.data.name);
        assert_eq!(saved.data.batches, original.data.batches);
        assert_eq!(saved.revision, original.revision);
        assert_eq!(saved.coverage, original.coverage);
    }
    let rollback = store.prepare_managed_version(&changed, &current.spec, || Ok(()))?;
    assert_eq!(rollback.generation, current.generation);
    let selected = capture(&store, &changed, &rollback, false)?;
    let third = request("rollback");
    let rollback_attempt = store.register_managed_attempt(&selected, &third, || Ok(()))?;
    let rollback_evaluations = [
        fixture.evaluation(&third, 10, Some(&selected))?,
        fixture.evaluation(&third, 11, Some(&selected))?,
    ];
    let rollback_receipt =
        fixture.publish(&store, &rollback_attempt, &rollback_evaluations, &outputs)?;
    let restored = fixture.current(&store)?;
    assert_eq!(restored.generation, current.generation);
    assert_eq!(restored.lifecycle, rollback_receipt.commit_revision);
    assert!(restored.lifecycle > changed.lifecycle);
    assert!(store
        .register_managed_attempt(&original, &request("stale-original"), || Ok(()))
        .is_err());
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, restored);
    let old = reopened
        .managed_attempt(
            [1; 16],
            "counter",
            &first.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored original attempt")?;
    assert_eq!(old.receipt(), Some(&first_receipt));
    assert_eq!(old.instance().spec, current.spec);
    assert_eq!(
        reopened.managed_history(
            &restored.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![first_receipt, receipt, rollback_receipt]
    );
    Ok(())
}

#[test]
fn failed_versions_keep_current() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let current = fixture.current(&store)?;
    let spec = target(&store, &current, "Reject the candidate.")?;
    let before = store.meta()?;
    assert!(store
        .prepare_managed_version(&current, &spec, || Err(
            Code::Denied.error("version admission authority")
        ))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, current);
    let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let original = fixture.capture(&store, false)?;
    let candidate = capture(&store, &current, &next, true)?;
    let input = request("failed-candidate");
    let mut input = ManagedRequest {
        rebuild: true,
        ..input
    };
    let attempt = store.register_managed_attempt(&candidate, &input, || Ok(()))?;
    store.finish_managed(&attempt, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    assert_eq!(fixture.current(&store)?, current);
    let status = store.managed_status(
        &current.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?;
    assert!(matches!(
        status.readiness,
        crate::PackageReadinessV1::Inactive
    ));
    let old_attempt =
        store.register_managed_attempt(&original, &request("old-still-usable"), || Ok(()))?;
    let old_input = old_attempt.request();
    let evaluations = [
        fixture.evaluation(old_input, 10, Some(&original))?,
        fixture.evaluation(old_input, 11, Some(&original))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &old_attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    input.id = "second-candidate".into();
    let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let candidate = capture(&store, &current, &next, true)?;
    let attempt = store.register_managed_attempt(&candidate, &input, || Ok(()))?;
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, current);
    assert_eq!(fixture.capture(&reopened, false)?.instance(), &current);
    Ok(())
}

#[test]
fn versions_require_explicit_rebuild() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let selected = fixture.capture(&store, false)?;
    let input = request("seed");
    let attempt = store.register_managed_attempt(&selected, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&selected))?,
        fixture.evaluation(&input, 11, Some(&selected))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    let mut spec = target(&store, &current, "Change a stateful call.")?;
    spec.manifest
        .calls
        .get_mut(&10)
        .ok_or("first call")?
        .arguments
        .push("changed => 1".into());
    let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    assert!(capture(&store, &current, &next, false).is_err());
    let rebuilt = capture(&store, &current, &next, true)?;
    assert!(rebuilt.prior(10).is_none());
    assert!(fixture
        .evaluation(
            &ManagedRequest {
                rebuild: true,
                ..request("rebuilt")
            },
            11,
            Some(&rebuilt)
        )?
        .checkpoint
        .is_none());
    assert_eq!(fixture.current(&store)?, current);
    Ok(())
}

#[test]
fn versions_keep_call_identity() -> TestResult {
    for changed in ["outer", "planner"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let selected = fixture.capture(&store, false)?;
        let input = request("seed");
        let attempt = store.register_managed_attempt(&selected, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&selected))?,
            fixture.evaluation(&input, 11, Some(&selected))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let current = fixture.current(&store)?;
        let mut spec = target(&store, &current, "Require exact call ownership.")?;
        if changed == "outer" {
            let sql = format!(
                "SELECT * FROM ({}) AS changed WHERE true",
                spec.definition.sql
            );
            spec.definition.sql = sql.clone();
            spec.definition.definition.program = Program::Sql {
                source: Source::Inline { inline: sql },
            };
            spec.manifest.definition = spec.definition.digest()?;
            store.admit_definition(spec.tenant, &spec.definition, || Ok(()))?;
        } else {
            spec.manifest.planner.push_str("/changed");
        }
        assert_eq!(spec.manifest.calls, current.spec.manifest.calls);
        let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
        let before = store.meta()?;
        assert!(
            capture(&store, &current, &next, false).is_err(),
            "{changed}"
        );
        assert_eq!(fixture.current(&store)?, current);
        assert_eq!(store.meta()?, before);
        let rebuilt = capture(&store, &current, &next, true)?;
        let input = ManagedRequest {
            rebuild: true,
            ..request("rebuild")
        };
        let attempt = store.register_managed_attempt(&rebuilt, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&rebuilt))?,
            fixture.evaluation(&input, 11, Some(&rebuilt))?,
        ];
        assert!(evaluations
            .iter()
            .all(|evaluation| evaluation.checkpoint.is_none()));
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let current = fixture.current(&store)?;
        assert_eq!(current.generation, next.generation);
        assert_eq!(current.progress, receipt.commit_revision);
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(fixture.current(&reopened)?, current);
    }
    Ok(())
}

#[test]
fn pending_versions_stay_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let current = fixture.current(&store)?;
    let spec = target(&store, &current, "Retain an unknown target attempt.")?;
    let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let selected = capture(&store, &current, &next, true)?;
    let input = ManagedRequest {
        rebuild: true,
        ..request("pending-target")
    };
    let attempt = store.register_managed_attempt(&selected, &input, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.prepare_managed_version(&current, &spec, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, current);
    let original = fixture.capture(&store, false)?;
    let old_input = request("old-program");
    let old_attempt = store.register_managed_attempt(&original, &old_input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&old_input, 10, Some(&original))?,
        fixture.evaluation(&old_input, 11, Some(&original))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &old_attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    assert!(store
        .prepare_managed_version(&current, &spec, || Ok(()))
        .is_err());
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let available = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    assert_eq!(available.generation, next.generation);
    assert_eq!(fixture.current(&store)?, current);
    Ok(())
}
