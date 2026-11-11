use super::*;
use araphor_data::PackageErrorCodeV1 as Code;

fn publish_step(fixture: &Fixture, store: &AnalysisStore, id: &str) -> TestResult<ManagedReceipt> {
    let input = request(id);
    let captured = fixture.capture(store)?;
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    fixture.publish(
        store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )
}

#[test]
fn removal_keeps_exact_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let receipt = publish_step(&fixture, &store, "retained")?;
    let current = fixture.current(&store)?;
    let stale = fixture.capture(&store)?;
    let before = store.meta()?;
    assert!(store
        .remove_managed(&current, || Err(
            Code::Denied.error("remove final authority")
        ))
        .is_err());
    assert_eq!(fixture.current(&store)?, current);
    assert_eq!(store.meta()?, before);
    let removed = store.remove_managed(&current, || Ok(()))?;
    assert!(removed.removed);
    assert!(!removed.running);
    assert_eq!(removed.spec, current.spec);
    assert_eq!(removed.grant, current.grant);
    assert_eq!(removed.generation, current.generation);
    assert_eq!(removed.progress, current.progress);
    assert!(removed.lifecycle > current.lifecycle);
    let status: araphor_data::InstanceStatusV1 = store
        .managed_status(
            &removed.grant.selection,
            "counter",
            &AnalysisReadControl::default(),
        )?
        .try_into()?;
    assert!(status.removed);
    assert!(!status.running);
    let before = store.meta()?;
    let mut guarded = false;
    assert_eq!(
        store.remove_managed(&removed, || {
            guarded = true;
            Ok(())
        })?,
        removed
    );
    assert!(guarded);
    assert_eq!(store.meta()?, before);
    assert!(store.remove_managed(&current, || Ok(())).is_err());
    assert!(store
        .admit_managed(&removed.spec, &removed.grant, || Ok(()))
        .is_err());
    assert!(store
        .set_managed_running([1; 16], "counter", removed.lifecycle, true, || Ok(()))
        .is_err());
    assert!(store
        .renew_managed(&removed, &removed.grant, || Ok(()))
        .is_err());
    assert!(store
        .prepare_managed_version(&removed, &removed.spec, || Ok(()))
        .is_err());
    assert!(store
        .register_managed_attempt(&stale, &request("stale"), || Ok(()))
        .is_err());
    assert!(fixture.capture(&store).is_err());
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    assert_eq!(
        store.managed_history(
            &removed.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![receipt.clone()]
    );
    for reference in receipt.results.values() {
        let retained = store.managed_result(
            &removed,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert!(!retained.current);
        assert_eq!(retained.result, *reference);
        assert_eq!(retained.receipt, receipt);
        assert_eq!(fixture.checkpoint(&store, reference)?.version, 1);
    }
    assert_eq!(store.meta()?, before);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, removed);
    assert_eq!(
        reopened.managed_history(
            &removed.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![receipt]
    );
    Ok(())
}

#[test]
fn removal_waits_all_attempts() -> TestResult {
    for candidate in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = fixture(&store)?;
        let current = fixture.current(&store)?;
        let captured = if candidate {
            let spec = super::version::target(&store, &current, "Pending candidate.")?;
            let next = store.prepare_managed_version(&current, &spec, || Ok(()))?;
            assert_ne!(next.generation, current.generation);
            super::version::capture(&store, &current, &next, false)?
        } else {
            fixture.capture(&store)?
        };
        let input = request("independent-pending");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let before = store.meta()?;
        let mut guarded = false;
        assert!(matches!(
            store.remove_managed(&current, || {
                guarded = true;
                Ok(())
            }),
            Err(araphor_data::Error::AnalysisBusy {
                resource: "managed attempt",
                ..
            })
        ));
        assert!(!guarded);
        assert_eq!(store.meta()?, before);
        assert_eq!(fixture.current(&store)?, current);
        store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
        assert!(
            store
                .remove_managed(&fixture.current(&store)?, || Ok(()))?
                .removed
        );
    }
    Ok(())
}

#[test]
fn recreation_keeps_scoped_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let mut scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    scope.nodes.push("node-a".into());
    let fixture = Fixture::new_scope(&store, "counter", DESCRIPTION.into(), scope)?;
    let first = publish_step(&fixture, &store, "scope-a")?;
    let original = fixture.current(&store)?;
    let removed = store.remove_managed(&original, || Ok(()))?;
    let mut grant = original.grant.clone();
    grant.selection.nodes = vec!["node-b".into()];
    grant.revision += 1;
    grant.principal = "new-owner".into();
    let before = store.meta()?;
    assert!(store
        .recreate_managed(&removed, &removed.spec, &grant, || Err(
            Code::Denied.error("recreate final authority")
        ))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, removed);
    let recreated = store.recreate_managed(&removed, &removed.spec, &grant, || Ok(()))?;
    assert!(!recreated.removed);
    assert!(!recreated.running);
    assert!(recreated.generation > removed.lifecycle);
    assert_eq!(recreated.lifecycle, recreated.generation);
    assert_eq!(recreated.progress, 0);
    assert_eq!(recreated.grant, grant);
    assert!(store
        .recreate_managed(&removed, &removed.spec, &grant, || Ok(()))
        .is_err());
    let next = fixture.capture(&store)?;
    assert!(next.prior(10).is_none());
    assert!(next.prior(11).is_none());
    let second = publish_step(&fixture, &store, "scope-b")?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    let old_id = first.results[&10].result_id.clone();
    assert!(matches!(
        store.managed_result(&current, &old_id, 10, &control),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(
        store.managed_history(&grant.selection, "counter", &control)?,
        vec![second.clone()]
    );
    assert_eq!(
        store.managed_history(&original.grant.selection, "counter", &control)?,
        vec![first.clone()]
    );
    let mut unrelated = grant.selection.clone();
    unrelated.nodes = vec!["node-c".into()];
    assert!(matches!(
        store.managed_history(&unrelated, "counter", &control),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    let mut broad = current.clone();
    broad.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    assert_eq!(
        store.managed_history(&broad.grant.selection, "counter", &control)?,
        vec![first.clone(), second.clone()]
    );
    let mut historical = current.clone();
    historical.grant = original.grant.clone();
    let old = store.managed_result(&historical, &old_id, 10, &control)?;
    assert!(!old.current);
    assert_eq!(old.result.commit_revision, first.commit_revision);
    assert_eq!(
        call_context(&store.managed_result(&broad, &old_id, 10, &control)?)?
            .context
            .id,
        "scope-a"
    );
    let before = store.meta()?;
    let retry = store
        .managed_attempt([1; 16], "counter", "scope-a", &control)?
        .ok_or("old immutable attempt")?;
    assert_eq!(retry.receipt(), Some(&first));
    assert_eq!(retry.instance().grant, original.grant);
    assert_eq!(store.meta()?, before);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, current);
    assert_eq!(
        reopened.managed_history(&original.grant.selection, "counter", &control)?,
        vec![first.clone()]
    );
    assert_eq!(
        reopened.managed_history(&broad.grant.selection, "counter", &control)?,
        vec![first, second]
    );
    assert!(matches!(
        reopened.managed_result(&current, &old_id, 10, &control),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert_eq!(
        call_context(&reopened.managed_result(&historical, &old_id, 10, &control)?)?
            .context
            .id,
        "scope-a"
    );
    Ok(())
}

#[test]
fn historical_scope_precedes_integrity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store)?;
    let first = publish_step(&fixture, &store, "scope-a")?;
    let original = fixture.current(&store)?;
    let removed = store.remove_managed(&original, || Ok(()))?;
    let mut grant = original.grant.clone();
    grant.selection.nodes = vec!["node-b".into()];
    let current = store.recreate_managed(&removed, &removed.spec, &grant, || Ok(()))?;
    let id = &first.results[&10].result_id;
    {
        let (key, bytes) = super::super::output::result_record(store.view()?.as_ref(), id)?;
        let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
        *mut_field(&mut saved, &["revision"])? = Value::U64(first.commit_revision + 1);
        let mut tx = store.write()?;
        tx.native().insert(key, framed(&saved)?);
        tx.commit([])?;
    }
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.managed_result(&current, id, 10, &control),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    let mut permitted = current.clone();
    permitted.grant = original.grant;
    assert!(store.managed_result(&permitted, id, 10, &control).is_err());
    Ok(())
}

#[test]
fn recovery_rejects_scope_changes() -> TestResult {
    for field in ["version", "captured", "removed"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = fixture(&store)?;
        publish_step(&fixture, &store, "scope-a")?;
        let original = fixture.current(&store)?;
        let removed = store.remove_managed(&original, || Ok(()))?;
        let mut grant = original.grant.clone();
        grant.selection.nodes = vec!["node-b".into()];
        store.recreate_managed(&removed, &removed.spec, &grant, || Ok(()))?;
        {
            let mut tx = store.write()?;
            match field {
                "version" => {
                    let (owner, _) = single(&store, b"\0data/J")?;
                    let key = [
                        b"\0data/Z".as_slice(),
                        &owner[7..],
                        &original.generation.to_be_bytes(),
                    ]
                    .concat();
                    let (_, bytes) = single(&store, &key)?;
                    let mut saved: Version = rmp_serde::from_slice(&bytes[1..])?;
                    saved.scope = grant.selection;
                    tx.native().insert(key, framed(&saved)?);
                }
                "captured" => {
                    let (key, bytes) = attempt_record(&store, "scope-a")?;
                    let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
                    *mut_field(&mut saved, &["capture", "grant"])? = serde_value::to_value(grant)?;
                    tx.native().insert(key, framed(&saved)?);
                }
                _ => {
                    let (key, bytes) = single(&store, b"\0data/J")?;
                    let mut saved: Instance = rmp_serde::from_slice(&bytes[1..])?;
                    saved.removed = true;
                    saved.running = true;
                    tx.native().insert(key, framed(&saved)?);
                }
            }
            tx.commit([])?;
        }
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "corruption {field}");
    }
    Ok(())
}

#[test]
fn uninstall_keeps_admitted_program() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let first = publish_step(&fixture, &store, "before-uninstall")?;
    let current = fixture.current(&store)?;
    let pin = &current.spec.definition.images[0];
    let image = store
        .package_image(
            [1; 16],
            &pin.image.package_id,
            Some(&pin.image.revision),
            &AnalysisReadControl::default(),
        )?
        .ok_or("installed image")?;
    assert!(store.uninstall_package_image([1; 16], pin, || Ok(()))?);
    assert!(store
        .package_image(
            [1; 16],
            &pin.image.package_id,
            Some(&pin.image.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(fixture.current(&store)?, current);
    assert_eq!(
        store.admit_managed(&current.spec, &current.grant, || Ok(()))?,
        current
    );
    let second = publish_step(&fixture, &store, "after-uninstall")?;
    let current = fixture.current(&store)?;
    let old = store.managed_result(
        &current,
        &first.results[&10].result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert!(!old.current);
    assert_eq!(call_context(&old)?.context.id, "before-uninstall");
    let mut fresh = current.spec.clone();
    fresh.id = "fresh-counter".into();
    let before = store.meta()?;
    assert!(store
        .admit_managed(&fresh, &current.grant, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, current);
    assert_eq!(
        reopened.managed_history(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![first, second]
    );
    assert!(reopened
        .package_image(
            [1; 16],
            &pin.image.package_id,
            Some(&pin.image.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    reopened.install_package_image([1; 16], &image, || Ok(()))?;
    assert!(
        !reopened
            .admit_managed(&fresh, &current.grant, || Ok(()))?
            .removed
    );
    Ok(())
}

#[test]
fn rollback_keeps_recreated_scope() -> TestResult {
    for rebuild in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let mut scope = AnalysisSelectionV1::tenant([1; 16]);
        scope.nodes = vec!["node-a".into()];
        let fixture = Fixture::new_scope(&store, "counter", DESCRIPTION.into(), scope)?;
        let first = publish_step(&fixture, &store, "original-a")?;
        let original = fixture.current(&store)?;
        let removed = store.remove_managed(&original, || Ok(()))?;
        let mut grant = original.grant.clone();
        grant.selection.nodes = vec!["node-b".into()];
        grant.principal = "new-owner".into();
        grant.revision += 1;
        let spec = super::version::target(&store, &removed, "Recreate in the second scope.")?;
        let recreated = store.recreate_managed(&removed, &spec, &grant, || Ok(()))?;
        assert_ne!(recreated.generation, original.generation);
        let second = publish_step(&fixture, &store, "recreated-b")?;
        let current = fixture.current(&store)?;
        let retained = store.managed_version(
            [1; 16],
            "counter",
            original.generation,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(retained, original.spec);
        let target = store.prepare_managed_version(&current, &retained, || Ok(()))?;
        assert_ne!(target.generation, original.generation);
        assert_eq!(target.grant, grant);
        assert_eq!(fixture.current(&store)?, current);
        let captured = super::version::capture(&store, &current, &target, rebuild)?;
        for call in [10, 11] {
            if rebuild {
                assert!(captured.prior(call).is_none());
            } else {
                let prior = captured.prior(call).ok_or("current-scope prior")?;
                assert_eq!(prior.result, second.results[&call].result_id);
                assert_ne!(prior.result, first.results[&call].result_id);
            }
        }
        let request = ManagedRequest {
            rebuild,
            ..request("rollback-b")
        };
        let attempt = store.register_managed_attempt(&captured, &request, || Ok(()))?;
        let evaluations = [
            fixture.continued(&request, 10, Some(&captured))?,
            fixture.continued(&request, 11, Some(&captured))?,
        ];
        let receipt = fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(20)?, fixture.output(30)?],
        )?;
        let current = fixture.current(&store)?;
        assert_eq!(current.spec, original.spec);
        assert_eq!(current.grant, grant);
        assert_eq!(current.generation, target.generation);
        assert_eq!(
            store.managed_history(&grant.selection, "counter", &AnalysisReadControl::default())?,
            vec![second.clone(), receipt.clone()]
        );
        assert!(matches!(
            store.managed_result(
                &current,
                &first.results[&10].result_id,
                10,
                &AnalysisReadControl::default()
            ),
            Err(araphor_data::Error::Package {
                code: Code::Denied,
                ..
            })
        ));
        let original_attempt = store
            .managed_attempt(
                [1; 16],
                "counter",
                "original-a",
                &AnalysisReadControl::default(),
            )?
            .ok_or("original attempt")?;
        assert_eq!(original_attempt.instance().grant, original.grant);
        assert_eq!(original_attempt.receipt(), Some(&first));
        drop(store);
        let reopened = AnalysisStore::open(&root)?;
        assert_eq!(fixture.current(&reopened)?, current);
        assert_eq!(
            reopened.managed_history(
                &grant.selection,
                "counter",
                &AnalysisReadControl::default()
            )?,
            vec![second, receipt]
        );
    }
    Ok(())
}
