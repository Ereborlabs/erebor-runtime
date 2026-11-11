use super::*;
use araphor_data::{PackageErrorCodeV1 as Code, PackageReadinessV1 as Readiness};

fn status(store: &AnalysisStore, fixture: &Fixture) -> TestResult<ManagedStatus> {
    Ok(store.managed_status(
        &fixture.instance.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?)
}

fn publish(fixture: &Fixture, store: &AnalysisStore, id: &str) -> TestResult<ManagedReceipt> {
    let captured = fixture.capture(store)?;
    let input = request(id);
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
fn idle_failure_keeps_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Inactive
    ));
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Ready
    ));
    let receipt = publish(&fixture, &store, "before-denial")?;
    let current = fixture.current(&store)?;
    assert_eq!(current.lifecycle, running.lifecycle);
    let before = store.meta()?;
    assert!(store
        .suspend_managed(&current, || Err(
            Code::Denied.error("status final authority")
        ))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Ready
    ));
    for stale in [
        ManagedInstance {
            generation: current.generation + 1,
            ..current.clone()
        },
        ManagedInstance {
            lifecycle: current.lifecycle + 1,
            ..current.clone()
        },
        ManagedInstance {
            progress: current.progress - 1,
            ..current.clone()
        },
    ] {
        let mut checked = false;
        assert!(matches!(
            store.suspend_managed(&stale, || {
                checked = true;
                Ok(())
            }),
            Err(araphor_data::Error::AnalysisConflict { .. })
        ));
        assert!(!checked);
        assert_eq!(store.meta()?, before);
    }
    let stopped = store.suspend_managed(&current, || Ok(()))?;
    let failed = status(&store, &fixture)?;
    let attempts = records(store.view()?.as_ref(), b"\0data/a")?.len();
    assert_eq!(attempts, 1);
    assert!(!failed.instance.running);
    assert_eq!(failed.status_progress, receipt.commit_revision);
    assert!(
        matches!(failed.readiness, Readiness::Failed { code: Code::Denied, ref field } if field == "model evaluation")
    );
    let before = store.meta()?;
    let mut checked = false;
    assert_eq!(
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, false, || {
            checked = true;
            Ok(())
        })?,
        stopped
    );
    assert!(checked);
    assert_eq!(store.meta()?, before);
    let resumed =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let denied = store.fail_managed(
        &ManagedResume {
            source: None,
            instance: resumed,
            frontier: None,
            completed: receipt.commit_revision,
        },
        Code::Denied,
        || Ok(()),
    )?;
    assert!(!denied.running);
    assert!(denied.lifecycle > stopped.lifecycle);
    let backup = root.join("backups/status");
    store.backup(&backup)?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let saved = status(&store, &fixture)?;
    assert_eq!(saved.status_progress, receipt.commit_revision);
    assert!(matches!(
        saved.readiness,
        Readiness::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(
        status(&restored, &fixture)?.status_progress,
        receipt.commit_revision
    );
    assert!(matches!(
        status(&restored, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let next = publish(&fixture, &store, "after-denial")?;
    let saved = status(&store, &fixture)?;
    assert!(matches!(saved.readiness, Readiness::Inactive));
    assert_eq!(saved.status_progress, next.commit_revision);
    assert!(Fixture::receipt(
        &store,
        [1; 16],
        "counter",
        "before-denial",
        &AnalysisReadControl::default()
    )?
    .is_some());
    Ok(())
}

#[test]
fn attempted_failure_uses_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store)?;
    let stale = store.register_managed_attempt(&captured, &request("old-lifecycle"), || Ok(()))?;
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert!(
        !store
            .finish_managed(&stale, ManagedExit::Failed(Code::Denied), || Ok(()))?
            .suspended
    );
    assert_eq!(status(&store, &fixture)?.instance, restarted);
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Ready
    ));
    let stopped =
        store.set_managed_running([1; 16], "counter", restarted.lifecycle, false, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Inactive
    ));
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert_eq!(status(&store, &fixture)?.instance, restarted);
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Ready
    ));
    let captured = fixture.capture(&store)?;
    let failed = store.register_managed_attempt(&captured, &request("invalid"), || Ok(()))?;
    store.finish_managed(&failed, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    let captured = fixture.capture(&store)?;
    let cancelled = store.register_managed_attempt(&captured, &request("cancelled"), || Ok(()))?;
    store.finish_managed(&cancelled, ManagedExit::Cancelled, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let current = fixture.current(&store)?;
    let stopped =
        store.set_managed_running([1; 16], "counter", current.lifecycle, false, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let resumed =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let stopped = store.suspend_managed(&resumed, || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Denied,
            ..
        }
    ));
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert!(restarted.lifecycle > restarted.generation);
    assert!(restarted.lifecycle > running.lifecycle);
    let captured = fixture.capture(&store)?;
    let failed = store.register_managed_attempt(&captured, &request("unsupported"), || Ok(()))?;
    let before = store.meta()?;
    assert!(store
        .finish_managed(&failed, ManagedExit::Failed(Code::Unsupported), || Err(
            Code::Denied.error("failure final authority")
        ))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(matches!(
        store.managed_status(
            &fixture.instance.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        ),
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let (_, bytes) = single(&store, b"\0data/Y")?;
    let saved: Failure = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(saved.code, Code::Denied);
    assert_eq!(saved.progress, stopped.progress);
    assert_eq!(saved.revision, stopped.lifecycle);
    store.finish_managed(&failed, ManagedExit::Failed(Code::Unsupported), || Ok(()))?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Unsupported,
            ..
        }
    ));
    let captured = fixture.capture(&store)?;
    let pending = store.register_managed_attempt(&captured, &request("pending"), || Ok(()))?;
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    assert!(matches!(
        store.managed_status(
            &fixture.instance.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        ),
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    store.finish_managed(&pending, ManagedExit::Cancelled, || Ok(()))?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Failed {
            code: Code::Unsupported,
            ..
        }
    ));
    let completed = publish(&fixture, &store, "new-success")?;
    let saved = status(&store, &fixture)?;
    assert!(matches!(saved.readiness, Readiness::Ready));
    assert_eq!(saved.status_progress, completed.commit_revision);
    assert_eq!(saved.instance.lifecycle, restarted.lifecycle);
    Ok(())
}

#[test]
fn status_read_is_scoped_metadata() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store)?;
    publish(&fixture, &store, "stored")?;
    let selected = AnalysisSelectionV1::new([1; 16], vec![identity()]);
    assert!(matches!(
        store.managed_status(&selected, "counter", &AnalysisReadControl::default()),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(matches!(
        store.managed_status(
            &AnalysisSelectionV1::tenant([2; 16]),
            "counter",
            &AnalysisReadControl::default()
        ),
        Err(araphor_data::Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .managed_status(&fixture.instance.grant.selection, "counter", &cancelled)
        .is_err());
    let view = store.view()?;
    let checkpoints = records(&view, b"\0data/U")?;
    let packages = records(&view, b"\0data/P")?;
    let bodies = records(&view, b"\0data/@package-body/")?;
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(packages.len(), 1);
    assert_eq!(bodies.len(), 1);
    let mut tx = store.write()?;
    for key in checkpoints
        .keys()
        .chain(packages.keys())
        .chain(bodies.keys())
    {
        tx.native().insert(key, b"invalid");
    }
    tx.commit([])?;
    let before = store.meta()?;
    assert!(matches!(
        status(&store, &fixture)?.readiness,
        Readiness::Inactive
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn failure_recovery_rejects_corruption() -> TestResult {
    for fault in 0..8 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = fixture(&store)?;
        let running = store.set_managed_running(
            [1; 16],
            "counter",
            fixture.instance.lifecycle,
            true,
            || Ok(()),
        )?;
        if fault == 7 {
            publish(&fixture, &store, "real-progress")?;
        }
        let stopped = store.suspend_managed(&fixture.current(&store)?, || Ok(()))?;
        assert!(stopped.lifecycle > running.lifecycle);
        let mut failure = Failure {
            origin: FailureOrigin::Admission,
            code: Code::Denied,
            progress: stopped.progress,
            revision: stopped.lifecycle,
        };
        match fault {
            0 => failure.code = Code::Invalid,
            1 => failure.progress = 1,
            2 => failure.revision = stopped.generation,
            3 => failure.revision = stopped.lifecycle + 1,
            7 => failure.progress = 1,
            _ => {}
        }
        let (key, _) = single(&store, b"\0data/Y")?;
        let mut tx = store.write()?;
        if fault == 3 {
            failure.revision = tx.revision() + 1;
        }
        match fault {
            4 => {
                let (key, bytes) = single(&store, b"\0data/J")?;
                let mut row: Instance = rmp_serde::from_slice(&bytes[1..])?;
                row.running = true;
                tx.native().insert(key, framed(&row)?);
            }
            5 => {
                let Value::Map(mut fields) = serde_value::to_value(&failure)? else {
                    return Err("failure fields".into());
                };
                assert!(fields.remove(&Value::String("revision".into())).is_some());
                tx.native().insert(key, framed(&Value::Map(fields))?);
            }
            6 => {
                tx.native()
                    .insert(key, [vec![0], br#"{"code":"denied"}"#.to_vec()].concat());
            }
            _ => {
                tx.native().insert(key, framed(&failure)?);
            }
        }
        tx.commit([])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "failure fault {fault}");
    }
    Ok(())
}

#[test]
fn terminal_status_recovery_checks_fact() -> TestResult {
    for fault in 0..7 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = fixture(&store)?;
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
        let captured = fixture.capture(&store)?;
        let attempt =
            store.register_managed_attempt(&captured, &request("known-failure"), || Ok(()))?;
        let code = if fault == 6 {
            Code::Denied
        } else {
            Code::Invalid
        };
        let terminal = store.finish_managed(&attempt, ManagedExit::Failed(code), || Ok(()))?;
        let mut failure = Failure {
            origin: FailureOrigin::Attempt,
            code,
            progress: 0,
            revision: terminal.revision,
        };
        if fault == 1 {
            failure.code = Code::Denied;
        }
        if fault == 2 {
            failure.revision += 1;
        }
        if fault == 4 {
            failure.origin = FailureOrigin::Admission;
        }
        let (key, _) = single(&store, b"\0data/Y")?;
        let mut tx = store.write()?;
        if fault == 2 {
            failure.revision = tx.revision() + 1;
        }
        if fault == 0 {
            tx.native().remove(key);
        } else if matches!(fault, 3 | 6) {
            let attempts = records(store.view()?.as_ref(), b"\0data/a")?;
            assert_eq!(attempts.len(), 1);
            for key in attempts.keys() {
                tx.native().remove(key);
            }
        } else if fault == 5 {
            #[derive(serde::Serialize)]
            struct MissingOrigin {
                code: Code,
                progress: u64,
                revision: u64,
            }
            let value = MissingOrigin {
                code: failure.code,
                progress: failure.progress,
                revision: failure.revision,
            };
            tx.native().insert(key, framed(&value)?);
        } else {
            tx.native().insert(key, framed(&failure)?);
        }
        tx.commit([])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "failure fact {fault}");
    }
    Ok(())
}

#[test]
fn admission_failure_keeps_intent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
        Ok(())
    })?;
    let prior = publish(&fixture, &store, "before-admission")?;
    let captured = fixture.capture(&store)?;
    let attempt = store.register_managed_attempt(&captured, &request("real-failure"), || Ok(()))?;
    let terminal =
        store.finish_managed(&attempt, ManagedExit::Failed(Code::Unsupported), || Ok(()))?;
    let expected = ManagedResume {
        source: None,
        instance: fixture.current(&store)?,
        frontier: None,
        completed: terminal.revision,
    };
    let activations = store.subscribe_activations()?;
    assert_eq!(activations.position(), store.meta()?.commit_revision);
    let recorded = store.fail_managed(&expected, Code::Limit, || Ok(()))?;
    assert_eq!(recorded, expected.instance);
    assert_eq!(recorded.progress, prior.commit_revision);
    assert!(recorded.running);
    assert!(!activations.has_changed()?);
    let before = store.meta()?;
    let mut checked = false;
    assert_eq!(
        store.fail_managed(&expected, Code::Limit, || {
            checked = true;
            Ok(())
        })?,
        recorded
    );
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert!(!activations.has_changed()?);
    let attempts = records(store.view()?.as_ref(), b"\0data/a")?.len();
    let (_, bytes) = single(&store, b"\0data/Y")?;
    assert_eq!(attempts, 2);
    let failure: Failure = rmp_serde::from_slice(&bytes[1..])?;
    assert!(failure.origin == FailureOrigin::Admission);
    assert_eq!(failure.code, Code::Limit);
    assert_eq!(failure.progress, prior.commit_revision);
    assert_eq!(failure.revision, before.commit_revision);
    drop(activations);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let saved = status(&store, &fixture)?;
    assert_eq!(saved.instance, recorded);
    assert!(matches!(
        saved.readiness,
        Readiness::Failed {
            code: Code::Limit,
            ..
        }
    ));
    assert!(Fixture::receipt(
        &store,
        [1; 16],
        "counter",
        "before-admission",
        &AnalysisReadControl::default()
    )?
    .is_some());
    let next = publish(&fixture, &store, "after-admission")?;
    let saved = status(&store, &fixture)?;
    assert!(matches!(saved.readiness, Readiness::Ready));
    assert_eq!(saved.instance.progress, next.commit_revision);
    assert_eq!(saved.instance.lifecycle, recorded.lifecycle);
    let empty = records(store.view()?.as_ref(), b"\0data/Y")?.is_empty();
    assert!(empty);
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                "real-failure",
                &AnalysisReadControl::default()
            )?
            .ok_or("historical failure absent")?
            .terminal(),
        Some(&terminal)
    );
    Ok(())
}

#[test]
fn admission_failure_checks_fences() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store)?;
    let current =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let expected = ManagedResume {
        source: None,
        instance: current.clone(),
        frontier: None,
        completed: 0,
    };
    let mut grant = current.clone();
    grant.grant.revision += 1;
    let mut spec = current.clone();
    spec.spec.definition.definition.description = "Different definition.".into();
    for stale in [
        ManagedInstance {
            generation: current.generation + 1,
            ..current.clone()
        },
        ManagedInstance {
            lifecycle: current.lifecycle + 1,
            ..current.clone()
        },
        ManagedInstance {
            progress: current.progress + 1,
            ..current.clone()
        },
        ManagedInstance {
            running: false,
            ..current.clone()
        },
        ManagedInstance {
            removed: true,
            running: false,
            ..current.clone()
        },
        grant,
        spec,
    ] {
        let before = store.meta()?;
        let mut checked = false;
        assert!(store
            .fail_managed(
                &ManagedResume {
                    instance: stale,
                    ..expected.clone()
                },
                Code::Invalid,
                || {
                    checked = true;
                    Ok(())
                }
            )
            .is_err());
        assert!(!checked);
        assert_eq!(store.meta()?, before);
        assert_eq!(fixture.current(&store)?, current);
    }
    let before = store.meta()?;
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .fail_managed(&expected, Code::Invalid, || cancelled.check())
        .is_err());
    assert_eq!(store.meta()?, before);
    let captured = fixture.capture(&store)?;
    let pending =
        store.register_managed_attempt(&captured, &request("pending-admission"), || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.fail_managed(&expected, Code::Invalid, || Ok(())),
        Err(araphor_data::Error::AnalysisBusy {
            resource: "managed attempt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let terminal = store.finish_managed(&pending, ManagedExit::Cancelled, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.fail_managed(&expected, Code::Invalid, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    let expected = ManagedResume {
        completed: terminal.revision,
        ..expected
    };
    store.fail_managed(&expected, Code::Invalid, || Ok(()))?;
    let receipt = publish(&fixture, &store, "new-progress")?;
    let before = store.meta()?;
    assert!(matches!(
        store.fail_managed(&expected, Code::Limit, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?.progress, receipt.commit_revision);
    let current = fixture.current(&store)?;
    let expected = ManagedResume {
        source: None,
        instance: current.clone(),
        completed: receipt.commit_revision,
        frontier: None,
    };
    let stopped = store.stop_managed(&current, || Ok(()))?;
    let mut renewed = stopped.grant.clone();
    renewed.revision += 1;
    store.renew_managed(&stopped, &renewed, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.fail_managed(&expected, Code::Invalid, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}
