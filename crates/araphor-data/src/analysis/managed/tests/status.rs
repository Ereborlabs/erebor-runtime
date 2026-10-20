use super::*;
use crate::{PackageErrorCodeV1 as Code, PackageReadinessV1 as Readiness};

fn status(store: &AnalysisStore, fixture: &Fixture) -> TestResult<ManagedStatus> {
    Ok(store.managed_status(
        &fixture.instance.spec.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?)
}

fn publish(fixture: &Fixture, store: &AnalysisStore, id: &str) -> TestResult<ManagedReceipt> {
    let captured = fixture.capture(store, false)?;
    let input = request(id);
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
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
    let fixture = Fixture::admit(&store)?;
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
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert!(!checked);
        assert_eq!(store.meta()?, before);
    }
    let stopped = store.suspend_managed(&current, || Ok(()))?;
    let failed = status(&store, &fixture)?;
    let attempts: u64 = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT count(*) FROM managed_attempts", [], |row| {
                row.get(0)
            })
            .context(crate::AnalysisDatabaseSnafu {
                operation: "count idle failure attempts",
            })
    })?;
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
    store.set_managed_running([1; 16], "counter", resumed.lifecycle, false, || Ok(()))?;
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
    assert!(store
        .managed_selected(
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
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store, false)?;
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
    let captured = fixture.capture(&store, false)?;
    let failed = store.register_managed_attempt(&captured, &request("invalid"), || Ok(()))?;
    store.finish_managed(&failed, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    let captured = fixture.capture(&store, false)?;
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
    let captured = fixture.capture(&store, false)?;
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
            &fixture.instance.spec.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let bytes: Vec<u8> = store.read_snapshot(|reader| {
        reader
            .query_row("SELECT failure FROM managed_instances", [], |row| {
                row.get(0)
            })
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read rolled back failure",
            })
    })?;
    let saved: super::super::status::Failure = serde_json::from_slice(&bytes)?;
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
    let captured = fixture.capture(&store, false)?;
    let pending = store.register_managed_attempt(&captured, &request("pending"), || Ok(()))?;
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    assert!(matches!(
        store.managed_status(
            &fixture.instance.spec.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::Package {
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
    let fixture = Fixture::admit(&store)?;
    publish(&fixture, &store, "stored")?;
    let selected = AnalysisSelectionV1::new([1; 16], vec![crate::analysis::tests::identity()]);
    assert!(matches!(
        store.managed_status(&selected, "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
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
        Err(crate::Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .managed_status(
            &fixture.instance.spec.grant.selection,
            "counter",
            &cancelled
        )
        .is_err());
    let before = store.meta()?;
    let mut writer = store.writer()?;
    writer
        .get_mut()?
        .execute("UPDATE managed_arrow SET ipc = 'invalid'::BLOB", [])?;
    writer.get_mut()?.execute(
        "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
        [],
    )?;
    drop(writer);
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
        let fixture = Fixture::admit(&store)?;
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
        let mut failure = super::super::status::Failure {
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
        let mut writer = store.writer()?;
        match fault {
            4 => {
                writer
                    .get_mut()?
                    .execute("UPDATE managed_instances SET running = true", [])?;
            }
            5 => {
                writer
                    .get_mut()?
                    .execute("ALTER TABLE managed_instances DROP COLUMN failure", [])?;
            }
            6 => {
                writer.get_mut()?.execute(
                    r#"UPDATE managed_instances SET failure = '{"code":"denied"}'::BLOB"#,
                    [],
                )?;
            }
            _ => {
                writer.get_mut()?.execute(
                    "UPDATE managed_instances SET failure = ?",
                    params![serde_json::to_vec(&failure)?],
                )?;
            }
        }
        drop(writer);
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "failure fault {fault}");
    }
    Ok(())
}

#[test]
fn terminal_status_recovery_checks_fact() -> TestResult {
    for fault in 0..3 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
        let captured = fixture.capture(&store, false)?;
        let attempt =
            store.register_managed_attempt(&captured, &request("known-failure"), || Ok(()))?;
        let terminal =
            store.finish_managed(&attempt, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
        let mut failure = super::super::status::Failure {
            code: Code::Invalid,
            progress: 0,
            revision: terminal.revision,
        };
        if fault == 1 {
            failure.code = Code::Denied;
        }
        if fault == 2 {
            failure.revision += 1;
        }
        let mut writer = store.writer()?;
        if fault == 0 {
            writer
                .get_mut()?
                .execute("UPDATE managed_instances SET failure = NULL", [])?;
        } else {
            writer.get_mut()?.execute(
                "UPDATE managed_instances SET failure = ?",
                params![serde_json::to_vec(&failure)?],
            )?;
        }
        drop(writer);
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "failure fact {fault}");
    }
    Ok(())
}
