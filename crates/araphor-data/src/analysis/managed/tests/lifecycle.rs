use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn explicit_stop_fences_birth() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let birth = fixture.instance.clone();
    let captured = fixture.capture(&store, false)?;
    let before = store.meta()?;
    assert!(store
        .stop_managed(
            &birth,
            || Err(Code::Denied.error("explicit stop authority"))
        )
        .is_err());
    assert_eq!(fixture.current(&store)?, birth);
    assert_eq!(store.meta()?, before);
    let mut wrong = birth.clone();
    wrong.grant.principal.push_str("-other");
    assert!(store.stop_managed(&wrong, || Ok(())).is_err());
    assert_eq!(store.meta()?, before);
    let stopped = store.stop_managed(&birth, || Ok(()))?;
    assert!(!stopped.running);
    assert!(stopped.lifecycle > birth.lifecycle);
    assert_eq!(stopped.generation, birth.generation);
    assert_eq!(stopped.progress, birth.progress);
    assert_eq!(stopped.spec, birth.spec);
    assert_eq!(stopped.grant, birth.grant);
    let before = store.meta()?;
    let mut checked = false;
    assert!(store
        .set_managed_running([1; 16], "counter", birth.lifecycle, true, || {
            checked = true;
            Ok(())
        })
        .is_err());
    assert!(!checked);
    assert!(store.stop_managed(&birth, || Ok(())).is_err());
    assert!(store
        .register_managed_attempt(&captured, &request("before-stop"), || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    let mut checked = false;
    assert_eq!(
        store.stop_managed(&stopped, || {
            checked = true;
            Ok(())
        })?,
        stopped
    );
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert!(store
        .stop_managed(&stopped, || Err(Code::Denied.error("stopped authority")))
        .is_err());
    assert_eq!(store.meta()?, before);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&reopened)?, stopped);
    assert!(reopened
        .set_managed_running([1; 16], "counter", birth.lifecycle, true, || Ok(()))
        .is_err());
    Ok(())
}

#[test]
fn lifecycle_cas_is_inert() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut notices = store.subscribe_activations();
    let fixture = Fixture::admit(&store)?;
    let admitted = &fixture.instance;
    assert!(!admitted.running);
    assert_eq!(admitted.lifecycle, admitted.generation);
    assert_eq!(admitted.progress, 0);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    assert!(!notices.has_changed()?);
    let before = store.meta()?;
    let mut checked = false;
    assert!(matches!(
        store.set_managed_running([1; 16], "counter", admitted.lifecycle, true, || {
            checked = true;
            Err(Code::Denied.error("lifecycle fixture authority"))
        }),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(checked);
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, *admitted);
    assert!(!notices.has_changed()?);
    let mut checked = false;
    let unchanged =
        store.set_managed_running([1; 16], "counter", admitted.lifecycle, false, || {
            checked = true;
            Ok(())
        })?;
    assert!(checked);
    assert_eq!(unchanged, *admitted);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let running =
        store.set_managed_running([1; 16], "counter", admitted.lifecycle, true, || Ok(()))?;
    assert!(running.running);
    assert!(running.lifecycle > admitted.lifecycle);
    assert_eq!(running.generation, admitted.generation);
    assert_eq!(running.progress, 0);
    assert_eq!(running.spec, admitted.spec);
    assert_eq!(
        store
            .active_managed(&AnalysisReadControl::default())?
            .1
            .as_slice(),
        std::slice::from_ref(&ManagedMember {
            tenant: running.spec.tenant,
            id: running.spec.id.clone(),
            generation: running.generation,
            lifecycle: running.lifecycle
        })
    );
    assert!(notices.has_changed()?);
    assert_eq!(*notices.borrow_and_update(), running.lifecycle);
    let mut checked = false;
    assert!(matches!(
        store.set_managed_running([1; 16], "counter", admitted.lifecycle, true, || {
            checked = true;
            Ok(())
        }),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(!checked);
    assert!(!notices.has_changed()?);
    let before = store.meta()?;
    let mut checked = false;
    assert!(matches!(
        store.set_managed_running([1; 16], "counter", running.lifecycle, true, || {
            checked = true;
            Err(Code::Denied.error("lifecycle no-op authority"))
        }),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(checked);
    assert_eq!(store.meta()?, before);
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    assert!(!stopped.running);
    assert!(stopped.lifecycle > running.lifecycle);
    assert_eq!(stopped.generation, admitted.generation);
    assert_eq!(stopped.progress, 0);
    assert_eq!(stopped.spec, admitted.spec);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    assert!(notices.has_changed()?);
    notices.borrow_and_update();
    assert!(matches!(
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(!notices.has_changed()?);
    Ok(())
}

#[test]
fn recovery_reconciles_running() -> TestResult {
    for applied in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = Fixture::admit(&store)?;
        let running = store.set_managed_running(
            [1; 16],
            "counter",
            fixture.instance.lifecycle,
            true,
            || Ok(()),
        )?;
        let previous = store.meta()?.commit_revision;
        let mut notices = store.subscribe_activations();
        let mut stopped = running.clone();
        let revision;
        {
            let mut writer = store.writer()?;
            let transaction = writer.get_mut()?.transaction()?;
            revision = store.package_next(&transaction)?;
            assert_eq!(transaction.execute(
                "UPDATE managed_instances SET running = false, lifecycle = ? WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
                params![revision, running.spec.tenant.as_slice(), running.spec.id, running.lifecycle],
            )?, 1);
            stopped.running = false;
            stopped.lifecycle = revision;
            AnalysisStore::record_revision(&transaction, revision, &["managed_instances"])?;
            transaction.execute_batch(if applied { "COMMIT" } else { "ROLLBACK" })?;
            assert!(matches!(
                store.commit_metadata(transaction, "test uncertain managed commit"),
                Err(crate::Error::AnalysisDatabase {
                    operation: "test uncertain managed commit",
                    ..
                })
            ));
        }
        assert!(!store.write_ready.load(std::sync::atomic::Ordering::Acquire));
        assert!(!notices.has_changed()?);
        store.recover()?;
        assert!(store.write_ready.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(notices.has_changed()?, applied);
        assert_eq!(
            *notices.borrow_and_update(),
            if applied { revision } else { running.lifecycle }
        );
        assert_eq!(
            store.meta()?.commit_revision,
            if applied { revision } else { previous }
        );
        assert_eq!(
            fixture.current(&store)?,
            if applied { stopped } else { running.clone() }
        );
        let expected = if applied {
            Vec::new()
        } else {
            vec![ManagedMember {
                tenant: running.spec.tenant,
                id: running.spec.id.clone(),
                generation: running.generation,
                lifecycle: running.lifecycle,
            }]
        };
        assert_eq!(
            store.active_managed(&AnalysisReadControl::default())?.1,
            expected
        );
        store.recover()?;
        assert!(!notices.has_changed()?);
        let bytes = Vec::<u8>::try_from(&crate::EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        store.accept_validated_batch(
            crate::analysis::tests::identity(),
            crate::analysis::tests::batch(1, &[&bytes]),
        )?;
        assert!(!notices.has_changed()?);
    }
    Ok(())
}

#[test]
fn lifecycle_notice_excludes_data() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let mut notices = store.subscribe_activations();
    let bytes = Vec::<u8>::try_from(&crate::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        crate::analysis::tests::identity(),
        crate::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![bytes.len()],
            framed_records: bytes.into(),
        },
    )?;
    assert!(!notices.has_changed()?);
    let captured = fixture.capture(&store, false)?;
    let input = request("metadata-notice");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(!notices.has_changed()?);
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    assert!(!notices.has_changed()?);
    let current = fixture.current(&store)?;
    assert_eq!(current.lifecycle, running.lifecycle);
    assert_eq!(current.generation, running.generation);
    assert_eq!(current.progress, receipt.commit_revision);
    let before = store.meta()?;
    let unchanged =
        store.set_managed_running([1; 16], "counter", running.lifecycle, true, || Ok(()))?;
    assert_eq!(unchanged, current);
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let stopped =
        store.set_managed_running([1; 16], "counter", current.lifecycle, false, || Ok(()))?;
    assert_eq!(stopped.progress, receipt.commit_revision);
    assert_eq!(stopped.generation, running.generation);
    assert!(notices.has_changed()?);
    assert_eq!(*notices.borrow_and_update(), stopped.lifecycle);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    Ok(())
}

#[test]
fn transition_fences_registration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let before = store.meta()?;
    let input = request("old-capture");
    assert!(matches!(
        store.register_managed_attempt(&captured, &input, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(store.meta()?, before);
    let requests = AnalysisTableRequests::new();
    assert!(store
        .read_managed_tables(
            &fixture.instance.grant.selection,
            &ManagedRead {
                execution: None,
                follow: false,
                expected: None,
                instance: fixture.instance.clone(),
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Metadata,
                now: 10
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .is_err());
    assert_eq!(fixture.current(&store)?, running);
    let current = fixture.capture(&store, false)?;
    assert_eq!(current.instance(), &running);
    assert_eq!(current.contract.lifecycle, running.lifecycle);
    assert!(current.contract.running);
    Ok(())
}

#[test]
fn transition_fences_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store, false)?;
    let input = request("old-work");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let before = store.meta()?;
    let error = fixture
        .publish(&store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("old lifecycle published")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?.progress, 0);
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    let before = store.meta()?;
    let error = fixture
        .publish(&store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("old lifecycle published")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?.progress, 0);
    assert_eq!(restarted.generation, fixture.instance.generation);
    let stopped =
        store.set_managed_running([1; 16], "counter", restarted.lifecycle, false, || Ok(()))?;
    let captured = fixture.capture(&store, false)?;
    let input = request("inactive-finite");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    assert!(!current.running);
    assert_eq!(current.lifecycle, stopped.lifecycle);
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(current.generation, fixture.instance.generation);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    Ok(())
}

#[test]
fn lifecycle_history_survives_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let pending_capture = fixture.capture(&store, false)?;
    let pending_input = request("retained-pending");
    let pending = store.register_managed_attempt(&pending_capture, &pending_input, || Ok(()))?;
    let pending_evaluations = [
        fixture.evaluation(&pending_input, 10, Some(&pending_capture))?,
        fixture.evaluation(&pending_input, 11, Some(&pending_capture))?,
    ];
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store, false)?;
    let input = request("retained-complete");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    assert_eq!(stopped.progress, receipt.commit_revision);
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    assert_eq!(restarted.progress, receipt.commit_revision);
    assert_eq!(restarted.generation, fixture.instance.generation);
    let before = store.meta()?;
    let mut checked = false;
    let retried = store.register_managed_attempt(&captured, &input, || {
        checked = true;
        Ok(())
    })?;
    assert!(checked);
    assert_eq!(retried.receipt(), Some(&receipt));
    assert_eq!(store.meta()?, before);
    assert!(store
        .register_managed_attempt(&captured, &input, || Err(
            Code::Denied.error("retained receipt authority")
        ))
        .is_err());
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(fixture.current(&store)?, restarted);
    assert_eq!(
        store
            .active_managed(&AnalysisReadControl::default())?
            .1
            .as_slice(),
        &[ManagedMember {
            tenant: restarted.spec.tenant,
            id: restarted.spec.id.clone(),
            generation: restarted.generation,
            lifecycle: restarted.lifecycle,
        }]
    );
    let saved = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved completed attempt")?;
    assert_eq!(saved.receipt(), Some(&receipt));
    assert_eq!(saved.instance(), captured.instance());
    let selected = store
        .managed_selected(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved selected relation")?;
    assert_eq!(selected.commit_revision, receipt.commit_revision);
    assert_eq!(selected.data.batches, outputs[0].datasets[0].batches);
    for reference in receipt.results.values() {
        let result = store.managed_result(
            &fixture.instance,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(result.commit_revision, receipt.commit_revision);
        assert!(result.current);
        assert!(result.output.checkpoint.is_some());
        assert_eq!(result.output.evidence.len(), 1);
        assert_eq!(result.output.reasons.len(), 1);
    }
    let resumed = fixture.capture(&store, false)?;
    let next = request("after-lifecycle");
    for call in [10, 11] {
        let evaluation = fixture.evaluation(&next, call, Some(&resumed))?;
        assert_eq!(
            evaluation
                .checkpoint
                .as_ref()
                .ok_or("retained checkpoint")?
                .version,
            1
        );
    }
    let recovered = store
        .managed_attempt(
            [1; 16],
            "counter",
            &pending_input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved pending attempt")?;
    assert!(recovered.receipt().is_none());
    assert_eq!(recovered.instance(), pending_capture.instance());
    let before = store.meta()?;
    let error = fixture
        .publish(&store, &recovered, &pending_evaluations, &outputs)
        .err()
        .ok_or("recovered pending attempt published")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let error = fixture
        .publish(&store, &pending, &pending_evaluations, &outputs)
        .err()
        .ok_or("old live attempt published after reopen")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, restarted);
    Ok(())
}

#[test]
fn lifecycle_recovery_rejects_corruption() -> TestResult {
    for corruption in [
        "initial-running",
        "past-lifecycle",
        "future-lifecycle",
        "capture-lifecycle",
        "capture-running",
        "schema-column",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
        let captured = fixture.capture(&store, false)?;
        let input = request("corrupt-lifecycle");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        {
            let mut writer = store.writer()?;
            let writer = writer.get_mut()?;
            match corruption {
                "initial-running" => {
                    writer.execute(
                        "UPDATE managed_instances SET running = true, lifecycle = generation",
                        [],
                    )?;
                }
                "past-lifecycle" => {
                    writer.execute(
                        "UPDATE managed_instances SET lifecycle = generation - 1",
                        [],
                    )?;
                }
                "future-lifecycle" => {
                    writer.execute("UPDATE managed_instances SET lifecycle = (SELECT commit_revision + 1 FROM store_meta)", [])?;
                }
                "schema-column" => {
                    writer.execute("ALTER TABLE managed_instances DROP COLUMN lifecycle", [])?;
                }
                _ => {
                    let mut saved: model::Attempt = ManagedCodec::decode(&writer.query_row(
                        "SELECT contract FROM managed_attempts WHERE attempt_id = ?",
                        params![input.id],
                        |row| row.get::<_, Vec<u8>>(0),
                    )?)?;
                    if corruption == "capture-lifecycle" {
                        saved.capture.lifecycle = saved.capture.revision + 1;
                    } else {
                        saved.capture.running = false;
                    }
                    writer.execute(
                        "UPDATE managed_attempts SET contract = ? WHERE attempt_id = ?",
                        params![ManagedCodec::encode(&saved)?, input.id],
                    )?;
                }
            }
        }
        drop(store);
        assert!(
            AnalysisStore::open(&root).is_err(),
            "corruption {corruption}"
        );
    }
    Ok(())
}

#[test]
fn prior_schema_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE store_meta SET schema_version = ?",
            params![crate::analysis::ANALYSIS_SCHEMA_VERSION - 1],
        )?;
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}

#[test]
fn active_metadata_honors_cancel() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let control = AnalysisReadControl::default();
    control.cancel()?;
    assert!(matches!(
        store.active_managed(&control),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn idle_suspend_checks_fences() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let before = store.meta()?;
    for stale in [
        ManagedInstance {
            generation: running.generation + 1,
            ..running.clone()
        },
        ManagedInstance {
            lifecycle: running.lifecycle + 1,
            ..running.clone()
        },
        ManagedInstance {
            progress: running.progress + 1,
            ..running.clone()
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
        assert_eq!(fixture.current(&store)?, running);
        assert_eq!(store.meta()?, before);
    }
    let mut checked = false;
    assert!(matches!(
        store.suspend_managed(&running, || {
            checked = true;
            Err(Code::Denied.error("suspension callback"))
        }),
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(checked);
    assert_eq!(fixture.current(&store)?, running);
    assert_eq!(store.meta()?, before);
    let stopped = store.suspend_managed(&running, || Ok(()))?;
    assert!(!stopped.running);
    assert_eq!(stopped.progress, running.progress);
    assert_eq!(stopped.generation, running.generation);
    assert_eq!(stopped.spec, running.spec);
    assert!(stopped.lifecycle > running.lifecycle);
    assert!(matches!(
        store.suspend_managed(&running, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    Ok(())
}

#[test]
fn host_lease_is_exclusive() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("store"))?);
    let lease = store.lease_managed()?;
    assert!(matches!(
        store.lease_managed(),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed host owner",
            ..
        })
    ));
    drop(lease);
    drop(store.lease_managed()?);
    Ok(())
}

#[test]
fn active_membership_keeps_revision() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let (revision, members) = store.active_managed(&AnalysisReadControl::default())?;
    assert_eq!(revision, store.meta()?.commit_revision);
    assert!(running.lifecycle <= revision);
    assert_eq!(
        members,
        [ManagedMember {
            tenant: running.spec.tenant,
            id: running.spec.id.clone(),
            generation: running.generation,
            lifecycle: running.lifecycle
        }]
    );
    assert_eq!(fixture.current(&store)?, running);
    Ok(())
}
