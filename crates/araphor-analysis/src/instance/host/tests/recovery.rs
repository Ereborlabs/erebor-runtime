use super::*;
use araphor_data::{AnalysisSelectionV1, AnalysisTableRequests, ManagedRead, Selection};
use araphor_query::follow::Clock as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_capture_recovers_on_change() -> TestResult {
    for repair_before_status in [false, true] {
        let fixture = Fixture::new(araphor_query::execution::Limits {
            input_bytes: 64 * 1024,
            ..Default::default()
        })?;
        fixture.context(1)?;
        let instance = fixture
            .admit(
                "capture-recovery",
                "SELECT CAST(octet_length(CAST(body AS VARCHAR)) AS BIGINT UNSIGNED) AS value FROM context_versions",
            )
            .await?;
        let lifecycle = fixture.start(&instance)?;
        fixture.query.store().fault_write(
            "UPDATE context_versions SET body = repeat('x', 131072)::BLOB",
            &[],
        )?;
        let mut stream = instance.subscribe(
            Arc::new(AnalysisReadControl::default()),
            u64::MAX,
            lifecycle,
        )?;
        let failure = stream
            .next()
            .await
            .ok_or("capture failure absent")?
            .err()
            .ok_or("oversized capture accepted")?;
        assert_eq!(
            Subscription::failure(&failure),
            ManagedExit::Failed(Code::Limit)
        );
        if repair_before_status {
            fixture
                .query
                .store()
                .fault_write("UPDATE context_versions SET body = 'x'::BLOB", &[])?;
            fixture.context(2)?;
        }
        assert!(stream
            .cancel_and_join(&AnalysisReadControl::default())
            .await?
            .is_none());
        let failed = fixture.query.store().managed_resume(
            [1; 16],
            "capture-recovery",
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(failed.instance.progress, 0);
        assert_eq!(failed.completed, 0);
        assert!(fixture
            .query
            .store()
            .managed_history(
                &fixture.grant.selection,
                "capture-recovery",
                &AnalysisReadControl::default()
            )?
            .is_empty());
        let recovery =
            araphor_query::follow::SourceRecovery::take(&failure).ok_or("source wait absent")?;
        assert!(araphor_query::follow::SourceRecovery::take(&failure).is_none());
        let control = AnalysisReadControl::default();
        let waiting = recovery.changed(&control);
        tokio::pin!(waiting);
        if !repair_before_status {
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                    .await
                    .is_err()
            );
            fixture
                .query
                .store()
                .commit_context(&araphor_data::AnalysisContextVersionV1 {
                    key: araphor_data::AnalysisContextKeyV1 {
                        tenant_id: [2; 16],
                        owner_id: "other-tenant".into(),
                        entity_key: vec![1],
                        lifetime_key: vec![1],
                        owner_revision: 1,
                    },
                    valid_from_utc_ns: None,
                    valid_until_utc_ns: None,
                    sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                    body: vec![1],
                })?;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                    .await
                    .is_err()
            );
            assert_eq!(
                fixture.query.store().managed_resume(
                    [1; 16],
                    "capture-recovery",
                    &AnalysisReadControl::default()
                )?,
                failed
            );
            fixture
                .query
                .store()
                .fault_write("UPDATE context_versions SET body = 'x'::BLOB", &[])?;
            fixture.context(2)?;
        }
        tokio::time::timeout(Duration::from_secs(30), &mut waiting).await??;
        let mut stream = instance.subscribe(
            Arc::new(AnalysisReadControl::default()),
            u64::MAX,
            lifecycle,
        )?;
        let receipt = stream.next().await.ok_or("recovered result absent")??;
        assert_eq!(
            fixture.selected("capture-recovery", &receipt.attempt)?,
            [1, 1]
        );
        stream
            .cancel_and_join(&AnalysisReadControl::default())
            .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_recovers_source_capture() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_bytes: 64 * 1024,
        ..Default::default()
    })?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "capture-host",
            "SELECT CAST(octet_length(CAST(body AS VARCHAR)) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let prior = instance
        .run(
            crate::instance::tests::request("prior"),
            &AnalysisReadControl::default(),
        )
        .await?;
    fixture.context(2)?;
    fixture.query.store().fault_write(
        "UPDATE context_versions SET body = repeat('x', 131072)::BLOB",
        &[],
    )?;
    fixture.start(&instance)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let result: TestResult = async {
        let mut changes = fixture.query.store().subscribe_revision();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let status = fixture.query.store().managed_status(
                    &fixture.grant.selection,
                    "capture-host",
                    &AnalysisReadControl::default(),
                )?;
                if matches!(
                    status.readiness,
                    araphor_data::PackageReadinessV1::Failed {
                        code: Code::Limit,
                        ..
                    }
                ) {
                    break Ok::<_, araphor_data::Error>(());
                }
                changes
                    .changed()
                    .await
                    .map_err(|_| Code::Incomplete.error("source failure notice"))?;
            }
        })
        .await??;
        assert_eq!(fixture.progress("capture-host")?, prior.commit_revision);
        assert_eq!(fixture.selected("capture-host", &prior.attempt)?, [1]);
        fixture
            .query
            .store()
            .fault_write("UPDATE context_versions SET body = 'x'::BLOB", &[])?;
        fixture.context(3)?;
        fixture
            .host_progress("capture-host", prior.commit_revision)
            .await?;
        assert_eq!(
            fixture
                .query
                .store()
                .managed_history(
                    &fixture.grant.selection,
                    "capture-host",
                    &AnalysisReadControl::default()
                )?
                .len(),
            2
        );
        Ok(())
    }
    .await;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_recovers_failed_frontier() -> TestResult {
    for (mode, code, timed) in [
        ("trap", Code::Incomplete, false),
        ("limit", Code::Limit, false),
        ("limit", Code::Limit, true),
    ] {
        let fixture = Fixture::new(araphor_query::execution::Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            ..Default::default()
        })?;
        let mut image = bundle("wasm")?;
        let model = &mut image.artifacts[0].descriptor.exports[0];
        model.name = "evaluate".into();
        model.inputs.clear();
        model.checkpoint = None;
        model.parameters = sdk::Schema::new(vec![
            sdk::Field::new("mode", sdk::DataType::Utf8, false),
            sdk::Field::new("amount", sdk::DataType::UInt64, false),
        ]);
        let araphor_package::PackageImplementationV1::Wasm { exports, .. } =
            &mut image.artifacts[0].implementations[0]
        else {
            return Err("recovery Wasm fixture".into());
        };
        *exports = vec!["evaluate".into()];
        fixture.install(&image)?;
        if !timed {
            fixture.context(1)?;
        }
        let amount = if timed {
            "(SELECT COUNT(*) FROM events WHERE received_at >= now() - INTERVAL '5 seconds')"
        } else {
            "(SELECT COALESCE(MAX(owner_revision), 0) FROM context_versions)"
        };
        let mode = if timed {
            format!("CASE WHEN {amount} > 0 THEN '{mode}' ELSE 'echo' END")
        } else {
            format!("CASE WHEN {amount} = 2 THEN '{mode}' WHEN {amount} = 4 THEN 'cancel' ELSE 'echo' END")
        };
        let instance = fixture.admit("source-recovery", &format!(
            r#"SELECT * FROM "runtime-fixture"."1".evaluate(mode => ({mode}), amount => CAST({amount} AS BIGINT UNSIGNED))"#
        )).await?;
        let clock = araphor_query::follow::SystemClock::default();
        let mut request = crate::instance::tests::request("prior-output");
        request.time_utc_ns = clock.now_ns()?;
        let prior = instance
            .run(request, &AnalysisReadControl::default())
            .await?;
        assert_eq!(
            fixture.selected("source-recovery", &prior.attempt)?,
            [u64::from(!timed)]
        );
        if timed {
            let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
                operation: 7,
                ..Default::default()
            })?;
            fixture.query.store().accept_validated_batch(
                araphor_data::EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "recovery-clock".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 1,
                    source_id: [3; 16],
                    source_epoch: 1,
                },
                araphor_data::ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: clock.now_ns()?,
                    frame_ends: vec![frame.len()],
                    framed_records: frame.into(),
                },
            )?;
        } else {
            fixture.context(2)?;
        }
        let lifecycle = fixture.start(&instance)?;
        let generation = instance.admitted().generation;
        let authority = Authority::new(&fixture);
        let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
        let mut changes = fixture.query.store().subscribe_revision();
        let (stop, stopped) = watch::channel(false);
        let mut worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
        let failed = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match fixture.query.store().managed_status(
                    &fixture.grant.selection,
                    "source-recovery",
                    &AnalysisReadControl::default(),
                ) {
                    Ok(status) => {
                        if matches!(status.readiness, araphor_data::PackageReadinessV1::Failed { code: found, .. } if found == code) {
                            break fixture.query.store().managed_resume(
                                [1; 16], "source-recovery", &AnalysisReadControl::default()
                            );
                        }
                    }
                    Err(araphor_data::Error::Package {
                        code: Code::Incomplete,
                        field: "managed pending attempt",
                        ..
                    }) => {}
                    Err(error) => return Err(error),
                }
                changes.changed().await.map_err(|_| Code::Incomplete.error("recovery failure notice"))?;
            }
        }).await;
        let recovered: TestResult<_> = async {
            let failed = failed??;
            assert_eq!(failed.instance.generation, generation);
            assert_eq!(failed.instance.lifecycle, lifecycle);
            assert_eq!(failed.instance.progress, prior.commit_revision);
            assert!(failed.instance.running);
            assert!(failed.completed > prior.commit_revision);
            let frontier = failed.frontier.as_ref().ok_or("failed native frontier")?;
            if timed {
                let expiry = frontier.next_change.ok_or("failed source deadline")?;
                assert!(clock.now_ns()? < expiry);
            } else {
                let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
                selection.contexts = Selection::All;
                let tables = AnalysisTableRequests::from([("context_versions".into(), None)]);
                for unrelated in [false, true] {
                    if unrelated {
                        fixture.query.store().commit_context(
                            &araphor_data::AnalysisContextVersionV1 {
                                key: araphor_data::AnalysisContextKeyV1 {
                                    tenant_id: [2; 16],
                                    owner_id: "instance-context".into(),
                                    entity_key: vec![1],
                                    lifetime_key: vec![1],
                                    owner_revision: 3,
                                },
                                valid_from_utc_ns: None,
                                valid_until_utc_ns: None,
                                sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                                body: vec![3],
                            },
                        )?;
                        fixture.reader_event()?;
                    }
                    let (_, revision) = fixture.query.store().managed_dependency_revision(
                        &selection,
                        &tables,
                        &ManagedRead {
                            execution: None,
                            instance: failed.instance.clone(),
                            expected: None,
                            rebuild: false,
                            completed: Some(failed.completed),
                            follow: true,
                        },
                        araphor_data::AnalysisExtractLimits::default(),
                        &AnalysisReadControl::default(),
                    )?;
                    assert!(
                        revision
                            <= araphor_query::follow::Cursor::decode(&frontier.cursor)?
                                .read_revision()
                    );
                    assert_eq!(
                        fixture.query.store().managed_resume(
                            [1; 16],
                            "source-recovery",
                            &AnalysisReadControl::default()
                        )?,
                        failed
                    );
                }
                fixture.context(3)?;
            }
            let progress = fixture
                .host_progress("source-recovery", prior.commit_revision)
                .await?;
            let receipts = fixture.query.store().managed_history(
                &fixture.grant.selection,
                "source-recovery",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(receipts.len(), 2);
            let current = receipts
                .iter()
                .find(|receipt| receipt.commit_revision == progress)
                .ok_or("recovered receipt")?;
            assert_eq!(
                fixture.selected("source-recovery", &prior.attempt)?,
                [u64::from(!timed)]
            );
            assert_eq!(
                fixture.selected("source-recovery", &current.attempt)?,
                [if timed { 0 } else { 3 }]
            );
            let evaluation = fixture.query.store().managed_evaluation(
                instance.admitted(),
                &current
                    .results
                    .values()
                    .next()
                    .ok_or("recovered Call")?
                    .result_id,
                &AnalysisReadControl::default(),
            )?;
            let parameters = evaluation
                .parameters
                .as_ref()
                .ok_or("recovered parameters")?;
            let amount = parameters
                .column(1)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("recovered scalar")?;
            assert_eq!(amount.values().as_ref(), &[if timed { 0 } else { 3 }]);
            let saved = fixture
                .query
                .store()
                .managed_attempt(
                    [1; 16],
                    "source-recovery",
                    &current.attempt,
                    &AnalysisReadControl::default(),
                )?
                .ok_or("recovered attempt")?;
            assert_eq!(
                evaluation.context.time_utc_ns as u64,
                saved.request().time_utc_ns
            );
            if timed {
                assert!(
                    saved.request().time_utc_ns >= frontier.next_change.ok_or("source expiry")?
                );
                assert_eq!(
                    current
                        .frontier
                        .as_ref()
                        .ok_or("recovered frontier")?
                        .next_change,
                    None
                );
            } else {
                let (entered, observed) = mpsc::channel();
                let (release, released) = mpsc::channel();
                fixture.query.guest_entry(entered, Some(released))?;
                fixture.context(4)?;
                let entered = tokio::task::spawn_blocking(move || {
                    observed.recv_timeout(Duration::from_secs(30))
                })
                .await
                .map_err(|error| format!("recovery {code:?} cancel task: {error}"))?;
                entered.map_err(|error| format!("recovery {code:?} cancel entry: {error}"))?;
                if code == Code::Incomplete {
                    stop.send_replace(true);
                } else {
                    authority.deny(&instance.admitted().grant.principal);
                }
                assert!(!worker.is_finished());
                assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
                release
                    .send(())
                    .map_err(|error| format!("recovery {code:?} cancel release: {error}"))?;
                if code == Code::Limit {
                    let suspended = fixture.host_stopped("source-recovery").await?;
                    assert_eq!(suspended.progress, progress);
                    assert_eq!(suspended.generation, generation);
                }
            }
            Ok(progress)
        }
        .await;
        stop.send_replace(true);
        let joined = tokio::time::timeout(Duration::from_secs(30), &mut worker).await;
        let progress = recovered?;
        joined???;
        assert_eq!(fixture.progress("source-recovery")?, progress);
        assert_eq!(
            fixture
                .query
                .store()
                .managed_history(
                    &fixture.grant.selection,
                    "source-recovery",
                    &AnalysisReadControl::default()
                )?
                .len(),
            2
        );
        drop(fixture.query.reserve_evaluation([1; 16])?);
        drop(fixture.query.store().lease_managed()?);
    }
    Ok(())
}
