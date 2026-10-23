use erebor_runtime_error::ErrorExt as _;

use super::*;

impl Fixture {
    pub(super) fn reader_event(&self) -> TestResult {
        let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        self.query.store().accept_validated_batch(
            araphor_data::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "host-reader".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    async fn hold_reader(
        &self,
    ) -> TestResult<(
        mpsc::Sender<()>,
        tokio::task::JoinHandle<araphor_data::Result<araphor_data::AnalysisPositionPageV1>>,
    )> {
        let control = AnalysisReadControl::default();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, released) = mpsc::channel();
        control.on_read_step(move || {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("reader entry"))?;
            released
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("reader release"))?;
            Ok(())
        })?;
        let store = Arc::clone(self.query.store());
        let worker = tokio::task::spawn_blocking(move || {
            let columns = (0..araphor_data::AnalysisStore::table_schemas()["events"]
                .fields()
                .len())
                .collect();
            let requests = std::collections::BTreeMap::from([("events".into(), Some(columns))]);
            store.read_tables(
                &araphor_data::AnalysisSelectionV1::tenant([1; 16]),
                araphor_data::AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    inputs: None,
                    mode: araphor_data::AnalysisReadModeV1::Complete,
                    now: 1,
                },
                araphor_data::AnalysisExtractLimits::default(),
                &control,
            )
        });
        tokio::time::timeout(Duration::from_secs(30), observed).await??;
        Ok((release, worker))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_waits_reader() -> TestResult {
    for cancel in [false, true] {
        let fixture = Fixture::storage(
            Default::default(),
            araphor_data::StorageLimitsV1 {
                reader_admissions: Some(2),
                ..Default::default()
            },
        )?;
        fixture.reader_event()?;
        let instance = fixture
            .admit(
                "reader-opening",
                "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
            )
            .await?;
        let lifecycle = fixture.start(&instance)?;
        let generation = instance.admitted().generation;
        drop(instance);
        let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
        let control = Arc::new(AnalysisReadControl::default());
        let (_, mut active) = host.membership(Arc::clone(&control)).await?;
        assert_eq!(active.len(), 1);
        let member = active.pop().ok_or("reader projected key")?;
        let bytes = std::mem::size_of::<ManagedMember>() + member.id.capacity();
        let expected = Arc::new((member, fixture.query.memory().reserve_input(bytes)?));
        let mut first = Some(fixture.hold_reader().await?);
        let (second, second_worker) = fixture.hold_reader().await?;
        assert!(matches!(
            fixture
                .query
                .store()
                .managed_instance([1; 16], "reader-opening", &control),
            Err(araphor_data::Error::AnalysisBusy {
                resource: "reader",
                ..
            })
        ));
        let result = {
            let opening = host.open_member(&expected, &control);
            tokio::pin!(opening);
            assert!(futures_util::poll!(opening.as_mut()).is_pending());
            if cancel {
                control.cancel()?;
            } else {
                let (release, worker) = first.take().ok_or("first reader")?;
                release.send(())?;
                assert_eq!(worker.await??.tables["events"][0].num_rows(), 1);
            }
            tokio::time::timeout(Duration::from_secs(30), opening).await?
        };
        if cancel {
            let error = result.err().ok_or("cancelled reader opening succeeded")?;
            assert_eq!(error.status_code(), StatusCode::Cancelled);
        } else {
            let owner = result?;
            assert_eq!(owner.admitted().generation, generation);
            assert_eq!(owner.admitted().lifecycle, lifecycle);
            assert_eq!(owner.admitted().progress, 0);
            drop(owner);
        }
        if let Some((release, worker)) = first {
            release.send(())?;
            assert_eq!(worker.await??.tables["events"][0].num_rows(), 1);
        }
        second.send(())?;
        assert_eq!(second_worker.await??.tables["events"][0].num_rows(), 1);
        assert_eq!(fixture.progress("reader-opening")?, 0);
        drop(expected);
        assert_eq!(fixture.query.memory().input_reserved(), 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_waits_capacity() -> TestResult {
    for action in ["release", "stop", "deny"] {
        let capacity = 1024 * 1024;
        let fixture = Fixture::new(araphor_query::execution::Limits {
            input_capacity: Some(capacity),
            ..Default::default()
        })?;
        fixture.install(&bundle("sql")?)?;
        let instance = fixture.admit("pressure-opening", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#).await?;
        fixture.start(&instance)?;
        drop(instance);
        let authority = Authority::new(&fixture);
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *authority.gate.lock().map_err(|_| "admission gate lock")? = Some((entered, released));
        let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
        let (stop, stopped) = watch::channel(false);
        let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
            .await??;
        let before = fixture.query.store().meta()?;
        let memory = fixture.query.memory().scope();
        let pressure = fixture.query.memory().reserve_input(
            capacity
                .checked_sub(fixture.query.memory().input_reserved())
                .ok_or("opening pressure")?,
        )?;
        let epoch = memory.capacity_epoch();
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(30), memory.capacity_changed(epoch))
            .await
            .map_err(|error| format!("admission {action} capacity notice: {error}"))??;
        assert_eq!(authority.admissions.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(fixture.progress("pressure-opening")?, 0);
        match action {
            "release" => {
                drop(pressure);
                fixture
                    .host_progress("pressure-opening", 0)
                    .await
                    .map_err(|error| format!("admission {action} progress: {error}"))?;
                assert_eq!(authority.admissions.load(Ordering::SeqCst), 2);
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker)
                    .await
                    .map_err(|error| format!("admission {action} host join: {error}"))???;
            }
            "stop" => {
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker)
                    .await
                    .map_err(|error| format!("admission {action} host join: {error}"))???;
                assert_eq!(fixture.query.store().meta()?, before);
                drop(pressure);
            }
            "deny" => {
                authority.deny(&fixture.grant.principal);
                let stopped = fixture
                    .host_stopped("pressure-opening")
                    .await
                    .map_err(|error| format!("admission {action} suspension: {error}"))?;
                assert_eq!(stopped.progress, 0);
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker)
                    .await
                    .map_err(|error| format!("admission {action} host join: {error}"))???;
                drop(pressure);
            }
            _ => return Err("opening action".into()),
        }
        drop(host);
        drop(fixture.query.store().lease_managed()?);
        drop(fixture.query.memory().reserve_input(capacity)?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assembly_waits_reader() -> TestResult {
    let fixture = Fixture::storage(
        Default::default(),
        araphor_data::StorageLimitsV1 {
            reader_admissions: Some(2),
            ..Default::default()
        },
    )?;
    fixture.reader_event()?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("reader-assembly", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(11 AS BIGINT UNSIGNED) AS value))"#).await?;
    fixture.start(&instance)?;
    drop(instance);
    let authority = Authority::new(&fixture);
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    *authority.gate.lock().map_err(|_| "assembly gate lock")? = Some((entered, released));
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await??;
    let (first, first_worker) = fixture.hold_reader().await?;
    let (second, second_worker) = fixture.hold_reader().await?;
    let (entered, observed) = tokio::sync::oneshot::channel();
    *authority
        .reader_busy
        .lock()
        .map_err(|_| "reader signal lock")? = Some(entered);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(30), observed).await??;
    first.send(())?;
    assert_eq!(first_worker.await??.tables["events"][0].num_rows(), 1);
    fixture.host_progress("reader-assembly", 0).await?;
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 1);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    second.send(())?;
    assert_eq!(second_worker.await??.tables["events"][0].num_rows(), 1);
    drop(host);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn opening_keeps_unknown_busy() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        input_capacity: Some(capacity),
        ..Default::default()
    })?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let permit = fixture.query.reserve_evaluation([1; 16])?;
    let busy = fixture
        .query
        .reserve_evaluation([1; 16])
        .err()
        .ok_or("evaluation pressure")?;
    assert_eq!(
        araphor_query::Failure::from(&busy),
        araphor_query::Failure::Busy
    );
    let limit = araphor_query::Error::Sql {
        source: fixture
            .query
            .memory()
            .reserve_input(capacity + 1)
            .err()
            .ok_or("fixed input bound")?,
    };
    assert_eq!(
        araphor_query::Failure::from(&limit),
        araphor_query::Failure::InputTooLarge
    );
    let before = fixture.query.store().meta()?;
    let memory = fixture.query.memory().scope();
    for error in [
        crate::Error::from(busy),
        crate::Error::from(limit),
        crate::Error::from(Code::Incomplete.error("managed pending attempt")),
    ] {
        assert!(
            !tokio::time::timeout(
                Duration::from_secs(30),
                host.wait_open(
                    &error,
                    &AnalysisReadControl::default(),
                    &memory,
                    memory.capacity_epoch(),
                )
            )
            .await??
        );
    }
    assert_eq!(fixture.query.store().meta()?, before);
    drop(permit);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(fixture.query.memory().reserve_input(capacity)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_waits_component_cache() -> TestResult {
    let mut limits = araphor_query::execution::Limits {
        global_evaluations: Some(2),
        tenant_evaluations: Some(2),
        ..Default::default()
    };
    limits.package.wasm.cache_entries = Some(1);
    let fixture = Fixture::new(limits)?;
    let held = fixture.terminal_instance("cache-held", "cancel").await?;
    let mut image = bundle("wasm")?;
    image.root.revision = "2".into();
    let artifact = &mut image.artifacts[0];
    artifact.descriptor.revision = "2".into();
    let model = &mut artifact.descriptor.exports[0];
    model.name = "evaluate".into();
    model.inputs.clear();
    model.checkpoint = None;
    model.parameters = sdk::Schema::new(vec![
        sdk::Field::new("mode", sdk::DataType::Utf8, false),
        sdk::Field::new("amount", sdk::DataType::UInt64, false),
    ]);
    let araphor_package::PackageImplementationV1::Wasm {
        exports, artifact, ..
    } = &mut artifact.implementations[0]
    else {
        return Err("cache Wasm fixture".into());
    };
    *exports = vec!["evaluate".into()];
    // A custom section gives this component a different code digest.
    artifact.extend_from_slice(&[0, 2, 1, b'x']);
    fixture.install(&image)?;
    let waiting = fixture
        .admit(
            "cache-waiting",
            r#"SELECT * FROM "runtime-fixture"."2".evaluate(mode => 'echo', amount => 7)"#,
        )
        .await?;
    let (entry, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(released))?;
    let control = Arc::new(AnalysisReadControl::default());
    let stage = Arc::clone(&control);
    let worker = tokio::spawn(async move {
        held.run(crate::instance::tests::request("cache-held"), &stage)
            .await
    });
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        control.cancel()?;
        let result = worker.await?;
        return Err(format!("cache guest entry failed: {error}; execution: {result:?}").into());
    }
    let before = fixture.query.store().meta()?;
    let busy = waiting
        .run(
            crate::instance::tests::request("cache-busy"),
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("pinned cache entry was evicted")?;
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&busy);
    let mut requested = None;
    while let Some(error) = source {
        if let Some(araphor_query::PackageRuntimeError::AnalysisBusy {
            resource: "component cache capacity",
            requested: bytes,
            ..
        }) = error.downcast_ref::<araphor_query::PackageRuntimeError>()
        {
            requested = Some(*bytes);
        }
        source = error.source();
    }
    let requested = requested.ok_or("original component cache Busy")?;
    assert!(requested > 0);
    assert_eq!(
        InstanceHost::open_resource(&busy),
        Some(("component cache capacity", requested))
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("cache-waiting")?, 0);
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "cache-waiting",
            "cache-busy",
            &AnalysisReadControl::default(),
        )?
        .is_none());
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let memory = fixture.query.memory().scope();
    let cancelled = AnalysisReadControl::default();
    {
        let wait = host.wait_open(&busy, &cancelled, &memory, memory.capacity_epoch());
        tokio::pin!(wait);
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
        cancelled.cancel()?;
        let error = wait.await.err().ok_or("cancelled cache wait succeeded")?;
        assert_eq!(error.status_code(), StatusCode::Cancelled);
    }
    let read = AnalysisReadControl::default();
    {
        let wait = host.wait_open(&busy, &read, &memory, memory.capacity_epoch());
        tokio::pin!(wait);
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
        assert!(!worker.is_finished());
        control.cancel()?;
        assert!(!worker.is_finished());
        release.send(())?;
        let error = tokio::time::timeout(Duration::from_secs(30), worker)
            .await??
            .err()
            .ok_or("cancelled cache guest published")?;
        assert_eq!(error.status_code(), StatusCode::Cancelled);
        assert!(tokio::time::timeout(Duration::from_secs(30), wait).await??);
    }
    let receipt = waiting
        .run(crate::instance::tests::request("cache-retry"), &read)
        .await?;
    assert_eq!(fixture.selected("cache-waiting", &receipt.attempt)?, [7]);
    let permits = [
        fixture.query.reserve_evaluation([1; 16])?,
        fixture.query.reserve_evaluation([1; 16])?,
    ];
    drop(permits);
    Ok(())
}

#[tokio::test]
async fn preparation_failure_keeps_intent() -> TestResult {
    let mut fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let failed = fixture
        .admit("a-preparation", "SELECT 1 AS value, 2 AS other")
        .await?;
    let healthy = fixture
        .admit(
            "z-preparation",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let prior = failed
        .run(
            araphor_data::ManagedRequest {
                id: "before-preparation".into(),
                time_utc_ns: 10,
                seed: Some(7),
                rebuild: false,
                witness_expiry: u64::MAX,
                frontier: None,
            },
            &AnalysisReadControl::default(),
        )
        .await?;
    let lifecycle = fixture.start(&failed)?;
    fixture.start(&healthy)?;
    let expected = fixture
        .query
        .store()
        .managed_instance([1; 16], "a-preparation", &AnalysisReadControl::default())?
        .ok_or("preparation member absent")?;
    drop(failed);
    drop(healthy);
    fixture.query = Engine::new(
        Arc::clone(fixture.query.store()),
        araphor_query::execution::Limits {
            projection_columns: Some(1),
            ..Default::default()
        },
    )?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let mut changes = fixture.query.store().subscribe_revision();
    let failed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let saved = fixture.query.store().managed_status(
                &fixture.grant.selection,
                "a-preparation",
                &AnalysisReadControl::default(),
            )?;
            if matches!(
                saved.readiness,
                araphor_data::PackageReadinessV1::Failed {
                    code: Code::Invalid,
                    ..
                }
            ) {
                break Ok::<_, crate::Error>(saved);
            }
            changes
                .changed()
                .await
                .map_err(|_| Code::Incomplete.error("preparation failure notice"))?;
        }
    })
    .await??;
    assert_eq!(failed.instance, expected);
    assert!(failed.instance.running);
    assert_eq!(failed.instance.lifecycle, lifecycle);
    assert_eq!(failed.status_progress, prior.commit_revision);
    let resume = fixture.query.store().managed_resume(
        [1; 16],
        "a-preparation",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(resume.completed, prior.commit_revision);
    assert!(resume.frontier.is_some());
    let first = fixture.host_progress("z-preparation", 0).await?;
    fixture.context(2)?;
    let second = fixture.host_progress("z-preparation", first).await?;
    assert_eq!(fixture.progress("a-preparation")?, prior.commit_revision);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(host);
    let Fixture {
        directory,
        query,
        authority: _,
        grant,
    } = fixture;
    drop(changes);
    drop(query);
    let reopened = araphor_data::AnalysisStore::open(directory.path().join("data"))?;
    let saved = reopened.managed_status(
        &grant.selection,
        "a-preparation",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(saved.instance, expected);
    assert!(matches!(
        saved.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    assert_eq!(saved.status_progress, prior.commit_revision);
    assert_eq!(
        reopened
            .managed_resume([1; 16], "a-preparation", &AnalysisReadControl::default())?
            .completed,
        prior.commit_revision
    );
    assert_eq!(
        reopened
            .managed_selected(
                [1; 16],
                "a-preparation",
                "before-preparation",
                &AnalysisReadControl::default()
            )?
            .ok_or("prior output after preparation failure")?
            .commit_revision,
        prior.commit_revision
    );
    assert_eq!(
        reopened
            .managed_instance([1; 16], "z-preparation", &AnalysisReadControl::default())?
            .ok_or("healthy member after reopen")?
            .progress,
        second
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_waits_output_capacity() -> TestResult {
    use sdk::arrow_array::Array as _;

    for cancel in [false, true] {
        const OUTPUT: usize = 64 * 1024;
        let fixture = Fixture::new(araphor_query::execution::Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            output_capacity: Some(OUTPUT),
            ..Default::default()
        })?;
        fixture.reader_event()?;
        let owner = fixture
            .admit("stream-capacity", "SELECT source_cursor FROM events")
            .await?;
        let lifecycle = fixture.start(&owner)?;
        let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
        let control = Arc::new(AnalysisReadControl::default());
        let (_, mut active) = host.membership(Arc::clone(&control)).await?;
        let member = active.pop().ok_or("capacity member")?;
        assert!(active.is_empty());
        let bytes = std::mem::size_of::<ManagedMember>() + member.id.capacity();
        let expected = Arc::new((member, fixture.query.memory().reserve_input(bytes)?));
        let count = sdk::arrow_array::UInt64Array::from(vec![0_u64]);
        let mut pressure = Some(
            fixture.query.memory().reserve_output(
                OUTPUT
                    .checked_sub(count.get_buffer_memory_size())
                    .ok_or("count buffer")?,
            )?,
        );
        let before = fixture.query.store().meta()?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, released) = mpsc::channel();
        control.on_read_step(move || {
            entered
                .send(())
                .map_err(|_| Code::Incomplete.error("stream source entry"))?;
            released
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Code::Incomplete.error("stream source release"))?;
            Ok(())
        })?;
        let serving = Arc::clone(&host);
        let selected = Arc::clone(&expected);
        let operation = Arc::clone(&control);
        let prepared = Arc::clone(&owner);
        let worker = tokio::spawn(async move {
            serving
                .member(&selected, &operation, u64::MAX, Some(prepared))
                .await
        });
        tokio::time::timeout(Duration::from_secs(30), observed).await??;
        assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
        release.send(())?;
        let joined = tokio::time::timeout(
            Duration::from_secs(30),
            fixture.query.acquire_evaluation([1; 16]),
        )
        .await??;
        assert_eq!(fixture.query.store().meta()?, before);
        let saved = fixture.query.store().managed_status(
            &fixture.grant.selection,
            "stream-capacity",
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(saved.instance.lifecycle, lifecycle);
        assert_eq!(saved.instance.progress, 0);
        assert!(saved.instance.running);
        assert!(matches!(
            saved.readiness,
            araphor_data::PackageReadinessV1::Ready
        ));
        let resume = fixture.query.store().managed_resume(
            [1; 16],
            "stream-capacity",
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(resume.completed, 0);
        assert!(resume.frontier.is_none());
        drop(joined);
        if cancel {
            control.cancel()?;
        } else {
            drop(pressure.take());
            fixture.host_progress("stream-capacity", 0).await?;
            control.cancel()?;
        }
        tokio::time::timeout(Duration::from_secs(30), worker).await???;
        if cancel {
            assert_eq!(fixture.query.store().meta()?, before);
            assert_eq!(fixture.progress("stream-capacity")?, 0);
            drop(pressure.take());
        }
        drop(expected);
        drop(owner);
        drop(host);
        assert_eq!(fixture.query.memory().input_reserved(), 0);
        drop(fixture.query.memory().reserve_output(OUTPUT)?);
        drop(fixture.query.reserve_evaluation([1; 16])?);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_busy_retries_capacity() -> TestResult {
    use crate::instance::tests::version::JoinedInput;

    const OUTPUT: usize = 64 * 1024;
    for action in ["release", "source", "finite", "cancel"] {
        let fixture = Fixture::new(araphor_query::execution::Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            output_capacity: Some(OUTPUT),
            ..Default::default()
        })?;
        fixture.context(1)?;
        let control = Arc::new(AnalysisReadControl::default());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let input = Arc::new(JoinedInput {
            schema: Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::UInt64,
                false,
            )])),
            wait: Mutex::new(None),
        });
        let memory = fixture.query.memory().scope();
        let mut session = fixture.query.session_on(
            fixture.grant.selection.clone(),
            &control,
            0,
            Arc::clone(&memory),
        )?;
        let partition: Arc<dyn datafusion::physical_plan::streaming::PartitionStream> =
            input.clone();
        session.register_table(
            "joined_input",
            Arc::new(datafusion::catalog::streaming::StreamingTable::try_new(
                Arc::clone(&input.schema),
                vec![partition],
            )?),
        )?;
        let sql = if action == "cancel" {
            "SELECT CAST((SELECT MAX(owner_revision) FROM context_versions) AS BIGINT UNSIGNED) AS value FROM joined_input CROSS JOIN range(4096) WHERE (SELECT MAX(owner_revision) FROM context_versions) <= 3"
        } else {
            "SELECT joined_input.value FROM joined_input CROSS JOIN range(4096) WHERE (SELECT MAX(owner_revision) FROM context_versions) = 1"
        };
        let prepared = session
            .prepare_definition(&Fixture::definition(sql))
            .await?;
        fixture
            .query
            .store()
            .admit_definition([1; 16], prepared.resolved(), || Ok(()))?;
        let authority = Authority::new(&fixture);
        let gate = || -> TestResult<(mpsc::Receiver<()>, mpsc::Sender<()>)> {
            let (entry, observed) = mpsc::channel();
            let (release, released) = mpsc::channel();
            *authority
                .delivery
                .lock()
                .map_err(|_| "capacity native gate")? = Some((entry, released));
            Ok((observed, release))
        };
        let owner = Instance::admit_prepared(
            session,
            authority.clone(),
            fixture.grant.clone(),
            "admitted-capacity".into(),
            prepared,
            araphor_data::ManagedDestination::Selected,
        )
        .await?;
        let prior = if action == "cancel" {
            let receipt = owner
                .run(
                    crate::instance::tests::request("capacity-prior"),
                    &AnalysisReadControl::default(),
                )
                .await?;
            assert_eq!(
                fixture.selected("admitted-capacity", &receipt.attempt)?,
                vec![1; 4096]
            );
            fixture.context(2)?;
            Some(receipt)
        } else {
            None
        };
        let prior_progress = prior.as_ref().map_or(0, |receipt| receipt.commit_revision);
        *input.wait.lock().map_err(|_| "capacity input gate")? = Some((entered, released));
        let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
        let lifecycle = owner.admitted().lifecycle;
        let owner = host.start(owner, lifecycle, &control).await?;
        let lifecycle = owner.admitted().lifecycle;
        let (_, mut active) = host.membership(Arc::clone(&control)).await?;
        let member = active.pop().ok_or("admitted capacity member")?;
        assert!(active.is_empty());
        let bytes = std::mem::size_of::<ManagedMember>() + member.id.capacity();
        let expected = Arc::new((member, fixture.query.memory().reserve_input(bytes)?));
        let serving = Arc::clone(&host);
        let selected = Arc::clone(&expected);
        let operation = Arc::clone(&control);
        let prepared = Arc::clone(&owner);
        let worker = tokio::spawn(async move {
            serving
                .member(&selected, &operation, u64::MAX, Some(prepared))
                .await
        });
        tokio::time::timeout(Duration::from_secs(30), observed).await??;
        assert!(matches!(
            fixture.query.store().managed_resume(
                [1; 16],
                "admitted-capacity",
                &AnalysisReadControl::default(),
            ),
            Err(araphor_data::Error::Package {
                code: Code::Incomplete,
                field: "managed pending attempt",
                ..
            })
        ));
        let pressure = fixture.query.memory().reserve_output(OUTPUT - 4096)?;
        let epoch = memory.capacity_epoch();
        let mut changes = fixture.query.store().subscribe_revision();
        let reopen = if action == "finite" {
            Some(gate()?)
        } else {
            None
        };
        release.send(()).map_err(|_| "admitted input release")?;
        let failed = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match fixture.query.store().managed_resume(
                    [1; 16],
                    "admitted-capacity",
                    &AnalysisReadControl::default(),
                ) {
                    Ok(resume) if resume.completed > prior_progress => break Ok(resume),
                    Ok(_) => {}
                    Err(araphor_data::Error::Package {
                        code: Code::Incomplete,
                        field: "managed pending attempt",
                        ..
                    }) => {}
                    Err(error) => break Err(error),
                }
                changes
                    .changed()
                    .await
                    .map_err(|_| Code::Incomplete.error("admitted capacity failure notice"))?;
            }
        })
        .await??;
        assert_eq!(failed.instance.lifecycle, lifecycle);
        assert_eq!(failed.instance.generation, owner.admitted().generation);
        assert_eq!(failed.instance.progress, prior_progress);
        assert!(failed.instance.running);
        assert!(failed.frontier.is_some());
        assert_eq!(memory.capacity_epoch(), epoch);
        assert!(!worker.is_finished());
        let status = fixture.query.store().managed_status(
            &fixture.grant.selection,
            "admitted-capacity",
            &AnalysisReadControl::default(),
        )?;
        assert!(matches!(
            status.readiness,
            araphor_data::PackageReadinessV1::Failed {
                code: Code::Incomplete,
                ..
            }
        ));
        assert_eq!(
            fixture.query.store().managed_history(
                &fixture.grant.selection,
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?,
            prior.clone().into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            fixture.query.store().managed_resume(
                [1; 16],
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?,
            failed
        );
        if action == "cancel" {
            let prior = prior.as_ref().ok_or("capacity prior receipt")?;
            let (entered, observed) = tokio::sync::oneshot::channel();
            let (mut release, released) = tokio::sync::oneshot::channel();
            *input.wait.lock().map_err(|_| "capacity fresh input gate")? =
                Some((entered, released));
            fixture.context(3)?;
            tokio::time::timeout(Duration::from_secs(30), observed).await??;
            assert!(matches!(
                fixture.query.store().managed_resume(
                    [1; 16],
                    "admitted-capacity",
                    &AnalysisReadControl::default(),
                ),
                Err(araphor_data::Error::Package {
                    code: Code::Incomplete,
                    field: "managed pending attempt",
                    ..
                })
            ));
            let (observed, release_open) = gate()?;
            drop(pressure);
            tokio::time::timeout(Duration::from_secs(30), release.closed()).await?;
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await??;
            let cancelled = fixture.query.store().managed_resume(
                [1; 16],
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?;
            assert!(cancelled.completed > failed.completed);
            assert_eq!(cancelled.instance.progress, prior.commit_revision);
            assert_eq!(cancelled.instance.lifecycle, lifecycle);
            assert_eq!(cancelled.instance.generation, failed.instance.generation);
            assert!(cancelled.instance.running);
            assert_eq!(cancelled.frontier, prior.frontier);
            assert_eq!(
                fixture.query.store().managed_history(
                    &fixture.grant.selection,
                    "admitted-capacity",
                    &AnalysisReadControl::default(),
                )?,
                std::slice::from_ref(prior)
            );
            release_open.send(())?;
            let progress = fixture
                .host_progress("admitted-capacity", prior.commit_revision)
                .await?;
            let history = fixture.query.store().managed_history(
                &fixture.grant.selection,
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(history.len(), 2);
            assert_eq!(history.first(), Some(prior));
            let receipt = history.last().ok_or("capacity fresh receipt")?;
            assert_eq!(receipt.commit_revision, progress);
            assert_eq!(
                fixture.selected("admitted-capacity", &prior.attempt)?,
                vec![1; 4096]
            );
            assert_eq!(
                fixture.selected("admitted-capacity", &receipt.attempt)?,
                vec![3; 4096]
            );
        } else if action == "finite" {
            let (observed, release) = reopen.ok_or("capacity reopen gate")?;
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await??;
            fixture.context(2)?;
            let receipt = owner
                .run(
                    crate::instance::tests::request("capacity-finite"),
                    &AnalysisReadControl::default(),
                )
                .await?;
            assert!(fixture
                .selected("admitted-capacity", &receipt.attempt)?
                .is_empty());
            let (observed, release_next) = gate()?;
            drop(pressure);
            release.send(())?;
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await??;
            let release_open = match fixture.query.reserve_evaluation([1; 16]) {
                Ok(permit) => {
                    drop(permit);
                    release_next
                }
                Err(error) => {
                    assert_eq!(
                        araphor_query::Failure::from(&error),
                        araphor_query::Failure::Busy
                    );
                    let (observed, release_open) = gate()?;
                    release_next.send(())?;
                    tokio::task::spawn_blocking(move || {
                        observed.recv_timeout(Duration::from_secs(30))
                    })
                    .await??;
                    drop(fixture.query.reserve_evaluation([1; 16])?);
                    release_open
                }
            };
            let (observed, release_begin) = gate()?;
            release_open.send(())?;
            tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30)))
                .await??;
            assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
            release_begin.send(())?;
            let idle = tokio::time::timeout(
                Duration::from_secs(30),
                fixture.query.acquire_evaluation([1; 16]),
            )
            .await??;
            let current = fixture.query.store().managed_resume(
                [1; 16],
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(current.instance.progress, receipt.commit_revision);
            assert_eq!(current.completed, receipt.commit_revision);
            assert_eq!(current.instance.lifecycle, lifecycle);
            assert_eq!(current.instance.generation, failed.instance.generation);
            assert!(current.instance.running);
            assert_eq!(
                fixture.query.store().managed_history(
                    &fixture.grant.selection,
                    "admitted-capacity",
                    &AnalysisReadControl::default(),
                )?,
                [receipt]
            );
            drop(idle);
        } else if action == "source" {
            fixture.context(2)?;
            let progress = fixture.host_progress("admitted-capacity", 0).await?;
            let history = fixture.query.store().managed_history(
                &fixture.grant.selection,
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(history.len(), 1);
            let receipt = history.first().ok_or("source capacity receipt")?;
            assert_eq!(receipt.commit_revision, progress);
            assert!(fixture
                .selected("admitted-capacity", &receipt.attempt)?
                .is_empty());
            assert_eq!(memory.capacity_epoch(), epoch);
            drop(pressure);
        } else {
            drop(pressure);
            let progress = fixture.host_progress("admitted-capacity", 0).await?;
            let history = fixture.query.store().managed_history(
                &fixture.grant.selection,
                "admitted-capacity",
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(history.len(), 1);
            let receipt = history.first().ok_or("admitted capacity receipt")?;
            assert_eq!(receipt.commit_revision, progress);
            assert_eq!(
                fixture.selected("admitted-capacity", &receipt.attempt)?,
                vec![3; 4096]
            );
        }
        control.cancel()?;
        tokio::time::timeout(Duration::from_secs(30), worker).await???;
        drop(expected);
        drop(owner);
        drop(host);
        drop(fixture.query.memory().reserve_output(OUTPUT)?);
        drop(fixture.query.reserve_evaluation([1; 16])?);
    }
    Ok(())
}
