use erebor_runtime_error::ErrorExt as _;

use super::*;

impl Fixture {
    fn reader_event(&self) -> TestResult {
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
        tokio::time::timeout(Duration::from_secs(30), memory.capacity_changed(epoch)).await??;
        assert_eq!(authority.admissions.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.query.store().meta()?, before);
        assert_eq!(fixture.progress("pressure-opening")?, 0);
        match action {
            "release" => {
                drop(pressure);
                fixture.host_progress("pressure-opening", 0).await?;
                assert_eq!(authority.admissions.load(Ordering::SeqCst), 2);
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker).await???;
            }
            "stop" => {
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker).await???;
                assert_eq!(fixture.query.store().meta()?, before);
                drop(pressure);
            }
            "deny" => {
                authority.deny(&fixture.grant.principal);
                let stopped = fixture.host_stopped("pressure-opening").await?;
                assert_eq!(stopped.progress, 0);
                stop.send_replace(true);
                tokio::time::timeout(Duration::from_secs(30), worker).await???;
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
