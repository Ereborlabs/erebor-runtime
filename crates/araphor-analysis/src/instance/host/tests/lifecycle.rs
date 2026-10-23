use super::*;

impl InstanceHost {
    pub(super) async fn ready(&self) -> TestResult {
        let mut serving = self.serving.subscribe();
        tokio::time::timeout(Duration::from_secs(30), async {
            while !*serving.borrow_and_update() {
                serving.changed().await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?
    }
}

#[tokio::test]
async fn unpolled_host_releases_registration() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let before = fixture.query.store().meta()?;
    let serving = Arc::clone(&host).serve(stopped, u64::MAX);
    assert!(*host.serving.borrow());
    assert!(fixture.query.store().lease_managed().is_err());
    drop(serving);
    assert!(!*host.serving.borrow());
    assert!(host
        .commands
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    drop(fixture.query.store().lease_managed()?);
    assert_eq!(fixture.query.store().meta()?, before);
    stop.send_replace(true);
    Arc::clone(&host).serve(stop.subscribe(), u64::MAX).await?;
    assert!(!*host.serving.borrow());
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn explicit_stop_preserves_intent() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit("intent", "SELECT CAST(7 AS BIGINT UNSIGNED) AS value")
        .await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let control = AnalysisReadControl::default();
    let stopped = host
        .stop(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    assert!(!stopped.admitted().running);
    assert!(stopped.admitted().lifecycle > instance.admitted().lifecycle);
    assert_eq!(
        stopped.admitted().generation,
        instance.admitted().generation
    );
    assert!(host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control
        )
        .await
        .is_err());
    let before = fixture.query.store().meta()?;
    let repeated = host
        .stop(Arc::clone(&stopped), stopped.admitted().lifecycle, &control)
        .await?;
    assert_eq!(repeated.admitted(), stopped.admitted());
    assert_eq!(fixture.query.store().meta()?, before);
    let running = host
        .start(repeated, stopped.admitted().lifecycle, &control)
        .await?;
    assert!(running.admitted().running);
    let stopped = host
        .stop(Arc::clone(&running), running.admitted().lifecycle, &control)
        .await?;
    assert!(!stopped.admitted().running);
    assert_eq!(fixture.progress("intent")?, 0);
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn host_uses_current_authority() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit(
            "current-authority",
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        )
        .await?;
    let authority = Authority::new(&fixture);
    authority.deny(&fixture.grant.principal);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority);
    let before = fixture.query.store().meta()?;
    assert!(host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await
        .is_err());
    assert!(host
        .stop(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("current-authority")?, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_stop_joins_guest() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("joined-stop", "cancel").await?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    host.ready().await?;
    let running = host
        .start(
            instance.clone(),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let entered =
        tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(30))).await?;
    if let Err(error) = entered {
        let _released = release.send(());
        stop.send_replace(true);
        let _joined = worker.await;
        return Err(format!("stop guest did not enter: {error}").into());
    }
    let before = fixture.query.store().meta()?;
    assert!(host
        .stop(
            Arc::clone(&running),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    let selected = Arc::clone(&host);
    let lifecycle = running.admitted().lifecycle;
    let stopping = tokio::spawn(async move {
        selected
            .stop(running, lifecycle, &AnalysisReadControl::default())
            .await
    });
    tokio::task::yield_now().await;
    assert!(!stopping.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let stopped_instance = tokio::time::timeout(Duration::from_secs(30), stopping).await???;
    assert!(!stopped_instance.admitted().running);
    assert_eq!(fixture.progress("joined-stop")?, 0);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn paused_member_keeps_ownership() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.context(1)?;
    let instance = fixture
        .admit(
            "held",
            "SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions",
        )
        .await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    host.ready().await?;
    let running = host
        .start(
            instance.clone(),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let progress = fixture.host_progress("held", 0).await?;
    let operation = Arc::new(AnalysisReadControl::default());
    let lease = host
        .pause_and_join(running.admitted(), Arc::clone(&operation))
        .await?;
    let held = fixture.query.memory().input_reserved();
    assert!(host
        .pause_and_join(running.admitted(), Arc::new(AnalysisReadControl::default()))
        .await
        .is_err());
    assert_eq!(fixture.query.memory().input_reserved(), held);
    fixture.context(2)?;
    tokio::task::yield_now().await;
    assert_eq!(fixture.progress("held")?, progress);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), operation.cancelled()).await?;
    assert!(!worker.is_finished());
    assert!(fixture.query.store().lease_managed().is_err());
    drop(lease);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    assert!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "held", &AnalysisReadControl::default())?
            .ok_or("held instance")?
            .running
    );
    Ok(())
}

#[tokio::test]
async fn restore_keeps_stopped_jobs() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit(
            "restored-stop",
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        )
        .await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let control = AnalysisReadControl::default();
    let stopped = host
        .stop(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    let before = fixture.query.store().meta()?;
    let crate::instance::Restored::Present(restored) =
        host.restore([1; 16], "restored-stop", &control).await?
    else {
        return Err("restored stopped instance".into());
    };
    assert_eq!(restored.admitted(), stopped.admitted());
    assert!(!restored.admitted().running);
    assert!(matches!(
        host.restore([1; 16], "absent", &control).await?,
        crate::instance::Restored::Absent
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("restored-stop")?, 0);
    Ok(())
}

#[tokio::test]
async fn start_reuses_prepared_owner() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    fixture.context(1)?;
    let instance = fixture.admit("prepared-start", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    let authority = Authority::new(&fixture);
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    host.ready().await?;
    let before = authority.admissions.load(Ordering::SeqCst);
    let lifecycle = instance.admitted().lifecycle;
    let running = host
        .start(instance, lifecycle, &AnalysisReadControl::default())
        .await?;
    assert!(Arc::ptr_eq(&running.authority, &host.authority));
    let stopped = host
        .stop(
            Arc::clone(&running),
            running.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(!stopped.admitted().running);
    assert!(stopped.admitted().lifecycle > running.admitted().lifecycle);
    assert_eq!(stopped.admitted().generation, running.admitted().generation);
    let prior = stopped.admitted().progress;
    fixture.context(2)?;
    let running = host
        .start(
            Arc::clone(&stopped),
            stopped.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(running.admitted().running);
    assert!(running.admitted().lifecycle > stopped.admitted().lifecycle);
    let first = fixture.host_progress("prepared-start", prior).await?;
    assert_eq!(authority.admissions.load(Ordering::SeqCst), before + 3);
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "prepared-start", &AnalysisReadControl::default())?
        .ok_or("current running instance")?;
    let revision = fixture.query.store().meta()?;
    let repeated = host
        .start(
            Arc::clone(&running),
            running.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert_eq!(repeated.admitted(), &current);
    assert_eq!(fixture.query.store().meta()?, revision);
    assert_eq!(fixture.progress("prepared-start")?, first);
    assert_eq!(authority.admissions.load(Ordering::SeqCst), before + 4);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    let saved = fixture
        .query
        .store()
        .managed_instance([1; 16], "prepared-start", &AnalysisReadControl::default())?
        .ok_or("retained running instance")?;
    assert!(saved.running);
    assert_eq!(saved.lifecycle, running.admitted().lifecycle);
    fixture.context(3)?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let second = fixture.host_progress("prepared-start", first).await?;
    assert!(second > first);
    assert_eq!(authority.admissions.load(Ordering::SeqCst), before + 5);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}
