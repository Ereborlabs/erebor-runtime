use super::*;
use crate::instance::tests::request;

struct RemoveAuthority {
    inner: Arc<FixtureAuthority>,
    final_denied: AtomicBool,
    admissions: AtomicUsize,
}

impl PackageAuthorization for RemoveAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if matches!(action, PackageActionV1::Run) {
            return Err(Code::Denied.error("remove fixture Run"));
        }
        self.inner.check(grant, action)
    }

    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        self.admissions.fetch_add(1, Ordering::SeqCst);
        Err(Code::Denied.error("remove fixture execution trust"))
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        image: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(
            &[(grant, action, None), (grant, action, Some(image))],
            operation,
        )
    }

    fn commit_many(
        &self,
        entries: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, action, image) in entries {
            self.check(grant, *action)?;
            if let Some(image) = image {
                self.admit(grant, image)?;
            }
            if *action == PackageActionV1::Remove && self.final_denied.load(Ordering::SeqCst) {
                return Err(Code::Denied.error("remove fixture final authority"));
            }
        }
        self.inner.commit_many(entries, operation)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes()
    }
}

#[tokio::test]
async fn removal_needs_only_remove() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))"#;
    let instance = fixture.admit("metadata-remove", sql).await?;
    let receipt = instance
        .run(request("retained"), &AnalysisReadControl::default())
        .await?;
    let authority = Arc::new(RemoveAuthority {
        inner: fixture.authority.clone(),
        final_denied: AtomicBool::new(true),
        admissions: AtomicUsize::new(0),
    });
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let before = fixture.query.store().meta()?;
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "metadata-remove", &AnalysisReadControl::default())?
        .ok_or("current instance")?;
    assert!(host
        .remove(
            fixture.grant.clone(),
            "metadata-remove".into(),
            current.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture.query.store().managed_instance(
            [1; 16],
            "metadata-remove",
            &AnalysisReadControl::default()
        )?,
        Some(current.clone())
    );
    authority.final_denied.store(false, Ordering::SeqCst);
    let mut restricted = fixture.grant.clone();
    restricted.selection.nodes = vec!["unrelated-node".into()];
    assert!(host
        .remove(
            restricted,
            "metadata-remove".into(),
            current.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    let removed = host
        .remove(
            fixture.grant.clone(),
            "metadata-remove".into(),
            current.lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    assert_eq!(removed.progress, receipt.commit_revision);
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 0);
    let history = Instance::read_history(
        Arc::clone(&fixture.query),
        authority.clone(),
        fixture.grant.clone(),
        "metadata-remove",
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(history, vec![receipt.clone()]);
    let output = Instance::read_result(
        Arc::clone(&fixture.query),
        authority.clone(),
        fixture.grant.clone(),
        "metadata-remove",
        &receipt
            .results
            .values()
            .next()
            .ok_or("call result")?
            .result_id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert!(!output.current);
    assert!(output.output.checkpoint.is_some());
    let before = fixture.query.store().meta()?;
    assert_eq!(
        host.remove(
            fixture.grant.clone(),
            "metadata-remove".into(),
            removed.lifecycle,
            &AnalysisReadControl::default()
        )
        .await?,
        removed
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture.admit("metadata-remove", sql).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_joins_native_guest() -> TestResult {
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let instance = fixture.terminal_instance("joined-remove", "cancel").await?;
    let (entry, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    fixture.query.guest_entry(entry, Some(waiting))?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
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
        return Err(format!("remove guest did not enter: {error}").into());
    }
    let before = fixture.query.store().meta()?;
    assert!(host
        .remove(
            fixture.grant.clone(),
            "joined-remove".into(),
            instance.admitted().lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    let selected = Arc::clone(&host);
    let grant = fixture.grant.clone();
    let removing = tokio::spawn(async move {
        selected
            .remove(
                grant,
                "joined-remove".into(),
                running.admitted().lifecycle,
                &AnalysisReadControl::default(),
            )
            .await
    });
    tokio::task::yield_now().await;
    assert!(!removing.is_finished());
    assert!(fixture.query.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let removed = tokio::time::timeout(Duration::from_secs(30), removing).await???;
    assert!(removed.removed);
    assert!(!removed.running);
    assert_eq!(removed.progress, 0);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(30), worker).await???;
    drop(fixture.query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn recreation_changes_scope_explicitly() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))"#;
    let first = fixture.admit("recreated", sql).await?;
    let receipt = first
        .run(request("old-scope"), &AnalysisReadControl::default())
        .await?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let removed = host
        .remove(
            fixture.grant.clone(),
            "recreated".into(),
            first.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let mut grant = fixture.grant.clone();
    grant.selection.nodes = vec!["node-b".into()];
    grant.revision += 1;
    let image = bundle("sql")?;
    let pin = &removed.spec.definition.images[0];
    fixture
        .query
        .store()
        .uninstall_package_image([1; 16], pin, || Ok(()))?;
    assert!(host
        .recreate(
            grant.clone(),
            "recreated".into(),
            removed.lifecycle,
            removed.spec.definition.clone(),
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(
        fixture.query.store().managed_instance(
            [1; 16],
            "recreated",
            &AnalysisReadControl::default()
        )?,
        Some(removed.clone())
    );
    fixture.install(&image)?;
    let next = host
        .recreate(
            grant.clone(),
            "recreated".into(),
            removed.lifecycle,
            removed.spec.definition.clone(),
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(!next.admitted().removed);
    assert!(!next.admitted().running);
    assert_eq!(next.admitted().progress, 0);
    assert_eq!(next.admitted().grant, grant);
    assert!(next.admitted().generation > removed.lifecycle);
    assert!(host
        .start(
            Arc::clone(&first),
            first.admitted().lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    let latest = next
        .run(request("new-scope"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("recreated", "new-scope")?, vec![10]);
    let id = &receipt
        .results
        .values()
        .next()
        .ok_or("old result")?
        .result_id;
    assert!(Instance::read_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant.clone(),
        "recreated",
        id,
        &AnalysisReadControl::default()
    )
    .await
    .is_err());
    assert!(next
        .replay(id, &AnalysisReadControl::default())
        .await
        .is_err());
    let old = Instance::read_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "recreated",
        id,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert!(!old.current);
    assert_eq!(old.context.context.id, "old-scope");
    assert_eq!(
        Instance::read_history(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            grant,
            "recreated",
            &AnalysisReadControl::default()
        )
        .await?,
        vec![latest.clone()]
    );
    assert_eq!(
        Instance::read_history(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            "recreated",
            &AnalysisReadControl::default()
        )
        .await?,
        vec![receipt, latest]
    );
    Ok(())
}

#[tokio::test]
async fn restoration_keeps_tombstones() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let instance = fixture.admit("retired", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))"#).await?;
    let authority = Arc::new(RemoveAuthority {
        inner: fixture.authority.clone(),
        final_denied: AtomicBool::new(false),
        admissions: AtomicUsize::new(0),
    });
    let host = InstanceHost::new(Arc::clone(&fixture.query), authority.clone());
    let control = AnalysisReadControl::default();
    let removed = host
        .remove(
            fixture.grant.clone(),
            "retired".into(),
            instance.admitted().lifecycle,
            &control,
        )
        .await?;
    fixture.query.store().uninstall_package_image(
        [1; 16],
        &removed.spec.definition.images[0],
        || Ok(()),
    )?;
    let before = fixture.query.store().meta()?;
    assert!(matches!(
        host.restore([1; 16], "absent", &control).await?,
        Restored::Absent
    ));
    assert!(
        matches!(host.restore([1;16], "retired", &control).await?, Restored::Removed(actual) if *actual == removed)
    );
    assert!(matches!(
        host.restore([2; 16], "retired", &control).await?,
        Restored::Absent
    ));
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(fixture
        .query
        .store()
        .managed_history(&fixture.grant.selection, "retired", &control)?
        .is_empty());
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "retired", &control)?,
        Some(removed)
    );
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(host.restore([1; 16], "retired", &cancelled).await.is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn removal_keeps_shared_instance() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    fixture.install(&bundle("sql")?)?;
    let sql = r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(10 AS BIGINT UNSIGNED) AS value))"#;
    let first = fixture.admit("first-shared", sql).await?;
    let second = fixture.admit("second-shared", sql).await?;
    let control = AnalysisReadControl::default();
    let first_receipt = first.run(request("first-original"), &control).await?;
    let second_receipt = second.run(request("second-original"), &control).await?;
    assert_eq!(
        fixture.selected("first-shared", "first-original")?,
        vec![10]
    );
    assert_eq!(
        fixture.selected("second-shared", "second-original")?,
        vec![10]
    );
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let removed = host
        .remove(
            fixture.grant.clone(),
            "first-shared".into(),
            first.admitted().lifecycle,
            &control,
        )
        .await?;
    let pin = &removed.spec.definition.images[0];
    fixture
        .query
        .store()
        .uninstall_package_image([1; 16], pin, || Ok(()))?;
    assert!(fixture
        .query
        .store()
        .package_image(
            [1; 16],
            &pin.image.package_id,
            Some(&pin.image.revision),
            &control
        )?
        .is_none());
    assert!(fixture
        .query
        .store()
        .retained_package_image([1; 16], pin, &control)?
        .is_some());
    assert!(fixture.admit("new-shared", sql).await.is_err());
    let next = second.run(request("second-next"), &control).await?;
    assert_eq!(fixture.selected("second-shared", "second-next")?, vec![20]);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "first-shared", &control)?,
        Some(removed.clone())
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "first-shared",
            &control
        )?,
        vec![first_receipt.clone()]
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &fixture.grant.selection,
            "second-shared",
            &control
        )?,
        vec![second_receipt, next]
    );
    let reference = first_receipt
        .results
        .values()
        .next()
        .ok_or("removed result")?;
    let retained = Instance::read_result(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.grant.clone(),
        "first-shared",
        &reference.result_id,
        &control,
    )
    .await?;
    assert!(!retained.current);
    assert!(retained.output.checkpoint.is_some());
    Ok(())
}
