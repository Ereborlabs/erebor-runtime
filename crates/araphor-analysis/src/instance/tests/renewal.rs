use super::*;

#[tokio::test]
async fn renewal_keeps_checkpoint() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    let instance = fixture.admit("renewal", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("renewal", "first")?, [3]);
    let reference = first
        .results
        .values()
        .next()
        .ok_or("original call result")?
        .clone();
    let araphor_data::ManagedOutput::Call {
        result: original, ..
    } = fixture.query.store().managed_output(
        instance.admitted(),
        &reference.result_id,
        10,
        &AnalysisReadControl::default(),
    )?
    else {
        return Err("package output variant".into());
    };
    let stored = fixture
        .query
        .store()
        .managed_instance([1; 16], "renewal", &AnalysisReadControl::default())?
        .ok_or("renewal instance")?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let mut grant = fixture.grant.clone();
    grant.revision += 1;
    fixture.authority.revoke(fixture.grant.revision);
    let renewed = host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert_eq!(renewed.admitted().spec, stored.spec);
    assert_eq!(renewed.admitted().grant, grant);
    assert_eq!(renewed.admitted().generation, stored.generation);
    assert_eq!(renewed.admitted().progress, first.commit_revision);
    assert!(!renewed.admitted().running);
    assert!(renewed.admitted().lifecycle > stored.lifecycle);
    assert_eq!(renewed.prepared.resolved(), instance.prepared.resolved());
    assert_eq!(
        renewed
            .prepared
            .images()
            .map(|(image, _)| image.encode())
            .collect::<std::result::Result<Vec<_>, _>>()?,
        instance
            .prepared
            .images()
            .map(|(image, _)| image.encode())
            .collect::<std::result::Result<Vec<_>, _>>()?
    );
    let before = fixture.query.store().meta()?;
    assert_eq!(
        renewed
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    assert_eq!(fixture.query.store().meta()?, before);
    let loaded = fixture
        .query
        .store()
        .managed_attempt([1; 16], "renewal", "first", &AnalysisReadControl::default())?
        .ok_or("original attempt")?;
    assert_eq!(loaded.instance().grant, fixture.grant);
    let second = renewed
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("renewal", "second")?, [6]);
    let mut rebuild = request("rebuild");
    rebuild.rebuild = true;
    let rebuilt = renewed
        .run(rebuild, &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("renewal", "rebuild")?, [3]);
    let continued = renewed
        .run(request("continued"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("renewal", "continued")?, [6]);
    let definition = renewed.admitted().spec.definition.clone();
    drop(renewed);
    drop(instance);
    drop(host);
    let Fixture {
        directory,
        query,
        authority,
        ..
    } = fixture;
    drop(query);
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Default::default(),
    )?;
    let instance = Instance::admit(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "renewal".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    assert_eq!(instance.admitted().generation, stored.generation);
    assert_eq!(instance.admitted().progress, continued.commit_revision);
    let before = query.store().meta()?;
    assert_eq!(
        instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    assert_eq!(query.store().meta()?, before);
    let loaded = query
        .store()
        .managed_attempt([1; 16], "renewal", "first", &AnalysisReadControl::default())?
        .ok_or("reopened attempt")?;
    assert_eq!(loaded.instance().grant, stored.grant);
    let araphor_data::PackageResponseV1::Result(retained) = Instance::read_output(
        Arc::clone(&query),
        authority.clone(),
        grant.clone(),
        "renewal",
        &reference.result_id,
        &AnalysisReadControl::default(),
    )
    .await?
    else {
        return Err("package output variant".into());
    };
    assert_eq!(retained.output, original.output);
    assert_eq!(retained.context, original.context);
    assert_eq!(retained.commit_revision, original.commit_revision);
    assert_eq!(
        Instance::read_history(
            Arc::clone(&query),
            authority.clone(),
            grant.clone(),
            "renewal",
            &AnalysisReadControl::default()
        )
        .await?,
        [first.clone(), second, rebuilt, continued]
    );
    authority.revoke(grant.revision);
    assert!(instance
        .run(request("first"), &AnalysisReadControl::default())
        .await
        .is_err());
    assert!(Instance::read_output(
        Arc::clone(&query),
        authority,
        grant,
        "renewal",
        &reference.result_id,
        &AnalysisReadControl::default()
    )
    .await
    .is_err());
    assert_eq!(query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn renewal_checks_current_authority() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    let instance = fixture.admit("renewal-guards", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let stored = fixture
        .query
        .store()
        .managed_instance([1; 16], "renewal-guards", &AnalysisReadControl::default())?
        .ok_or("renewal instance")?;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let mut grant = fixture.grant.clone();
    grant.revision += 1;
    let before = fixture.query.store().meta()?;
    let retained = fixture.query.memory().input_reserved();
    let notices = fixture.query.store().subscribe_activations();
    fixture.authority.deny_next.store(true, Ordering::SeqCst);
    assert!(host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    let mut expired = grant.clone();
    expired.expires_utc_ns = Some(1);
    assert!(host
        .renew(
            expired,
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    let mut changed = grant.clone();
    changed.selection.contexts = araphor_data::Selection::Exact(Vec::new());
    assert!(host
        .renew(
            changed,
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .clear();
    assert!(host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .insert(image.digest()?);
    let held = fixture.query.memory().reserve_input(CAPACITY - retained)?;
    assert!(host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    drop(held);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance([1; 16], "renewal-guards", &AnalysisReadControl::default())?
            .ok_or("unchanged instance")?,
        stored
    );
    assert!(!notices.has_changed()?);
    let renewed = host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let before = fixture.query.store().meta()?;
    for id in ["first", "stale-owner"] {
        assert!(instance
            .run(request(id), &AnalysisReadControl::default())
            .await
            .is_err());
        assert_eq!(fixture.query.store().meta()?, before);
    }
    assert!(fixture
        .query
        .store()
        .managed_attempt(
            [1; 16],
            "renewal-guards",
            "stale-owner",
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert!(host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            stored.lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    fixture.authority.deny_next.store(true, Ordering::SeqCst);
    assert!(host
        .renew(
            grant.clone(),
            stored.spec.id.clone(),
            renewed.admitted().lifecycle,
            &AnalysisReadControl::default()
        )
        .await
        .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        renewed
            .run(request("first"), &AnalysisReadControl::default())
            .await?,
        first
    );
    let unchanged = host
        .renew(
            grant,
            stored.spec.id.clone(),
            renewed.admitted().lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert_eq!(unchanged.admitted(), renewed.admitted());
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
