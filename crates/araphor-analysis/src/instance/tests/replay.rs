use super::*;

#[tokio::test]
async fn replay_keeps_captured_state() -> TestResult {
    replay_state("sql").await
}

#[tokio::test]
async fn replay_wasm_captured_state() -> TestResult {
    replay_state("wasm").await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn replay_native_captured_state() -> TestResult {
    replay_state("native").await
}

async fn replay_state(target: &str) -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let image = bundle(target)?;
    fixture.install(&image)?;
    fixture.context(1)?;
    let moving = fixture.admit("replay-source", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS value FROM context_versions))"#).await?;
    let source = moving
        .run(request("source"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("replay-source", "source")?, [1]);
    let reference = source.results.values().next().ok_or("source result")?;
    let araphor_data::ManagedOutput::Call {
        result: original, ..
    } = fixture.query.store().managed_output(
        moving.admitted(),
        &reference.result_id,
        10,
        &AnalysisReadControl::default(),
    )?
    else {
        return Err("package output variant".into());
    };
    fixture.context(2)?;
    let before = fixture.query.store().meta()?;
    let replayed = moving
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [1]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("replayed source call")?;
    assert_eq!(call.evaluation().context, original.context.context);
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original.output
    );
    assert_eq!(fixture.query.store().meta()?, before);
    drop(replayed);
    let constant = fixture.admit("replay-state", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let first = constant
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let second = constant
        .run(request("second"), &AnalysisReadControl::default())
        .await?;
    let third = constant
        .run(request("third"), &AnalysisReadControl::default())
        .await?;
    assert_eq!(fixture.selected("replay-state", "third")?, [9]);
    let reference = second
        .results
        .values()
        .next()
        .ok_or("second result")?
        .clone();
    let araphor_data::ManagedOutput::Call {
        result: original, ..
    } = fixture.query.store().managed_output(
        constant.admitted(),
        &reference.result_id,
        10,
        &AnalysisReadControl::default(),
    )?
    else {
        return Err("package output variant".into());
    };
    let before = fixture.query.store().meta()?;
    let replayed = constant
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [6]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("replayed state call")?;
    assert_eq!(call.evaluation().context, original.context.context);
    assert!(call.evaluation().checkpoint.is_some());
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original.output
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.progress("replay-state")?, third.commit_revision);
    drop(replayed);
    let definition = constant.admitted().spec.definition.clone();
    drop(constant);
    drop(moving);
    let Fixture {
        directory,
        query,
        authority,
        grant,
    } = fixture;
    drop(query);
    let query = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Default::default(),
    )?;
    let instance = Instance::admit(
        Arc::clone(&query),
        authority,
        grant.clone(),
        "replay-state".into(),
        definition,
        &AnalysisReadControl::default(),
    )
    .await?;
    let before = query.store().meta()?;
    let replayed = instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [6]);
    let call = replayed
        .calls
        .values()
        .next()
        .ok_or("reopened replay call")?;
    assert_eq!(
        sdk::wire::Output::encode_model(call.output(), &image.artifacts[0].descriptor.exports[0])?,
        original.output
    );
    assert_eq!(query.store().meta()?, before);
    assert_eq!(
        query.store().managed_history(
            &grant.selection,
            "replay-state",
            &AnalysisReadControl::default()
        )?,
        [first, second, third]
    );
    Ok(())
}

#[tokio::test]
async fn replay_checks_current_authority() -> TestResult {
    const CAPACITY: usize = 4 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let image = bundle("sql")?;
    fixture.install(&image)?;
    let instance = fixture.admit("replay-guards", r#"SELECT * FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(3 AS BIGINT UNSIGNED) AS value))"#).await?;
    let receipt = instance
        .run(request("first"), &AnalysisReadControl::default())
        .await?;
    let reference = receipt.results.values().next().ok_or("replay result")?;
    let before = fixture.query.store().meta()?;
    let retained = fixture.query.memory().input_reserved();
    fixture.authority.set(false);
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    fixture.authority.set(true);
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .clear();
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    fixture
        .authority
        .images
        .lock()
        .map_err(|_| "image trust lock")?
        .insert(image.digest()?);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(instance
        .replay(&reference.result_id, &cancelled)
        .await
        .is_err());
    let held = fixture.query.memory().reserve_input(CAPACITY - retained)?;
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    drop(held);
    fixture.authority.deny_next.store(true, Ordering::SeqCst);
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    assert!(!fixture.authority.deny_next.load(Ordering::SeqCst));
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    assert_eq!(fixture.query.store().meta()?, before);
    let current = fixture
        .query
        .store()
        .managed_instance([1; 16], "replay-guards", &AnalysisReadControl::default())?
        .ok_or("current replay instance")?;
    let mut grant = fixture.grant.clone();
    grant.revision += 1;
    let host = InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let renewed = host
        .renew(
            grant,
            current.spec.id.clone(),
            current.lifecycle,
            &AnalysisReadControl::default(),
        )
        .await?;
    let before = fixture.query.store().meta()?;
    assert!(instance
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await
        .is_err());
    let replayed = renewed
        .replay(&reference.result_id, &AnalysisReadControl::default())
        .await?;
    assert_eq!(values(&replayed.batches)?, [3]);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
