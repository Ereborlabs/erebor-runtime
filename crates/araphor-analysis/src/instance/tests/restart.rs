use futures_util::StreamExt as _;

use super::*;

#[tokio::test]
async fn restart_skips_input_capacity() -> TestResult {
    const CAPACITY: usize = 2 * 1024 * 1024;
    let fixture = Fixture::new(araphor_query::execution::Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        input_capacity: Some(CAPACITY),
        ..Default::default()
    })?;
    let package = bundle("sql")?;
    fixture.install(&package)?;
    fixture.context(1)?;
    let instance = fixture.admit("restart", r#"SELECT value FROM "runtime-fixture"."1".accumulate(input => (SELECT CAST(1 AS BIGINT UNSIGNED) AS value)) WHERE EXISTS (SELECT 1 FROM context_versions)"#).await?;
    let retained = fixture.query.memory().input_reserved();
    let lifecycle = fixture.start(&instance)?;
    let mut first = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let receipt = tokio::time::timeout(Duration::from_secs(30), first.next())
        .await?
        .ok_or("initial restart receipt")??;
    assert_eq!(fixture.selected("restart", &receipt.attempt)?, [1]);
    assert_eq!(receipt.results.len(), 1);
    assert_eq!(
        first
            .cancel_and_join(&AnalysisReadControl::default())
            .await?,
        None
    );
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    let control = AnalysisReadControl::default();
    let store = fixture.query.store();
    let saved = store.managed_resume([1; 16], "restart", &control)?;
    assert_eq!(saved.instance.progress, receipt.commit_revision);
    assert_eq!(saved.completed, receipt.commit_revision);
    assert_eq!(saved.instance.lifecycle, lifecycle);
    assert!(saved.instance.running);
    let reference = receipt.results.values().next().ok_or("checkpoint result")?;
    let result = store.managed_result(
        instance.admitted(),
        &reference.result_id,
        u64::MAX,
        &control,
    )?;
    let checkpoint = result
        .output
        .checkpoint
        .as_ref()
        .ok_or("saved checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(checkpoint.datasets.len(), 1);
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [1]);
    let model = &package.artifacts[0].descriptor.exports[0];
    let encoded = sdk::wire::Output::encode_model(&result.output, model, result.limits)?;
    drop(result);
    let before = store.meta()?;
    let pressure = fixture.query.memory().reserve_input(CAPACITY - retained)?;
    assert!(fixture.query.memory().reserve_input(1).is_err());
    let mut resumed = instance.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        lifecycle,
    )?;
    let mut next = Box::pin(resumed.next());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), next.as_mut())
            .await
            .is_err()
    );
    tokio::select! {
        update = &mut next => return Err(format!("unchanged restart executed: {update:?}").into()),
        available = tokio::time::timeout(Duration::from_secs(30), fixture.query.acquire_evaluation([1; 16])) => drop(available??),
    }
    assert_eq!(fixture.query.memory().input_reserved(), CAPACITY);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.managed_resume([1; 16], "restart", &control)?, saved);
    let attempt = store
        .managed_attempt([1; 16], "restart", &receipt.attempt, &control)?
        .ok_or("retained restart attempt")?;
    assert_eq!(attempt.receipt(), Some(&receipt));
    let result = store.managed_result(
        instance.admitted(),
        &reference.result_id,
        u64::MAX,
        &control,
    )?;
    assert_eq!(result.commit_revision, receipt.commit_revision);
    assert_eq!(
        sdk::wire::Output::encode_model(&result.output, model, result.limits)?,
        encoded
    );
    drop(result);
    drop(pressure);
    fixture.context(2)?;
    let changed = tokio::time::timeout(Duration::from_secs(30), next)
        .await?
        .ok_or("changed restart receipt")??;
    assert_ne!(changed.attempt, receipt.attempt);
    assert!(changed.commit_revision > receipt.commit_revision);
    assert_eq!(fixture.selected("restart", &changed.attempt)?, [2]);
    let result = store.managed_result(
        instance.admitted(),
        &changed
            .results
            .values()
            .next()
            .ok_or("changed checkpoint")?
            .result_id,
        u64::MAX,
        &control,
    )?;
    let checkpoint = result.output.checkpoint.as_ref().ok_or("next checkpoint")?;
    assert_eq!(checkpoint.version, 1);
    assert_eq!(checkpoint.datasets.len(), 1);
    assert_eq!(values(&checkpoint.datasets[0].batches)?, [2]);
    drop(result);
    assert_eq!(resumed.cancel_and_join(&control).await?, None);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    assert_eq!(fixture.progress("restart")?, changed.commit_revision);
    drop(fixture.query.reserve_evaluation([1; 16])?);
    drop(instance);
    assert_eq!(fixture.query.memory().input_reserved(), 0);
    drop(fixture.query.memory().reserve_input(CAPACITY)?);
    Ok(())
}
