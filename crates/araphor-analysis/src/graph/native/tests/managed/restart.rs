use super::*;
use futures_util::StreamExt as _;

#[tokio::test]
async fn graph_restart_keeps_frontier() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "graph-restart".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let first = job
        .run(request("before-restart")?, &fixture.control)
        .await?;
    let frontier = first.frontier.clone().ok_or("Graph native frontier")?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let graph = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Graph head before restart")?;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &graph.result_id)?;
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let running = host
        .start(Arc::clone(&job), job.admitted().lifecycle, &fixture.control)
        .await?;
    let saved = running.admitted().clone();
    for image in &saved.spec.definition.images {
        assert!(fixture.query.store().uninstall_package_image(
            fixture.source.tenant_id,
            image,
            || Ok(())
        )?);
    }
    let unchanged = fixture.query.store().meta()?;
    assert!(fixture.prepare("").await.is_err());
    assert_eq!(fixture.query.store().meta()?, unchanged);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let before = fixture.query.store().meta()?;
    let record = fixture.records.last().ok_or("Graph record")?.clone();
    let Fixture {
        query,
        control,
        source,
        facts,
        authority,
        _directory,
        _graph: graph_lease,
        ..
    } = fixture;
    drop(running);
    drop(job);
    drop(host);
    drop(graph_lease);
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let query = Engine::new(store, Default::default())?;
    let host = crate::InstanceHost::with_graph_facts(Arc::clone(&query), authority, facts.clone());
    let crate::instance::Restored::Present(restored) = host
        .restore(source.tenant_id, "graph-restart", &control)
        .await?
    else {
        return Err("restored Graph job".into());
    };
    assert_eq!(restored.admitted(), &saved);
    assert_eq!(query.store().meta()?, before);
    let resumed = query
        .store()
        .managed_resume(source.tenant_id, "graph-restart", &control)?;
    assert_eq!(resumed.frontier, Some(frontier));
    assert_eq!(resumed.instance.progress, first.commit_revision);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 1);
    let retained = query.memory().input_reserved();
    let mut stream = restored.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        restored.admitted().lifecycle,
    )?;
    let mut next = Box::pin(stream.next());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), next.as_mut())
            .await
            .is_err()
    );
    assert_eq!(query.store().meta()?, before);
    assert_eq!(query.store().processor_result(&scope)?, Some(graph.clone()));
    assert_eq!(facts.calls.load(Ordering::SeqCst), 1);
    query.store().accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.into(),
        },
    )?;
    let second = tokio::time::timeout(std::time::Duration::from_secs(30), next)
        .await?
        .ok_or("Graph change after restart")??;
    assert_ne!(second.attempt, first.attempt);
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(second.results.len(), 3);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph progress")?
            .consumed_cursor,
        4
    );
    assert_eq!(
        query
            .store()
            .managed_attempt(source.tenant_id, "graph-restart", &first.attempt, &control)?
            .ok_or("retained Graph attempt")?
            .receipt(),
        Some(&first)
    );
    assert_eq!(
        query
            .store()
            .graph_result(source.tenant_id, &graph.result_id)?,
        original
    );
    assert_eq!(stream.cancel_and_join(&control).await?, None);
    assert_eq!(query.memory().input_reserved(), retained);
    Ok(())
}
