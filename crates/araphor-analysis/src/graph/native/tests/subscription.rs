use futures_util::StreamExt as _;

use super::*;

#[tokio::test]
async fn drains_captured_backlog() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture
        .prepare("WHERE source_cursor <= (SELECT consumed_cursor + 1 FROM graph_state)")
        .await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "graph-backlog",
            "SELECT * FROM events WHERE source_cursor <= (SELECT consumed_cursor + 1 FROM graph_state)",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let projection = &job.graph_owner().ok_or("Running Graph owner")?.projection;
    let observed = projection.observe_capture();
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let checked: TestResult = async {
        let mut previous = None;
        for consumed in 1..=3 {
            let receipt = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
                .await?
                .ok_or("Graph subscription ended")??;
            let scope = araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: fixture.source.clone(),
            };
            let head = fixture
                .query
                .store()
                .processor_result(&scope)?
                .ok_or("Graph processor result")?;
            let id = head.result_id;
            assert_eq!(head.commit_revision, receipt.commit_revision);
            let graph = fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &id)?
                .ok_or("Graph result")?;
            assert_eq!(graph.last_cursor, consumed);
            assert_eq!(graph.previous_result_id, previous);
            let health = fixture
                .query
                .store()
                .processor_health(&graph.scope)?
                .ok_or("Graph progress")?;
            assert_eq!(health.consumed_cursor, consumed);
            assert_eq!(health.accepted_cursor, 3);
            assert_eq!(
                fixture
                    .query
                    .store()
                    .processor_result(&graph.scope)?
                    .ok_or("Graph processor result")?
                    .result_id,
                id
            );
            let headers = fixture
                .query
                .store()
                .graph_window_headers(&fixture.source, None)?;
            let (result, _, revision) = headers
                .iter()
                .find(|(result, _, _)| result == &id)
                .ok_or("Graph backlog window")?;
            assert_eq!(result, &id);
            assert_eq!(*revision, receipt.commit_revision);
            assert!(receipt.commit_revision > 0);
            let captured = observed.try_recv()?;
            assert_eq!(captured.accepted, 3);
            assert_eq!(captured.consumed, consumed - 1);
            assert!(captured.source.upgrade().is_none());
            previous = Some(id);
        }
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
        assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
        let mut next = Box::pin(stream.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
        assert_eq!(projection.projections.load(Ordering::SeqCst), 3);
        drop(next);
        Ok(())
    }
    .await;
    let joined = stream.cancel_and_join(&fixture.control).await;
    checked?;
    let _terminal = joined?;
    assert!(fixture
        .query
        .acquire_evaluation(fixture.source.tenant_id)
        .await
        .is_ok());
    Ok(())
}
