use futures_util::StreamExt as _;

use super::*;

#[tokio::test]
async fn drains_captured_backlog() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture
        .prepare("WHERE source_cursor <= (SELECT consumed_cursor + 1 FROM graph_state)")
        .await?;
    let projection = Arc::clone(&publication.projection);
    let observed = projection.observe_capture();
    let mut stream = publication.subscribe(b"graph-backlog").await?;
    let mut previous = None;
    for consumed in 1..=3 {
        let (id, receipt) = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await?
            .ok_or("Graph subscription ended")??;
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
    drop(next);
    stream.cancel_and_join().await?;
    assert!(fixture
        .query
        .acquire_evaluation(fixture.source.tenant_id)
        .await
        .is_ok());
    Ok(())
}

#[tokio::test]
async fn benign_notice_keeps_capture() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let projection = Arc::clone(&publication.projection);
    let observed = projection.observe_capture();
    let (entered, entry) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    *fixture
        .facts
        .gate
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((entered, released));
    let mut stream = publication.subscribe(b"graph-authority").await?;
    let worker = tokio::spawn(async move {
        let result = stream.next().await;
        (stream, result)
    });
    tokio::task::spawn_blocking(move || entry.recv_timeout(std::time::Duration::from_secs(30)))
        .await??;
    fixture.authority.set(true);
    release.send(())?;
    let (mut stream, result) = worker.await?;
    let (id, _) = result.ok_or("Graph subscription ended")??;
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .is_some());
    assert!(observed.try_recv()?.source.upgrade().is_none());
    assert!(observed.try_recv().is_err());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
    let before = fixture.query.store().meta()?.commit_revision;
    fixture.authority.set(false);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await?
            .ok_or("Graph denial ended without an error")?
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?.commit_revision, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    stream.cancel_and_join().await?;
    Ok(())
}
