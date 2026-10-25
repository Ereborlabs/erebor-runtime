use std::sync::atomic::AtomicU64;

use futures_util::StreamExt as _;

use super::*;

pub(super) struct Clock {
    now: AtomicU64,
    changes: watch::Sender<u64>,
    entered: tokio::sync::Notify,
}

impl Clock {
    pub(super) fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            changes: watch::channel(0).0,
            entered: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn advance(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_modify(|revision| *revision += 1);
    }
}

impl araphor_query::follow::Clock for Clock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        let now = self.now.load(Ordering::SeqCst);
        self.entered.notify_one();
        Ok(now)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[tokio::test]
async fn expires_from_query_clock() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let (original, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:expiry-input".into())
        .await?;
    let previous = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &original)?
        .ok_or("Graph expiry input")?;
    let (_, references) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&original))?;
    assert_eq!(
        references
            .iter()
            .filter(|reference| reference.key.owner_id == "native-package-v1")
            .count(),
        3
    );
    let clock = Clock::new(previous.witness_deadline_utc_ns - 1);
    let publication = fixture.prepare("").await?;
    let projection = Arc::clone(&publication.projection);
    let definition = publication.expiry_definition().await?;
    let mut stream = publication
        .open_subscription(
            definition,
            sink::Kind::Expire,
            b"graph-expiry",
            clock.clone(),
        )
        .await?;
    let before = fixture.query.store().meta()?;
    let mut next = Box::pin(stream.next());
    tokio::select! {
        result = &mut next => return Err(format!("Graph expired before its deadline: {result:?}").into()),
        _ = clock.entered.notified() => {},
    }
    assert_eq!(fixture.query.store().meta()?, before);
    clock.advance(previous.witness_deadline_utc_ns);
    let (id, receipt) = tokio::time::timeout(std::time::Duration::from_secs(30), &mut next)
        .await?
        .ok_or("Graph expiry subscription ended")??;
    drop(next);
    let expected = Graph::expire(&previous, &original, previous.context_notice_revision)?;
    let actual = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("Expired Graph")?;
    assert_eq!(actual, expected);
    assert_eq!(receipt.consumed_cursor, 0);
    let (witnesses, contexts) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?;
    assert!(witnesses.is_empty());
    assert_eq!(contexts, references);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(projection.projections.load(Ordering::SeqCst), 0);
    let after = fixture.query.store().meta()?;
    clock.advance(previous.witness_deadline_utc_ns + 1);
    let mut next = Box::pin(stream.next());
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    drop(next);
    stream.cancel_and_join().await?;
    assert_eq!(fixture.query.store().meta()?, after);
    let Fixture {
        query,
        records,
        _directory,
        ..
    } = fixture;
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let fixture = Fixture::stored(Target::Wasm, records, _directory, store)?;
    let publication = fixture.prepare("").await?;
    let definition = publication.expiry_definition().await?;
    let clock = Clock::new(previous.witness_deadline_utc_ns + 2);
    let mut stream = publication
        .open_subscription(
            definition,
            sink::Kind::Expire,
            b"graph-expiry-recovered",
            clock.clone(),
        )
        .await?;
    let before = fixture.query.store().meta()?;
    let mut next = Box::pin(stream.next());
    tokio::select! {
        result = &mut next => return Err(format!("Graph expiry was repeated after recovery: {result:?}").into()),
        _ = clock.entered.notified() => {},
    }
    drop(next);
    stream.cancel_and_join().await?;
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &id)?,
        Some(expected)
    );
    Ok(())
}
