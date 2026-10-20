use araphor_query::execution::{Engine, Limits};
use araphor_query::follow::{Clock, Subscription, Update};
use futures_util::TryStreamExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::*;

struct CapturedClock {
    now: AtomicU64,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Clock for CapturedClock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        Ok(self.now.load(Ordering::SeqCst))
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

async fn capture(
    engine: &Arc<Engine>,
    sql: &str,
    now: u64,
) -> std::result::Result<Update, Box<dyn std::error::Error>> {
    let (plan, sources) = engine.prepare(sql, Vec::new()).await?;
    let mut subscription = Subscription::new(
        engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            now,
        )?,
        Arc::new(plan),
        sources,
        b"notification-test",
        None,
        Arc::new(CapturedClock {
            now: AtomicU64::new(now),
            changes: tokio::sync::watch::channel(0).0,
        }),
        false,
    )?;
    let update = subscription.try_next().await?.ok_or("missing update")?;
    assert!(!update.limited && update.exhausted);
    Ok(update)
}

#[tokio::test]
async fn native_notification_follow() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    store.enable_graph_owner()?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let mut approval = grant(NotificationPrincipalV1::Human);
    approval.expires_utc_ns = 2_000_000_000;
    for name in ["escalation", "primary"] {
        router.configure(&approval, policy(name), 10)?;
    }
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    let (plan, sources) = engine.prepare(NotificationRouter::SQL, Vec::new()).await?;
    let clock = Arc::new(CapturedClock {
        now: AtomicU64::new(100),
        changes: tokio::sync::watch::channel(0).0,
    });
    let mut subscription = Subscription::new(
        engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            100,
        )?,
        Arc::new(plan),
        sources,
        b"notification-follow",
        None,
        clock.clone(),
        true,
    )?;
    let initial = tokio::time::timeout(Duration::from_secs(10), subscription.try_next())
        .await??
        .ok_or("missing initial update")?;
    assert_eq!(initial.snapshot.next_change, Some(2_000_000_000));
    assert_eq!(
        initial
            .batches
            .as_ref()
            .ok_or("initial notification batches")?
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), subscription.try_next())
            .await
            .is_err()
    );
    clock.now.store(2_000_000_000, Ordering::SeqCst);
    clock.changes.send_replace(2_000_000_000);
    let expired = tokio::time::timeout(Duration::from_secs(10), subscription.try_next())
        .await??
        .ok_or("missing expiry update")?;
    assert!(expired.clock_changed);
    assert_eq!(expired.evaluated_utc_ns, 2_000_000_000);
    assert_eq!(expired.snapshot.next_change, None);
    assert_eq!(
        expired.snapshot.page.extraction.meta.commit_revision,
        initial.snapshot.page.extraction.meta.commit_revision
    );
    subscription.cancel()?;
    Ok(())
}

#[tokio::test]
async fn native_notification_eligibility() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    store.enable_graph_owner()?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let sink = Sink::default();
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    let routed = router.consume(&update, &sink)?;
    assert_eq!(routed.routed.len(), 1);
    assert_eq!(
        *routed.routed[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    assert!(routed.delivered.is_empty());
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    let delivered = router.consume(&update, &sink)?;
    assert!(delivered.routed.is_empty());
    assert_eq!(delivered.delivered.len(), 1);
    assert_eq!(
        *delivered.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    let key = delivered.delivered[0].0;
    let update = capture(&engine, NotificationRouter::SQL, 101).await?;
    assert_eq!(update.snapshot.next_change, Some(200));
    let stable = router.consume(&update, &sink)?;
    assert!(stable.routed.is_empty() && stable.delivered.is_empty());
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);

    let mut changed = policy("primary");
    changed.revision = 2;
    router.configure(&grant(NotificationPrincipalV1::Human), changed, 110)?;
    let update = capture(&engine, NotificationRouter::SQL, 110).await?;
    let changed = router.consume(&update, &sink)?;
    assert_eq!(changed.routed.len(), 1);
    assert_eq!(
        *changed.routed[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    assert!(changed.delivered.is_empty());
    assert_eq!(
        router
            .state(key)?
            .route
            .as_ref()
            .ok_or("notification route")?
            .revision,
        2
    );
    let update = capture(&engine, NotificationRouter::SQL, 111).await?;
    let stable = router.consume(&update, &sink)?;
    assert!(stable.routed.is_empty() && stable.delivered.is_empty());

    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    let update = capture(&engine, NotificationRouter::SQL, 120).await?;
    assert_eq!(router.consume(&update, &sink)?.routed.len(), 1);
    let update = capture(&engine, NotificationRouter::SQL, 120).await?;
    let revised = router.consume(&update, &sink)?;
    assert_eq!(revised.delivered.len(), 1);
    assert_eq!(revised.delivered[0].0, key);
    assert_eq!(
        *revised.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    assert_eq!(router.state(key)?.deadline_utc_ns, Some(200));
    Ok(())
}

#[tokio::test]
async fn native_notification_retry_deadline() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    store.enable_graph_owner()?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let sink = Sink {
        fail_primary: true,
        ..Default::default()
    };
    configure(&router)?;
    let mut retry = policy("primary");
    retry.revision = 2;
    retry.retry_delay_ns = 10;
    router.configure(&grant(NotificationPrincipalV1::Human), retry, 20)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    router.consume(&update, &sink)?;
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    let failed = router.consume(&update, &sink)?;
    assert_eq!(
        *failed.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        2
    );
    let key = failed.delivered[0].0;
    let before = store.meta()?.commit_revision;
    let update = capture(&engine, NotificationRouter::SQL, 109).await?;
    assert_eq!(update.snapshot.next_change, Some(110));
    let idle = router.consume(&update, &sink)?;
    assert!(idle.routed.is_empty() && idle.delivered.is_empty());
    assert_eq!(store.meta()?.commit_revision, before);
    let update = capture(&engine, NotificationRouter::SQL, 110).await?;
    let retried = router.consume(&update, &sink)?;
    assert_eq!(retried.delivered.len(), 1);
    assert_eq!(
        *retried.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    assert_eq!(retried.delivered[0].0, key);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 3);
    let update = capture(&engine, NotificationRouter::SQL, 111).await?;
    assert_eq!(update.snapshot.next_change, Some(120));
    assert!(router.consume(&update, &sink)?.delivered.is_empty());
    let state = router.state(key)?;
    router.acknowledge(
        &grant(NotificationPrincipalV1::Human),
        key,
        state.finding_revision,
        [6; 16],
        112,
    )?;
    let update = capture(&engine, NotificationRouter::SQL, 200).await?;
    assert_eq!(update.snapshot.next_change, Some(10_000));
    assert!(router.consume(&update, &sink)?.delivered.is_empty());
    Ok(())
}

#[tokio::test]
async fn native_notification_requires_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store, Limits::default())?;
    let error = capture(&engine, NotificationRouter::SQL, 100)
        .await
        .err()
        .ok_or("a missing graph owner must fail")?;
    let error = error
        .downcast_ref::<araphor_query::Error>()
        .ok_or("query error type")?;
    assert!(matches!(error,
        araphor_query::Error::Sql { source: datafusion::common::DataFusionError::External(source) }
        if matches!(source.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisUnavailable { relation: "findings", .. }))
    ));
    Ok(())
}

#[tokio::test]
async fn native_notification_item_isolation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    route(&router, 100)?;
    let update = capture(
        &engine,
        "SELECT CAST(NULL AS VARCHAR) AS finding_id, CAST(NULL AS VARCHAR) AS result_id,
        X'77777777777777777777777777777777' AS notification_id UNION ALL
        SELECT NULL AS finding_id,NULL AS result_id,notification_id FROM notifications WHERE delivery_ready",
        100,
    )
    .await?;
    let result = router.consume(&update, &Sink::default())?;
    assert_eq!(result.delivered.len(), 2);
    assert!(result.delivered[0].1.is_err());
    assert_eq!(
        *result.delivered[1]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    Ok(())
}
