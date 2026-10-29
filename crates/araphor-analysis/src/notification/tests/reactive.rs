mod concerns;
mod findings;
mod routing;

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
    capture_tenant(engine, [1; 16], sql, now).await
}

async fn capture_tenant(
    engine: &Arc<Engine>,
    tenant: [u8; 16],
    sql: &str,
    now: u64,
) -> std::result::Result<Update, Box<dyn std::error::Error>> {
    let (plan, sources) = engine.prepare(sql, Vec::new()).await?;
    let mut subscription = Subscription::new(
        engine.session(
            AnalysisSelectionV1::tenant(tenant),
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
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
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
    let retained_deadline = 1 + araphor_data::GRAPH_WITNESS_TTL_NS;
    assert_eq!(expired.snapshot.next_change, Some(retained_deadline));
    assert!(expired
        .snapshot
        .witnesses
        .iter()
        .any(|witness| witness.expires_utc_ns == retained_deadline));
    assert_eq!(
        expired.snapshot.page.extraction.meta.commit_revision,
        initial.snapshot.page.extraction.meta.commit_revision
    );
    clock.now.store(retained_deadline, Ordering::SeqCst);
    clock.changes.send_replace(retained_deadline);
    let retained = tokio::time::timeout(Duration::from_secs(10), subscription.try_next())
        .await??
        .ok_or("missing retained witness deadline update")?;
    assert!(retained.clock_changed);
    assert_eq!(retained.evaluated_utc_ns, retained_deadline);
    assert_eq!(retained.snapshot.next_change, None);
    assert_eq!(
        retained.snapshot.page.extraction.meta.commit_revision,
        initial.snapshot.page.extraction.meta.commit_revision
    );
    assert!(retained
        .snapshot
        .witnesses
        .iter()
        .any(|witness| witness.expires_utc_ns == retained_deadline));
    subscription.cancel()?;
    Ok(())
}

#[tokio::test]
async fn native_notification_eligibility() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
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
    assert_eq!(routed.delivered.len(), 1);
    assert_eq!(
        *routed.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    let key = routed.delivered[0].0;
    {
        let calls = sink.calls.lock().map_err(|_| "sink lock")?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].key, key);
        assert_eq!(
            calls[0].finding.as_ref().ok_or("finding absent")?.revision,
            manifest(1)
        );
    }
    assert_eq!(router.state(key)?.deadline_utc_ns, Some(200));
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    let delivered = router.consume(&update, &sink)?;
    assert!(delivered.routed.is_empty() && delivered.delivered.is_empty());
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);
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
    assert_eq!(changed.delivered.len(), 1);
    for (_, result) in &changed.delivered {
        assert_eq!(*result.as_ref().map_err(|error| error.to_string())?, 0);
    }
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);
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
    let revised = router.consume(&update, &sink)?;
    assert_eq!(revised.routed.len(), 1);
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
    let after_revision = store.meta()?;
    let update = capture(&engine, NotificationRouter::SQL, 120).await?;
    let quiet = router.consume(&update, &sink)?;
    assert!(quiet.routed.is_empty() && quiet.delivered.is_empty());
    assert_eq!(store.meta()?, after_revision);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn native_notification_retry_deadline() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
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
    assert_eq!(route(&router, 100)?, 1);
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
async fn native_notification_retained_findings() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let empty = capture(&engine, NotificationRouter::SQL, 100).await?;
    assert_eq!(
        empty
            .batches
            .iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    assert!(!store.graph_enabled());
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    let before = store.processor_health(&ProcessorScopeV1 {
        processor_id: GRAPH_PROCESSOR.into(),
        method_version: 1,
        identity: source(),
    })?;
    let update = capture(&engine, NotificationRouter::SQL, 100).await?;
    assert_eq!(router.consume(&update, &Sink::default())?.routed.len(), 1);
    assert!(update
        .snapshot
        .results()
        .any(|reference| reference.result_id == "graph-test-1"));
    assert!(update
        .snapshot
        .witnesses
        .iter()
        .any(|witness| witness.expires_utc_ns == 1 + araphor_data::GRAPH_WITNESS_TTL_NS));
    let coverage = capture(
        &engine,
        "SELECT state FROM coverage WHERE kind = 'receipt'",
        100,
    )
    .await?;
    let batch = coverage
        .batches
        .as_ref()
        .ok_or("coverage batches")?
        .first()
        .ok_or("coverage row")?;
    let states = batch
        .column(0)
        .as_any()
        .downcast_ref::<araphor_analysis_sdk::arrow_array::StringArray>()
        .ok_or("coverage state")?;
    assert_eq!(states.value(0), "unknown");
    let after = store
        .processor_health(&ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: 1,
            identity: source(),
        })?
        .ok_or("retained processor")?;
    let before = before.ok_or("original processor")?;
    assert_eq!(after.consumed_cursor, before.consumed_cursor);
    assert_eq!(after.accepted_cursor, before.accepted_cursor);
    assert_eq!(after.incomplete, before.incomplete);
    assert!(!store.graph_enabled());
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

#[tokio::test]
async fn native_notification_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    assert_eq!(route(&router, 100)?, 1);
    let key = router.obligations(&grant(NotificationPrincipalV1::Human), 100)?[0].key;
    let update = capture(
        &engine,
        "SELECT CAST(NULL AS VARCHAR) AS finding_id, CAST(NULL AS VARCHAR) AS result_id,
        notification_id FROM notifications WHERE delivery_ready UNION ALL
        SELECT 'finding:unrelated-missing', 'graph:unrelated-missing', arrow_cast(NULL, 'Binary')
        ORDER BY notification_id NULLS LAST",
        100,
    )
    .await?;
    assert_eq!(
        update
            .batches
            .iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        2
    );
    let effects = std::cell::Cell::new(0usize);
    let checked_after_effect = std::cell::Cell::new(false);
    let result = router.consume_rows(
        [1; 16],
        100,
        update
            .batches
            .as_deref()
            .ok_or("notification batches absent")?,
        &|| {
            if effects.get() > 0 {
                checked_after_effect.set(true);
            }
            Ok(())
        },
        &mut |delivery| {
            assert_eq!(delivery.key, key);
            assert_eq!(delivery.attempt, 1);
            assert_eq!(delivery.deadline_utc_ns, 200);
            assert_eq!(
                delivery.finding.as_ref().map(|value| &value.revision),
                Some(&manifest(1))
            );
            effects.set(effects.get() + 1);
            Ok(NotificationSinkResultV1::Accepted {
                receipt: "accepted".into(),
            })
        },
    )?;
    assert!(
        checked_after_effect.get(),
        "unrelated routing ran before the ready delivery"
    );
    assert_eq!(effects.get(), 1);
    assert_eq!(result.routed.len(), 1);
    assert!(result.routed[0].1.is_err());
    assert_eq!(result.delivered.len(), 1);
    assert_eq!(result.delivered[0].0, key);
    assert_eq!(
        *result.delivered[0]
            .1
            .as_ref()
            .map_err(|error| error.to_string())?,
        1
    );
    let saved = router.state(key)?;
    assert_eq!(saved.deadline_utc_ns, Some(200));
    assert_eq!(saved.attempts.len(), 1);
    assert!(saved.attempts[0]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    Ok(())
}

#[tokio::test]
async fn stale_batch_keeps_current_and_ready_work() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let sink = Sink::default();
    configure(&router)?;
    commit_finding_at(&store, finding(1, FindingSeverityV1::High), 1, 1)?;
    commit_finding_at(&store, finding(2, FindingSeverityV1::High), 2, 2)?;
    assert_eq!(route(&router, 100)?, 1);
    let update = capture(
        &engine,
        "SELECT finding_id, result_id, notification_id FROM (
            SELECT 'finding:exact-process-key' AS finding_id, 'graph-test-1' AS result_id,
                notification_id, 0 AS step FROM notifications WHERE delivery_ready
            UNION ALL SELECT 'finding:exact-process-key', 'graph-test-1',
                arrow_cast(NULL, 'Binary'), 1
            UNION ALL SELECT 'finding:missing', 'graph-test-2',
                arrow_cast(NULL, 'Binary'), 2
            UNION ALL SELECT '', 'graph-test-2', arrow_cast(NULL, 'Binary'), 3
            UNION ALL SELECT 'finding:exact-process-key', '', arrow_cast(NULL, 'Binary'), 4
            UNION ALL SELECT NULL AS finding_id, NULL AS result_id, notification_id, 5
                FROM notifications WHERE delivery_ready
            UNION ALL SELECT 'finding:exact-process-key', 'graph-test-2',
                arrow_cast(NULL, 'Binary'), 6
         ) ORDER BY step",
        100,
    )
    .await?;
    let result = router.consume(&update, &sink)?;
    assert_eq!(result.routed.len(), 5);
    assert!(matches!(
        &result.routed[0].1,
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Conflict,
                field: "current finding reference",
                ..
            }
        })
    ));
    assert!(matches!(
        &result.routed[1].1,
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Denied,
                field: "current finding scope",
                ..
            }
        })
    ));
    assert!(matches!(
        &result.routed[2].1,
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Invalid,
                field: "finding reference",
                ..
            }
        })
    ));
    assert!(matches!(
        &result.routed[3].1,
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Invalid,
                field: "finding reference",
                ..
            }
        })
    ));
    assert!(result.routed[4].1.is_ok());
    assert_eq!(result.delivered.len(), 1);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn current_head_change_after_preflight_stays_checked() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    configure(&router)?;
    commit_finding_at(&store, finding(1, FindingSeverityV1::High), 1, 1)?;
    let update = capture(
        &engine,
        "SELECT 'finding:exact-process-key' AS finding_id, 'graph-test-1' AS result_id,
            arrow_cast(NULL, 'Binary') AS notification_id",
        100,
    )
    .await?;
    let checks = std::cell::Cell::new(0);
    let effects = std::cell::Cell::new(0);
    let result = router.consume_rows(
        [1; 16],
        100,
        update.batches.as_deref().ok_or("notification rows")?,
        &|| {
            let count = checks.get();
            checks.set(count + 1);
            if count == 1 {
                commit_finding_at(&store, finding(2, FindingSeverityV1::High), 2, 2)?;
            }
            Ok(())
        },
        &mut |_| {
            effects.set(effects.get() + 1);
            Ok(NotificationSinkResultV1::Accepted {
                receipt: "accepted".into(),
            })
        },
    )?;
    assert!(checks.get() >= 2);
    assert_eq!(effects.get(), 0);
    assert_eq!(result.routed.len(), 1);
    assert!(matches!(
        &result.routed[0].1,
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Conflict,
                field: "current finding reference",
                ..
            }
        })
    ));
    Ok(())
}
