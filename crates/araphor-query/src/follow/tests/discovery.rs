use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use araphor_discovery_effects::ObservedEffects;
use datafusion::common::ScalarValue;
use futures_util::StreamExt as _;

use super::{
    next, values, AnalysisReadControl, AnalysisSelectionV1, Duration, EvidenceIntakeIdentityV1,
    Fixture, Limits, Operation, Subscription, TestClock,
};

const COUNTS: &str = "SELECT event_count, first_cursor, last_cursor, binding_id, source_id
    FROM discovery.observed_effects((SELECT * FROM events)) ORDER BY source_id";

fn fixture(limits: Limits) -> Fixture {
    let mut fixture = Fixture::new(limits);
    Arc::get_mut(&mut fixture.engine)
        .unwrap()
        .register_relation_planner(Arc::new(ObservedEffects))
        .unwrap();
    fixture
}

async fn subscribe(
    fixture: &Fixture,
    sql: &str,
    clock: Arc<TestClock>,
) -> (Subscription, Arc<AnalysisReadControl>) {
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
    let subscription = fixture
        .engine
        .subscribe(
            sql,
            vec![],
            fixture.selection(),
            Arc::clone(&control),
            b"discovery package",
            None,
            clock,
            true,
        )
        .await
        .unwrap();
    (subscription, control)
}

fn assert_released(fixture: &Fixture) {
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .reserve_stream(fixture.source.tenant_id)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(fixture.engine.limits().input_capacity)
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(fixture.engine.limits().output_capacity)
            .unwrap(),
    );
}

#[tokio::test]
async fn updates_keep_source_scope() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&other, 1, 3, 1_100_000_000);
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&foreign, 1, 5, 1_200_000_000);
    let (_, sources) = fixture.engine.prepare(COUNTS, vec![]).await.unwrap();
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        ["events"]
    );
    let (mut subscription, _) = subscribe(&fixture, COUNTS, TestClock::new(2_000_000_000)).await;
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(values(&first, 1), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(values(&first, 2), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&first, 3), [ScalarValue::Binary(None)]);
    assert_eq!(
        values(&first, 4),
        [ScalarValue::Binary(Some(fixture.source.source_id.to_vec()))]
    );
    assert_eq!(first.snapshot.witnesses.len(), 2);
    fixture.commit(&fixture.source, 3, 1, 1_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(3))]);
    assert_eq!(values(&second, 1), [ScalarValue::UInt64(Some(1))]);
    assert_eq!(values(&second, 2), [ScalarValue::UInt64(Some(3))]);
    assert!(second.cursor.read_revision() > first.cursor.read_revision());
    assert_eq!(second.snapshot.witnesses.len(), 3);
    assert!(second.snapshot.witnesses.iter().all(|witness| {
        matches!(&witness.identity, araphor_data::AnalysisStreamIdentityV1::Evidence(identity) if identity == &fixture.source)
    }));
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(first.snapshot.witnesses.len(), 2);
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn tenant_sources_stay_separate() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&other, 1, 3, 1_100_000_000);
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    fixture.commit(&foreign, 1, 5, 1_200_000_000);
    let mut subscription = fixture
        .engine
        .subscribe(
            COUNTS,
            vec![],
            AnalysisSelectionV1::tenant(fixture.source.tenant_id),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"tenant discovery",
            None,
            TestClock::new(2_000_000_000),
            false,
        )
        .await
        .unwrap();
    let result = next(&mut subscription).await;
    assert_eq!(
        values(&result, 0),
        [ScalarValue::Int64(Some(2)), ScalarValue::Int64(Some(3))]
    );
    assert_eq!(
        values(&result, 4),
        [
            ScalarValue::Binary(Some(fixture.source.source_id.to_vec())),
            ScalarValue::Binary(Some(other.source_id.to_vec())),
        ]
    );
    assert_eq!(
        values(&result, 3),
        [ScalarValue::Binary(None), ScalarValue::Binary(None)]
    );
    assert_eq!(result.snapshot.witnesses.len(), 5);
    assert!(subscription.next().await.is_none());
}

#[tokio::test]
async fn window_expires_without_intake() {
    let fixture = fixture(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_123);
    fixture.commit(&fixture.source, 2, 1, 3_000_000_000);
    let clock = TestClock::new(4_000_000_000);
    let sql = "SELECT event_count, first_cursor, last_cursor,
            first_received_at, last_received_at
        FROM discovery.observed_effects((SELECT * FROM events
            WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '3 seconds'))";
    let (mut subscription, _) = subscribe(&fixture, sql, Arc::clone(&clock)).await;
    assert_eq!(subscription.moving_resolution_ns(), Some(1_000));
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(
        values(&first, 3),
        [ScalarValue::TimestampMicrosecond(Some(1_000_000), None)]
    );
    assert_eq!(
        values(&first, 4),
        [ScalarValue::TimestampMicrosecond(Some(3_000_000), None)]
    );
    let revision = first.snapshot.page.extraction.meta.commit_revision;
    clock.set(4_000_001_000);
    let second = next(&mut subscription).await;
    assert!(second.clock_changed);
    assert_eq!(values(&second, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(values(&second, 1), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(values(&second, 2), [ScalarValue::UInt64(Some(2))]);
    assert_eq!(second.snapshot.witnesses.len(), 1);
    assert_eq!(
        second.snapshot.page.extraction.meta.commit_revision,
        revision
    );
    clock.set(6_000_001_000);
    let empty = next(&mut subscription).await;
    assert!(empty.clock_changed);
    assert!(values(&empty, 0).is_empty());
    assert!(empty.snapshot.witnesses.is_empty());
    assert_eq!(
        empty.snapshot.page.extraction.meta.commit_revision,
        revision
    );
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn idle_waits_for_events() {
    let fixture = fixture(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let (mut subscription, control) = subscribe(&fixture, COUNTS, Arc::clone(&clock)).await;
    drop(next(&mut subscription).await);
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&reads);
    control
        .on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    {
        let waiting = subscription.next();
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        let clock_reads = clock.reads.load(Ordering::SeqCst);
        clock.now.store(1_000_000_000_000, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_millis(40), waiting.as_mut())
                .await
                .is_err()
        );
        assert_eq!(clock.reads.load(Ordering::SeqCst), clock_reads);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        control.cancel().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(8), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    }
    assert!(subscription.next().await.is_none());
    drop(subscription);
    assert_released(&fixture);
}

#[tokio::test]
async fn cancel_joins_source_read() {
    let fixture = fixture(Limits {
        tenant_streams: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let (mut subscription, control) =
        subscribe(&fixture, COUNTS, TestClock::new(2_000_000_000)).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let joined = Arc::new(AtomicBool::new(false));
    let started = Arc::clone(&entered);
    let finished = Arc::clone(&joined);
    let (release, released) = std::sync::mpsc::channel();
    control
        .on_read_step(move || {
            started.notify_one();
            released.recv().unwrap();
            finished.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    let worker = tokio::spawn(async move {
        let result = subscription.next().await;
        (subscription, result)
    });
    tokio::time::timeout(Duration::from_secs(8), entered.notified())
        .await
        .unwrap();
    control.cancel().unwrap();
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    assert!(!joined.load(Ordering::SeqCst));
    release.send(()).unwrap();
    let (mut subscription, result) = tokio::time::timeout(Duration::from_secs(8), worker)
        .await
        .unwrap()
        .unwrap();
    let error = result.unwrap().unwrap_err();
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    assert!(joined.load(Ordering::SeqCst));
    assert!(subscription.next().await.is_none());
    drop(subscription);
    assert_released(&fixture);
}
