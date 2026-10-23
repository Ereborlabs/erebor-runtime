use super::*;

#[tokio::test]
async fn native_clock_waits_source() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut stream = fixture.subscribe(
        "SELECT source_cursor, CURRENT_TIMESTAMP AS observed FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut stream).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(first.snapshot.next_change, None);
    assert_eq!(
        values(&first, 1),
        [ScalarValue::TimestampNanosecond(Some(2_000_000_000), None)]
    );
    assert!(futures_util::poll!(stream.next()).is_pending());
    clock.set(3_000_000_000);
    let metadata = next(&mut stream).await;
    assert!(metadata.batches.is_none());
    assert_eq!(metadata.evaluated_utc_ns, 2_000_000_000);
    assert!(metadata.completed_windows.is_empty());
    assert!(futures_util::poll!(stream.next()).is_pending());
    fixture.commit(&fixture.source, 2, 1, 2_500_000_000);
    let changed = next(&mut stream).await;
    assert_eq!(changed.evaluated_utc_ns, 3_000_000_000);
    assert_eq!(
        values(&changed, 1),
        [
            ScalarValue::TimestampNanosecond(Some(3_000_000_000), None),
            ScalarValue::TimestampNanosecond(Some(3_000_000_000), None),
        ]
    );
    stream.cancel_and_join().await.unwrap();
}

#[tokio::test]
async fn bare_clock_without_deadline() {
    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(2_000_000_000);
    let mut stream = fixture.subscribe(
        "SELECT CURRENT_TIMESTAMP AS observed",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut stream).await;
    assert_eq!(first.snapshot.next_change, None);
    assert_eq!(
        values(&first, 0),
        [ScalarValue::TimestampNanosecond(Some(2_000_000_000), None)]
    );
    assert!(futures_util::poll!(stream.next()).is_pending());
    clock.set(3_000_000_000);
    let metadata = next(&mut stream).await;
    assert!(metadata.batches.is_none());
    assert_eq!(metadata.evaluated_utc_ns, 2_000_000_000);
    assert_eq!(metadata.snapshot.next_change, None);
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join().await.unwrap();
}

#[tokio::test]
async fn native_predicate_captures_deadline() {
    let fixture = Fixture::new(Limits::default());
    fixture.notification(100);
    let (plan, sources) = fixture.plan(
        "SELECT count(*) AS due FROM notifications WHERE CAST(deadline_utc_ns AS BIGINT) <= CAST(CURRENT_TIMESTAMP AS BIGINT)", Vec::new(),
    );
    assert!(Window::from_plan(&plan).unwrap().is_none());
    let clock = TestClock::new(99);
    let session = fixture
        .engine
        .session(
            AnalysisSelectionV1::tenant(fixture.source.tenant_id),
            &AnalysisReadControl::default(),
            0,
        )
        .unwrap();
    let mut stream = Subscription::new(
        session,
        plan,
        sources,
        b"deadline",
        None,
        clock.clone(),
        true,
    )
    .unwrap();
    let first = next(&mut stream).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(0))]);
    assert_eq!(first.snapshot.next_change, Some(100));
    let before = fixture.store.meta().unwrap();
    clock.set(100);
    let due = next(&mut stream).await;
    assert_eq!(values(&due, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(due.evaluated_utc_ns, 100);
    assert_eq!(due.snapshot.next_change, None);
    assert!(due.completed_windows.is_empty());
    assert_eq!(fixture.store.meta().unwrap(), before);
    assert!(futures_util::poll!(stream.next()).is_pending());
    clock.set(200);
    let idle = next(&mut stream).await;
    assert!(idle.batches.is_none());
    assert_eq!(idle.evaluated_utc_ns, 100);
    assert_eq!(idle.snapshot.next_change, None);
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join().await.unwrap();
}
