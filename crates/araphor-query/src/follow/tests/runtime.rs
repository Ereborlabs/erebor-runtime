use super::{
    AnalysisReadControl, BTreeMap, Duration, Expr, Parser, SourceSnapshot, Subscription,
    TableProvider,
};

use std::sync::atomic::Ordering;
use std::sync::Arc;

use araphor_data::EvidenceIntakeIdentityV1;
use datafusion::common::ScalarValue;
use futures_util::StreamExt as _;

use super::{next, values, Fixture, Limits, Operation, TestClock};

#[tokio::test]
async fn subscription_keeps_memory_scope() {
    for (sql, expected) in [
        (
            "SELECT source_cursor FROM events",
            vec![ScalarValue::UInt64(Some(2))],
        ),
        (
            "SELECT COUNT(*) AS n FROM events",
            vec![ScalarValue::Int64(Some(2))],
        ),
        (
            "SELECT SUM(source_cursor) AS n FROM events",
            vec![ScalarValue::UInt64(Some(3))],
        ),
    ] {
        let fixture = Fixture::new(Limits::default());
        fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
        let memory = fixture.engine.memory().scope();
        let epoch = memory.capacity_epoch();
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap();
        let session = fixture
            .engine
            .session_on(fixture.selection(), &control, 0, Arc::clone(&memory))
            .unwrap();
        let (plan, sources) = fixture.plan(sql, vec![]);
        let mut subscription = Subscription::new(
            session,
            plan,
            sources,
            b"scope",
            None,
            TestClock::new(2_000_000_000),
            true,
        )
        .unwrap();
        drop(next(&mut subscription).await);
        assert_eq!(memory.capacity_epoch(), epoch, "initial {sql}");
        fixture.notification(10_000_000_000);
        let metadata = next(&mut subscription).await;
        assert!(metadata.batches.is_none());
        drop(metadata);
        assert_eq!(memory.capacity_epoch(), epoch, "metadata {sql}");
        fixture.commit(&fixture.source, 2, 1, 1_500_000_000);
        let update = next(&mut subscription).await;
        assert_eq!(values(&update, 0), expected);
        let borrowed = Arc::clone(update.batches.as_ref().unwrap()[0].column(0));
        drop(update);
        drop(subscription);
        assert!(!borrowed.is_empty());
        drop(borrowed);
        assert_eq!(memory.capacity_epoch(), epoch, "complete {sql}");
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
}

#[tokio::test]
async fn subscription_keeps_bindings() {
    use datafusion::arrow::array::{ArrayRef, UInt64Array};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};

    let fixture = Fixture::new(Limits::default());
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::UInt64,
        false,
    )]));
    let column = Arc::new(UInt64Array::from(vec![7, 9])) as ArrayRef;
    let batch = datafusion::arrow::array::RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::clone(&column)],
    )
    .unwrap();
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap();
    let mut session = fixture
        .engine
        .session(fixture.selection(), &control, 0)
        .unwrap();
    session
        .register("provided", Arc::clone(&schema), &[batch])
        .unwrap();
    session
        .set_output(2, fixture.engine.limits().output_bytes)
        .unwrap();
    let mut limited = session.clone();
    limited
        .set_output(1, fixture.engine.limits().output_bytes)
        .unwrap();
    let provider = crate::sources::SourceProvider::local("provided", Arc::clone(&schema));
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("provided".into(), provider)]))
        .unwrap();
    let statement = Parser::default()
        .parse("SELECT value FROM provided")
        .unwrap();
    let plan = Arc::new(fixture.engine.plan(&state, statement, vec![]).unwrap());
    let mut subscription = Subscription::new(
        session,
        Arc::clone(&plan),
        BTreeMap::new(),
        b"provided",
        None,
        TestClock::new(2_000_000_000),
        false,
    )
    .unwrap();
    let update = next(&mut subscription).await;
    assert_eq!(
        values(&update, 0),
        vec![ScalarValue::UInt64(Some(7)), ScalarValue::UInt64(Some(9))]
    );
    assert!(!update.limited);
    assert!(update.snapshot.selection.sources.is_empty());
    assert!(update.snapshot.witnesses.is_empty());
    assert!(subscription.next().await.is_none());
    let mut limited = Subscription::new(
        limited,
        plan,
        BTreeMap::new(),
        b"provided",
        None,
        TestClock::new(2_000_000_000),
        false,
    )
    .unwrap();
    assert!(limited.next().await.unwrap().is_err());
    assert!(limited.next().await.is_none());
    assert_eq!(column.len(), 2);
}

#[tokio::test]
async fn unchanged_result_advances_cursor() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events WHERE source_cursor = 1",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(first.evaluated_utc_ns, 2_000_000_000);

    // Change the test time without an extra clock notification.
    clock.now.store(3_000_000_000, Ordering::SeqCst);
    fixture.commit(&fixture.source, 2, 1, 2_500_000_000);
    let completed = next(&mut subscription).await;
    assert!(completed.batches.is_none());
    assert!(!completed.clock_changed);
    assert_eq!(completed.evaluated_utc_ns, 3_000_000_000);
    assert!(completed.cursor.read_revision() > first.cursor.read_revision());
    assert_eq!(
        completed.cursor.read_revision(),
        completed.snapshot.page.extraction.meta.commit_revision
    );
    assert_ne!(completed.cursor, first.cursor);
    assert_eq!(
        completed
            .snapshot
            .witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );

    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    clock.now.store(4_000_000_000, Ordering::SeqCst);
    fixture.commit(&other, 1, 1, 3_500_000_000);
    let unrelated = next(&mut subscription).await;
    assert!(unrelated.batches.is_none());
    assert!(!unrelated.clock_changed);
    assert_eq!(unrelated.cursor, completed.cursor);
    assert_eq!(unrelated.evaluated_utc_ns, completed.evaluated_utc_ns);
    assert!(
        unrelated.snapshot.page.extraction.meta.commit_revision > completed.cursor.read_revision()
    );

    clock.set(5_000_000_000);
    let health = next(&mut subscription).await;
    assert!(health.batches.is_none());
    assert!(health.clock_changed);
    assert_eq!(health.cursor, completed.cursor);
    assert_eq!(health.evaluated_utc_ns, completed.evaluated_utc_ns);
    assert_eq!(
        health.snapshot.page.extraction.meta,
        unrelated.snapshot.page.extraction.meta
    );
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn health_uses_remaining_capacity() {
    let metadata_space = 64 * 1024;
    let fixture = Fixture::new(Limits {
        input_bytes: 2 * 1024 * 1024,
        input_capacity: 2 * 1024 * 1024 + metadata_space,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 128, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(128))]);
    assert_eq!(first.snapshot.witnesses.len(), 128);
    let cursor = first.cursor.clone();
    let evaluated = first.evaluated_utc_ns;
    let receipt = Arc::clone(&first.snapshot);
    let borrowed = Arc::clone(first.batches.as_ref().unwrap()[0].column(0));
    drop(first);

    let memory = fixture.engine.memory();
    let input_capacity = fixture.engine.limits().input_capacity;
    let output_capacity = fixture.engine.limits().output_capacity;
    let available = {
        let reservation = memory.prepare_input(input_capacity).unwrap();
        reservation.size()
    };
    assert!(available > metadata_space);
    let pressure = memory.reserve_input(available - metadata_space).unwrap();
    assert!(memory
        .reserve_input(fixture.engine.limits().input_bytes)
        .is_err());

    clock.set(3_000_000_000);
    let health = next(&mut subscription).await;
    assert!(health.batches.is_none());
    assert!(health.clock_changed);
    assert_eq!(health.cursor, cursor);
    assert_eq!(health.evaluated_utc_ns, evaluated);
    assert_eq!(
        health.snapshot.page.extraction.meta,
        receipt.page.extraction.meta
    );
    assert_eq!(health.snapshot.page.extraction.scanned_bytes, 0);
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0).unwrap(),
        ScalarValue::Int64(Some(128))
    );
    assert!(memory
        .reserve_input(fixture.engine.limits().input_bytes)
        .is_err());
    drop(health);
    drop(pressure);
    subscription.cancel().unwrap();
    drop(subscription);
    assert_eq!(receipt.witnesses.len(), 128);
    drop(receipt);

    assert!(memory.reserve_input(input_capacity).is_err());
    assert!(memory.reserve_output(output_capacity).is_err());
    assert_eq!(
        ScalarValue::try_from_array(&borrowed, 0).unwrap(),
        ScalarValue::Int64(Some(128))
    );
    drop(borrowed);
    drop(memory.reserve_input(input_capacity).unwrap());
    drop(memory.reserve_output(output_capacity).unwrap());
}

#[tokio::test]
async fn fallback_sum_keeps_progress() {
    let fixture = Fixture::new(Limits {
        output_rows: 1,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT CAST(sum(source_cursor) AS BIGINT UNSIGNED) AS total FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::UInt64(Some(3))]);
    assert_eq!(first.evaluated_utc_ns, 2_000_000_000);
    assert_eq!(first.snapshot.witnesses.len(), 2);
    assert_eq!(
        first.cursor.read_revision(),
        first.snapshot.page.extraction.meta.commit_revision
    );
    assert!(first.exhausted && !first.limited);
    let cursor = first.cursor.clone();
    drop(first);

    clock.now.store(3_000_000_000, Ordering::SeqCst);
    fixture.commit(&fixture.source, 3, 1, 2_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(second.operation, Operation::Replace);
    assert_eq!(values(&second, 0), [ScalarValue::UInt64(Some(6))]);
    assert_eq!(second.evaluated_utc_ns, 3_000_000_000);
    assert_eq!(second.snapshot.witnesses.len(), 3);
    assert!(second.cursor.read_revision() > cursor.read_revision());
    assert_eq!(
        second.cursor.read_revision(),
        second.snapshot.page.extraction.meta.commit_revision
    );
    assert!(second.exhausted && !second.limited);
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn finite_query_freezes_clock() {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Limits::default());
    let clock = TestClock::new(1_700_000_000_123_456_789);
    let mut subscription = fixture.subscribe(
        "SELECT now() AS first_clock, current_timestamp AS second_clock",
        clock.clone(),
        None,
        false,
    );
    assert_eq!(clock.reads.load(Ordering::SeqCst), 0);
    let now = 1_700_000_005_987_654_321;
    clock.now.store(now, Ordering::SeqCst);
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(first.evaluated_utc_ns, now);
    for column in 0..2 {
        assert_eq!(
            values(&first, column),
            [ScalarValue::TimestampNanosecond(Some(now as i64), None)]
        );
    }
    assert!(first.exhausted && !first.limited);
    assert!(clock.reads.load(Ordering::SeqCst) > 0);
    assert!(subscription.next().await.is_none());
    drop(first);
    drop(subscription);
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
}

#[tokio::test]
async fn join_uses_new_cut() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let sql =
        "SELECT COUNT(*) AS total FROM events a JOIN events b ON a.source_cursor = b.source_cursor";
    let (plan, sources) = fixture.plan(sql, vec![]);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(sql, clock, None, true);
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(1))]);
    assert_eq!(first.snapshot.witnesses.len(), 1);
    let cursor = first.cursor.clone();
    drop(first);

    fixture.commit(&fixture.source, 2, 1, 1_500_000_000);
    let second = next(&mut subscription).await;
    assert_eq!(second.operation, Operation::Replace);
    assert_eq!(values(&second, 0), vec![ScalarValue::Int64(Some(2))]);
    assert_eq!(second.snapshot.witnesses.len(), 2);
    assert!(second.cursor.read_revision() > cursor.read_revision());
    assert_eq!(second.cursor.position().ordinal, 0);
    assert_eq!(
        second.cursor.read_revision(),
        second.snapshot.page.extraction.meta.commit_revision,
    );
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap();
    let (snapshot, batches) = fixture
        .engine
        .session(fixture.selection(), &control, second.evaluated_utc_ns)
        .unwrap()
        .execute(plan, &sources)
        .unwrap();
    assert_eq!(
        snapshot.page.extraction.meta,
        second.snapshot.page.extraction.meta
    );
    assert_eq!(second.batches.as_ref().unwrap(), &batches);
    assert!(batches
        .iter()
        .all(|batch| batch.schema() == subscription.schema()));
}

#[derive(Debug)]
struct PlanningGate {
    inner: Arc<dyn TableProvider>,
    entered: Arc<tokio::sync::Notify>,
    released: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl TableProvider for PlanningGate {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn schema(&self) -> datafusion::arrow::datatypes::SchemaRef {
        self.inner.schema()
    }

    fn table_type(&self) -> datafusion::logical_expr::TableType {
        self.inner.table_type()
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> datafusion::common::Result<Vec<datafusion::logical_expr::TableProviderFilterPushDown>>
    {
        self.inner.supports_filters_pushdown(filters)
    }

    async fn scan(
        &self,
        state: &dyn datafusion::catalog::Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> datafusion::common::Result<Arc<dyn datafusion::physical_plan::ExecutionPlan>> {
        let released = self.released.notified();
        self.entered.notify_one();
        released.await;
        self.inner.scan(state, projection, filters, limit).await
    }
}

#[tokio::test]
async fn planning_keeps_clock_change() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let entered = Arc::new(tokio::sync::Notify::new());
    let released = Arc::new(tokio::sync::Notify::new());
    let provider: Arc<dyn TableProvider> = Arc::new(PlanningGate {
        inner: SourceSnapshot::providers()["events"].clone(),
        entered: Arc::clone(&entered),
        released: Arc::clone(&released),
    });
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("events".into(), provider)]))
        .unwrap();
    let plan = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::default()
                    .parse("SELECT COUNT(*) AS total FROM events")
                    .unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture
        .engine
        .session(
            fixture.selection(),
            &(Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap())),
            0,
        )
        .and_then(|session| {
            Subscription::new(
                session,
                plan,
                BTreeMap::from([("events".into(), None)]),
                b"planning clock principal",
                None,
                clock.clone(),
                true,
            )
        })
        .unwrap();
    assert_eq!(clock.reads.load(Ordering::SeqCst), 0);
    let first = tokio::spawn(async move {
        let update = next(&mut subscription).await;
        (subscription, update)
    });
    tokio::time::timeout(Duration::from_secs(8), entered.notified())
        .await
        .unwrap();
    assert_eq!(clock.now.load(Ordering::SeqCst), 2_000_000_000);
    clock.set(3_000_000_000);
    released.notify_one();
    let (mut subscription, first) = first.await.unwrap();
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(first.evaluated_utc_ns, 2_000_000_000);
    assert_eq!(values(&first, 0), vec![ScalarValue::Int64(Some(1))]);
    assert_eq!(first.snapshot.witnesses.len(), 1);
    let health = next(&mut subscription).await;
    assert!(health.batches.is_none());
    assert!(health.clock_changed);
    assert_eq!(health.cursor, first.cursor);
    assert_eq!(health.evaluated_utc_ns, first.evaluated_utc_ns);
    assert_eq!(
        health.snapshot.page.extraction.meta,
        first.snapshot.page.extraction.meta
    );
}

#[tokio::test]
async fn native_first_clock_time() {
    let fixture = Fixture::new(Limits {
        tenant_evaluations: 1,
        ..Default::default()
    });
    let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
    let clock = TestClock::new(2_000_000_000);
    let (plan, sources) = fixture.plan("SELECT CURRENT_TIMESTAMP AS observed", vec![]);
    assert!(sources.is_empty());
    let schema = Arc::clone(plan.schema().inner());
    let session = fixture
        .engine
        .session(fixture.selection(), &control, 2_000_000_000)
        .unwrap();
    let mut state = session.state().unwrap();
    state
        .config_mut()
        .set_extension(Arc::new(crate::stream::Run {
            session: Arc::new(
                fixture
                    .engine
                    .session(fixture.selection(), &control, 0)
                    .unwrap(),
            ),
            sources,
            plan: Arc::clone(&plan),
            clock: clock.clone(),
            follow: false,
            operation: Operation::Replace,
            window: None,
            resume: None,
        }));
    let logical = crate::planner::subscription::Subscribe::runtime(plan.as_ref().clone(), false);
    let physical = state.create_physical_plan(&logical).await.unwrap();
    assert!(physical
        .as_any()
        .is::<crate::stream::physical::SubscribeExec>());
    assert_eq!(physical.schema(), schema);
    let context = state.task_ctx();
    drop(state);
    drop(session);
    drop(plan);

    clock.set(3_000_000_000);
    let mut stream = physical.execute(0, context).unwrap();
    drop(physical);
    let batch = stream.next().await.unwrap().unwrap();
    assert_eq!(batch.schema(), schema);
    assert_eq!(batch.num_columns(), 1);
    assert_eq!(batch.num_rows(), 1);
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::TimestampNanosecondArray>()
            .unwrap()
            .value(0),
        3_000_000_000,
    );
    drop(
        fixture
            .engine
            .reserve_evaluation(fixture.source.tenant_id)
            .unwrap(),
    );
    let borrowed = Arc::clone(batch.column(0));
    drop(batch);
    assert!(stream.next().await.is_none());
    drop(stream);
    control.check().unwrap();
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_err());
    assert_eq!(
        borrowed
            .as_any()
            .downcast_ref::<datafusion::arrow::array::TimestampNanosecondArray>()
            .unwrap()
            .value(0),
        3_000_000_000,
    );
    drop(borrowed);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[tokio::test]
async fn native_page_follow_properties() {
    use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};

    for follow in [false, true] {
        let fixture = Fixture::new(Limits {
            output_rows: 1,
            ..Default::default()
        });
        fixture.commit(&fixture.source, 1, 2, 1_000_000_000);
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap());
        let clock = TestClock::new(2_000_000_000);
        let (plan, sources) = fixture.plan("SELECT source_cursor FROM events", vec![]);
        let schema = Arc::clone(plan.schema().inner());
        let session = fixture
            .engine
            .session(fixture.selection(), &control, 2_000_000_000)
            .unwrap();
        let mut state = session.state().unwrap();
        state
            .config_mut()
            .set_extension(Arc::new(crate::stream::Run {
                session: Arc::new(session.clone()),
                sources,
                plan: Arc::clone(&plan),
                clock,
                follow,
                operation: Operation::Append,
                window: None,
                resume: None,
            }));
        let logical = crate::planner::subscription::Subscribe::runtime(plan.as_ref().clone(), true);
        let physical = state.create_physical_plan(&logical).await.unwrap();
        assert!(physical
            .as_any()
            .is::<crate::stream::physical::SubscribeExec>());
        assert_eq!(physical.schema(), schema);
        assert_eq!(
            physical.properties().boundedness,
            Boundedness::Unbounded {
                requires_infinite_memory: false,
            }
        );
        assert_eq!(
            physical.properties().emission_type,
            EmissionType::Incremental
        );
        assert_eq!(physical.children().len(), 1);
        assert_eq!(
            physical.children()[0].properties().boundedness,
            Boundedness::Bounded
        );
        let mut stream = physical.execute(0, state.task_ctx()).unwrap();
        drop(physical);
        drop(state);
        drop(session);
        drop(plan);
        let first = tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first.schema(), schema);
        assert_eq!(first.num_columns(), 1);
        assert_eq!(first.num_rows(), 1);
        assert_eq!(
            ScalarValue::try_from_array(first.column(0), 0).unwrap(),
            ScalarValue::UInt64(Some(1))
        );
        drop(first);
        if !follow {
            assert!(tokio::time::timeout(Duration::from_secs(8), stream.next())
                .await
                .unwrap()
                .is_none());
            continue;
        }
        let second = tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(second.schema(), schema);
        assert_eq!(second.num_rows(), 1);
        assert_eq!(
            ScalarValue::try_from_array(second.column(0), 0).unwrap(),
            ScalarValue::UInt64(Some(2))
        );
        drop(second);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );
        fixture.commit(&fixture.source, 3, 1, 1_500_000_000);
        let third = tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(third.schema(), schema);
        assert_eq!(third.num_rows(), 1);
        assert_eq!(
            ScalarValue::try_from_array(third.column(0), 0).unwrap(),
            ScalarValue::UInt64(Some(3))
        );
        drop(third);
        control.cancel().unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap()
            .is_err());
    }
}

#[tokio::test]
async fn subscription_prunes_columns() {
    use datafusion::common::tree_node::{TreeNode as _, TreeNodeRecursion};
    use datafusion::physical_plan::ExecutionPlan;

    let fixture = Fixture::new(Limits {
        scan_bytes: 32 * 1024,
        input_bytes: 64 * 1024,
        ..Default::default()
    });
    fixture.commit(&fixture.source, 1, 1, 50_000_000_000);
    fixture.commit(&fixture.source, 2, 1, 90_000_000_000);
    let sql = "SELECT COUNT(*) AS total FROM events WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '60 seconds'";
    let (plan, _) = fixture.plan(sql, vec![]);
    let now = 100_000_000_000;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap();
    let session = fixture
        .engine
        .session(fixture.selection(), &control, now)
        .unwrap();
    let state = session.state().unwrap();
    let ordinary = session.physical(&plan, &state).await.unwrap();
    let wrapped = crate::planner::subscription::Subscribe::runtime(plan.as_ref().clone(), false);
    let subscription = session.physical(&wrapped, &state).await.unwrap();
    let scans = |physical: &Arc<dyn ExecutionPlan>| {
        let mut schemas = Vec::new();
        physical
            .apply(|node| {
                if crate::sources::SourceData::from_plan(node.as_ref()).is_some() {
                    schemas.push(node.schema());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
        schemas
    };
    let ordinary_scans = scans(&ordinary);
    let subscription_scans = scans(&subscription);
    assert_eq!(ordinary_scans.len(), 1);
    assert_eq!(subscription_scans.len(), 1);
    assert!(ordinary_scans[0].fields().len() < SourceSnapshot::schemas()["events"].fields().len());
    assert_eq!(subscription_scans, ordinary_scans);
    drop(subscription);
    drop(ordinary);
    drop(state);
    drop(session);

    let mut subscription = fixture.subscribe(sql, TestClock::new(now), None, true);
    let first = next(&mut subscription).await;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(values(&first, 0), [ScalarValue::Int64(Some(2))]);
    assert_eq!(first.evaluated_utc_ns, now);
    assert!(first.exhausted && !first.limited);
    assert_eq!(first.snapshot.witnesses.len(), 2);
    assert_eq!(
        first
            .snapshot
            .witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(first
        .snapshot
        .witnesses
        .iter()
        .all(|witness| matches!(&witness.identity, araphor_data::AnalysisStreamIdentityV1::Evidence(identity) if identity == &fixture.source)));
    assert_eq!(
        first.cursor.read_revision(),
        first.snapshot.page.extraction.meta.commit_revision
    );
    assert!(first.snapshot.page.extraction.scanned_bytes <= fixture.engine.limits().scan_bytes);
    assert!(first.snapshot.page.extraction.input_bytes <= fixture.engine.limits().input_bytes);
    assert!(first
        .batches
        .as_ref()
        .unwrap()
        .iter()
        .all(|batch| batch.schema() == subscription.schema()));
    subscription.cancel().unwrap();
}

#[tokio::test]
async fn clock_keeps_pending_source() {
    let fixture = Fixture::new(Limits::default());
    fixture.commit(&fixture.source, 1, 1, 1_000_000_000);
    let clock = TestClock::new(2_000_000_000);
    let mut subscription = fixture.subscribe(
        "SELECT count(*) AS total FROM events",
        clock.clone(),
        None,
        true,
    );
    let first = next(&mut subscription).await;
    fixture.commit(&fixture.source, 2, 1, 2_500_000_000);
    clock.set(3_000_000_000);
    let health = next(&mut subscription).await;
    assert!(health.clock_changed);
    assert!(health.batches.is_none());
    assert_eq!(health.cursor, first.cursor);
    assert_eq!(health.evaluated_utc_ns, first.evaluated_utc_ns);
    let changed = next(&mut subscription).await;
    assert_eq!(values(&changed, 0), [ScalarValue::Int64(Some(2))]);
    assert!(changed.cursor.read_revision() > first.cursor.read_revision());
    assert!(!changed.clock_changed);
}
