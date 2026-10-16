use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use datafusion::arrow::array::{ArrayRef, Int64Array, RecordBatch};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::catalog::{Session as NativeSession, TableProvider};
use datafusion::common::{Result as NativeResult, ScalarValue};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, LogicalPlan, TableType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::{PartitionStream, StreamingTableExec};
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use erebor_runtime_error::{ErrorExt as _, StatusCode};
use futures_util::TryStreamExt as _;
use tokio::sync::Notify;

use super::{Engine, Limits, Read};
use crate::parser::Parser;
use crate::planner::Planner;
use crate::Error;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(mut limits: Limits) -> Self {
        limits.extract_timeout = Duration::from_secs(5);
        limits.evaluate_timeout = Duration::from_secs(5);
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(store, limits).unwrap();
        Self {
            engine,
            _directory: directory,
        }
    }
}

fn control() -> AnalysisReadControl {
    AnalysisReadControl::with_timeout(Duration::from_secs(10)).unwrap()
}

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]))
}

fn batch(value: i64) -> RecordBatch {
    let values: ArrayRef = Arc::new(Int64Array::from(vec![value]));
    RecordBatch::try_new(schema(), vec![values]).unwrap()
}

#[tokio::test]
async fn waiting_preserves_global_capacity() {
    let fixture = Fixture::new(Limits::default());
    let held = fixture.engine.reserve_evaluation([1; 16]).unwrap();
    {
        let waiting = fixture.engine.acquire_evaluation([1; 16]);
        futures_util::pin_mut!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let other = fixture.engine.reserve_evaluation([2; 16]).unwrap();
        drop(other);
        drop(held);
        let acquired = waiting.await.unwrap();
        assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
        drop(acquired);
    }
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_ok());
}

#[tokio::test]
async fn subscription_admission_is_shared() {
    use futures_util::StreamExt as _;

    let fixture = Fixture::new(Limits::default());
    let sql = "WITH unused AS (SELECT * FROM events) SELECT $1 AS value";
    let (plan, sources) = fixture
        .engine
        .prepare(sql, vec![ScalarValue::Int64(Some(17))])
        .await
        .unwrap();
    assert_eq!(sources, BTreeSet::from(["events".into()]));
    assert_eq!(plan.schema().field(0).name(), "value");
    let control = Arc::new(control());
    let mut subscription = fixture
        .engine
        .subscribe(
            sql,
            vec![ScalarValue::Int64(Some(17))],
            AnalysisSelectionV1::new([1; 16], vec![]),
            Arc::clone(&control),
            b"native-admission",
            None,
            Arc::new(crate::follow::SystemClock::default()),
            false,
        )
        .await
        .unwrap();
    let update = subscription.next().await.unwrap().unwrap();
    assert_eq!(value(update.batches.as_ref().unwrap()), 17);
    assert!(subscription.next().await.is_none());
    drop(subscription);
    assert!(control.check().is_err());
    assert!(fixture
        .engine
        .prepare("DELETE FROM events", vec![])
        .await
        .is_err());
    assert!(fixture.engine.prepare(sql, vec![]).await.is_err());
}

fn value(batches: &[RecordBatch]) -> i64 {
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .value(0)
}

fn local_plan(engine: &Engine) -> (Arc<LogicalPlan>, BTreeSet<String>) {
    let catalog = engine
        .catalog(BTreeMap::from([("local_rows".into(), schema())]))
        .unwrap();
    let statement = Parser::parse("SELECT value FROM local_rows").unwrap();
    let sources = catalog
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| source.table().to_owned())
        .collect();
    let plan = engine.plan(&catalog, statement, vec![]).unwrap();
    (Arc::new(plan), sources)
}

#[test]
fn local_skips_store() {
    let fixture = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let state = fixture.engine.catalog(BTreeMap::new()).unwrap();
    let clock = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::parse("SELECT CURRENT_TIMESTAMP AS clock").unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let constant = Arc::new(
        fixture
            .engine
            .plan(&state, Parser::parse("SELECT 7 AS value").unwrap(), vec![])
            .unwrap(),
    );
    let source = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::parse("SELECT source_cursor FROM events").unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let frozen = 1_234_567_890;
    let mut session = fixture
        .engine
        .session(
            AnalysisSelectionV1::new([1; 16], vec![]),
            &control(),
            frozen,
        )
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(11)])
        .unwrap();
    let meta = fixture.engine.store().meta().unwrap();
    let mut readers = Vec::new();
    while let Ok(permit) = fixture.engine.store().reserve_trace_read() {
        readers.push(permit);
    }
    assert!(!readers.is_empty());
    assert!(fixture.engine.store().reserve_trace_read().is_err());
    assert_eq!(value(&session.execute_local(plan).unwrap()), 11);
    let now = session.execute_local(clock).unwrap();
    assert!(
        matches!(ScalarValue::try_from_array(now[0].column(0), 0).unwrap(),
        ScalarValue::TimestampNanosecond(Some(value), _) if value == frozen as i64)
    );
    session
        .register(
            "events",
            crate::sources::SourceSnapshot::providers()["events"].schema(),
            &[],
        )
        .unwrap();
    assert!(session.execute_local(source).is_err());
    let error = session
        .execute(Arc::clone(&constant), &BTreeSet::new())
        .unwrap_err();
    assert!(
        matches!(error, Error::Sql { source: datafusion::common::DataFusionError::External(source) }
        if matches!(source.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisBusy { resource: "reader", .. })))
    );
    drop(readers);
    assert!(matches!(
        session.execute(Arc::clone(&constant), &BTreeSet::new()),
        Err(Error::Data {
            source: araphor_data::Error::AnalysisReadCancelled { .. }
        })
    ));
    let session = fixture
        .engine
        .session(
            AnalysisSelectionV1::new([1; 16], vec![]),
            &control(),
            frozen,
        )
        .unwrap();
    let (receipt, rows) = session.execute(constant, &BTreeSet::new()).unwrap();
    assert_eq!(value(&rows), 7);
    assert_eq!(receipt.page.extraction.meta, meta);
}

#[test]
fn local_output_bounds() {
    let fixture = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    let values: ArrayRef = Arc::new(Int64Array::from(vec![11, 22]));
    session
        .register(
            "local_rows",
            schema(),
            &[RecordBatch::try_new(schema(), vec![values]).unwrap()],
        )
        .unwrap();
    session
        .set_output(1, fixture.engine.limits().output_bytes)
        .unwrap();
    let error = session.execute_local(plan).unwrap_err();
    assert_eq!(error.status_code(), StatusCode::InvalidArguments);
    assert!(matches!(error, Error::Sql { source }
        if matches!(source.find_root(), datafusion::common::DataFusionError::ResourcesExhausted(_))));
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[test]
fn native_plan_reuses_inputs() {
    let fixture = Fixture::new(Limits::default());
    let (plan, sources) = local_plan(&fixture.engine);
    let mut first = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    let mut second = fixture
        .engine
        .session(AnalysisSelectionV1::new([2; 16], vec![]), &control(), 2)
        .unwrap();
    first
        .register("local_rows", schema(), &[batch(11)])
        .unwrap();
    second
        .register("local_rows", schema(), &[batch(22)])
        .unwrap();
    let (first_snapshot, first_rows) = first.execute(Arc::clone(&plan), &sources).unwrap();
    let (second_snapshot, second_rows) = second.execute(Arc::clone(&plan), &sources).unwrap();
    assert_eq!(value(&first_rows), 11);
    assert_eq!(value(&second_rows), 22);
    assert_eq!(first_snapshot.selection.tenant_id, [1; 16]);
    assert_eq!(second_snapshot.selection.tenant_id, [2; 16]);
    first
        .register("local_rows", schema(), &[batch(33)])
        .unwrap();
    let (_, rows) = first.execute(Arc::clone(&plan), &sources).unwrap();
    assert_eq!(value(&rows), 33);
    assert_eq!(value(&first_rows), 11);
    assert_eq!(value(&second_rows), 22);
}

#[test]
fn native_counts_rebind() {
    let fixture = Fixture::new(Limits::default());
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("CaseRows".into(), schema())]))
        .unwrap();
    let plan = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::parse(
                    "WITH selected AS (SELECT value FROM \"CaseRows\") SELECT count(*) AS total, current_timestamp AS clock FROM selected",
                )
                .unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let mut first = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    first
        .register("CaseRows", schema(), &[batch(11), batch(22)])
        .unwrap();
    let mut second = fixture
        .engine
        .session(AnalysisSelectionV1::new([2; 16], vec![]), &control(), 2)
        .unwrap();
    second.register("caserows", schema(), &[batch(99)]).unwrap();
    assert!(second.execute_local(Arc::clone(&plan)).is_err());
    second.register("CaseRows", schema(), &[]).unwrap();
    for (session, expected, clock) in [(&first, 2, 1), (&second, 0, 2)] {
        let rows = session.execute_local(Arc::clone(&plan)).unwrap();
        assert_eq!(value(&rows), expected);
        assert_eq!(
            ScalarValue::try_from_array(rows[0].column(1), 0).unwrap(),
            ScalarValue::TimestampNanosecond(Some(clock), None)
        );
    }
    first.register("CaseRows", schema(), &[batch(33)]).unwrap();
    assert_eq!(value(&first.execute_local(Arc::clone(&plan)).unwrap()), 1);
    assert_eq!(value(&second.execute_local(plan).unwrap()), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn native_scans_fix_inputs() {
    let fixture = Fixture::new(Limits::default());
    let (plan, sources) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(11)])
        .unwrap();
    let (_, mut stream) = session
        .stream(&plan, &sources, Read::Snapshot)
        .await
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(33)])
        .unwrap();
    let first = stream.try_next().await.unwrap().unwrap();
    assert_eq!(value(&[first]), 11);
    assert!(stream.try_next().await.unwrap().is_none());
    let (_, fresh) = session.execute(Arc::clone(&plan), &sources).unwrap();
    assert_eq!(value(&fresh), 33);
}

#[test]
fn native_bindings_fail_closed() {
    let fixture = Fixture::new(Limits::default());
    let (plan, sources) = local_plan(&fixture.engine);
    let mut first = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    first
        .register("local_rows", schema(), &[batch(11)])
        .unwrap();
    let mut second = fixture
        .engine
        .session(AnalysisSelectionV1::new([2; 16], vec![]), &control(), 1)
        .unwrap();
    assert!(second.execute(Arc::clone(&plan), &sources).is_err());
    second
        .register("local_rows", schema(), &[batch(22)])
        .unwrap();
    let (_, rows) = second.execute(Arc::clone(&plan), &sources).unwrap();
    assert_eq!(value(&rows), 22);
    let metadata = std::collections::HashMap::from([("owner".into(), "changed".into())]);
    for changed in [
        Schema::new(vec![Field::new("value", DataType::UInt64, false)]),
        Schema::new(vec![Field::new("value", DataType::Int64, true)]),
        Schema::new(vec![
            Field::new("value", DataType::Int64, false).with_metadata(metadata.clone())
        ]),
        schema().as_ref().clone().with_metadata(metadata),
    ] {
        let changed = Arc::new(changed);
        second
            .register(
                "local_rows",
                Arc::clone(&changed),
                &[RecordBatch::new_empty(changed)],
            )
            .unwrap();
        assert!(second.execute(Arc::clone(&plan), &sources).is_err());
    }
    second
        .register("local_rows", schema(), &[batch(44)])
        .unwrap();
    let (_, rows) = second.execute(plan, &sources).unwrap();
    assert_eq!(value(&rows), 44);
}

#[test]
fn sessions_freeze_native_clocks() {
    let fixture = Fixture::new(Limits::default());
    let catalog = fixture.engine.catalog(BTreeMap::new()).unwrap();
    let statement =
        Parser::parse("SELECT current_timestamp AS first_clock, current_timestamp AS second_clock")
            .unwrap();
    let sources = catalog
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| source.table().to_owned())
        .collect();
    let plan = Arc::new(fixture.engine.plan(&catalog, statement, vec![]).unwrap());
    for now in [1_700_000_000_123_456_789u64, 1_700_000_005_987_654_321] {
        let session = fixture
            .engine
            .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), now)
            .unwrap();
        let (_, rows) = session.execute(Arc::clone(&plan), &sources).unwrap();
        assert_eq!(rows.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        for column in 0..2 {
            assert_eq!(
                ScalarValue::try_from_array(rows[0].column(column), 0).unwrap(),
                ScalarValue::TimestampNanosecond(Some(now as i64), None)
            );
        }
    }
}

fn execute_sync(engine: &Arc<Engine>) {
    let (plan, sources) = local_plan(engine);
    let mut session = engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(71)])
        .unwrap();
    let (_, rows) = session.execute(plan, &sources).unwrap();
    assert_eq!(value(&rows), 71);
}

#[test]
fn synchronous_execution_without_tokio() {
    let fixture = Fixture::new(Limits::default());
    assert!(tokio::runtime::Handle::try_current().is_err());
    execute_sync(&fixture.engine);
}

#[tokio::test(flavor = "current_thread")]
async fn execute_in_current_thread() {
    let fixture = Fixture::new(Limits::default());
    execute_sync(&fixture.engine);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_in_multithread_runtime() {
    let fixture = Fixture::new(Limits::default());
    execute_sync(&fixture.engine);
}

#[tokio::test(flavor = "current_thread")]
async fn execute_in_blocking_worker() {
    let fixture = Fixture::new(Limits::default());
    let engine = Arc::clone(&fixture.engine);
    tokio::task::spawn_blocking(move || execute_sync(&engine))
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn buffers_outlive_producer_permits() {
    let fixture = Fixture::new(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        ..Limits::default()
    });
    let (plan, sources) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(81)])
        .unwrap();
    let (snapshot, mut stream) = session
        .stream(&plan, &sources, Read::Snapshot)
        .await
        .unwrap();
    drop(session);
    let idle = fixture
        .engine
        .session(AnalysisSelectionV1::new([2; 16], vec![]), &control(), 1)
        .unwrap();
    assert!(matches!(
        idle.stream(&plan, &sources, Read::Snapshot).await,
        Err(Error::Busy {
            resource: "evaluation",
            ..
        })
    ));
    let output = stream.try_next().await.unwrap().unwrap();
    assert_eq!(value(std::slice::from_ref(&output)), 81);
    let borrowed = output.column(0).to_data().buffers()[0].clone();
    drop(output);
    assert!(matches!(
        idle.stream(&plan, &sources, Read::Snapshot).await,
        Err(Error::Busy {
            resource: "evaluation",
            ..
        })
    ));
    drop(stream);
    drop(snapshot);
    let next = fixture.engine.reserve_evaluation([2; 16]).unwrap();
    drop(next);
    let limits = fixture.engine.limits();
    assert!(fixture
        .engine
        .memory()
        .reserve_input(limits.input_capacity)
        .is_err());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(limits.output_capacity)
        .is_err());
    drop(borrowed);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(limits.input_capacity)
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(limits.output_capacity)
        .is_ok());
}

#[test]
fn cancelled_sessions_release_capacity() {
    let fixture = Fixture::new(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        ..Limits::default()
    });
    let cancelled = control();
    cancelled.cancel().unwrap();
    let error =
        match fixture
            .engine
            .session(AnalysisSelectionV1::new([1; 16], vec![]), &cancelled, 1)
        {
            Ok(_) => panic!("cancelled session was admitted"),
            Err(error) => error,
        };
    assert_eq!(error.status_code(), StatusCode::Cancelled);
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_ok());
}

#[test]
fn idle_sessions_skip_admission() {
    let fixture = Fixture::new(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        ..Limits::default()
    });
    let idle = (1..=8)
        .map(|tenant| {
            fixture
                .engine
                .session(
                    AnalysisSelectionV1::new([tenant; 16], vec![]),
                    &control(),
                    1,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let permit = fixture.engine.reserve_evaluation([1; 16]).unwrap();
    assert!(matches!(
        fixture.engine.reserve_evaluation([2; 16]),
        Err(Error::Busy {
            resource: "evaluation",
            ..
        })
    ));
    drop(permit);
    let (plan, sources) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(91)])
        .unwrap();
    let (_, rows) = session.execute(plan, &sources).unwrap();
    assert_eq!(value(&rows), 91);
    assert_eq!(idle.len(), 8);
}

#[test]
fn input_output_budget() {
    let fixture = Fixture::new(Limits {
        input_bytes: 64 * 1024,
        input_capacity: 128 * 1024,
        output_bytes: 128,
        output_capacity: 128,
        ..Default::default()
    });
    let state = fixture.engine.catalog(BTreeMap::new()).unwrap();
    let statement = Parser::parse("SELECT $1 AS payload").unwrap();
    let sources = state
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| source.table().to_owned())
        .collect();
    let text = "x".repeat(4096);
    let plan = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                statement,
                vec![ScalarValue::Utf8(Some(text.clone()))],
            )
            .unwrap(),
    );
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session.set_output(1, 16 * 1024).unwrap();
    let (receipt, batches) = session.execute_input(Arc::clone(&plan), &sources).unwrap();
    assert_eq!(
        ScalarValue::try_from_array(batches[0].column(0), 0).unwrap(),
        ScalarValue::Utf8(Some(text))
    );
    assert!(batches[0].get_array_memory_size() > fixture.engine.limits().output_capacity);
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
    let client = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    let error = client.execute(plan, &sources).unwrap_err();
    assert!(matches!(error, Error::Sql { source }
        if matches!(source.find_root(), datafusion::common::DataFusionError::ResourcesExhausted(_))));
    let borrowed = Arc::clone(batches[0].column(0));
    drop(batches);
    drop(receipt);
    drop(session);
    drop(client);
    let capacity = fixture.engine.limits().input_capacity;
    assert!(fixture.engine.memory().reserve_input(capacity).is_err());
    drop(borrowed);
    assert!(fixture.engine.memory().reserve_input(capacity).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[derive(Clone, Debug)]
struct Gate {
    schema: SchemaRef,
    entered: Arc<Notify>,
    dropped: Arc<Notify>,
}

impl Gate {
    async fn plan(&self, engine: &Engine) -> (LogicalPlan, BTreeSet<String>) {
        let provider: Arc<dyn TableProvider> = Arc::new(self.clone());
        let state = engine.catalog(BTreeMap::new()).unwrap();
        let options = &state.config_options().catalog;
        state
            .catalog_list()
            .catalog(&options.default_catalog)
            .unwrap()
            .schema(&options.default_schema)
            .unwrap()
            .register_table("gate".into(), provider)
            .unwrap();
        let statement = Parser::parse("SELECT value FROM gate").unwrap();
        let sources = state
            .resolve_table_references(&statement)
            .unwrap()
            .into_iter()
            .map(|source| source.table().to_owned())
            .collect();
        (
            Planner::new(&state).build(statement, vec![]).await.unwrap(),
            sources,
        )
    }
}

struct PollGuard(Arc<Notify>);

impl Drop for PollGuard {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[async_trait::async_trait]
impl TableProvider for Gate {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _: &dyn NativeSession,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        assert!(filters.is_empty());
        let schema = match projection {
            Some(indices) => Arc::new(self.schema.project(indices)?),
            None => Arc::clone(&self.schema),
        };
        let partition: Arc<dyn PartitionStream> = Arc::new(Self {
            schema: Arc::clone(&schema),
            ..self.clone()
        });
        Ok(Arc::new(StreamingTableExec::try_new(
            schema,
            vec![partition],
            None,
            [],
            false,
            limit,
        )?))
    }
}

impl PartitionStream for Gate {
    fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    fn execute(&self, _: Arc<TaskContext>) -> SendableRecordBatchStream {
        let entered = Arc::clone(&self.entered);
        let dropped = Arc::clone(&self.dropped);
        let stream = futures_util::stream::once(async move {
            let _guard = PollGuard(dropped);
            entered.notify_one();
            std::future::pending::<NativeResult<RecordBatch>>().await
        });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_stops_native_producers() {
    let fixture = Fixture::new(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        ..Limits::default()
    });
    let gate = Gate {
        schema: schema(),
        entered: Arc::new(Notify::new()),
        dropped: Arc::new(Notify::new()),
    };
    let (plan, sources) = gate.plan(&fixture.engine).await;
    let control = control();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control, 1)
        .unwrap();
    let (snapshot, mut stream) = session
        .stream(&plan, &sources, Read::Snapshot)
        .await
        .unwrap();
    drop(session);
    let producer = tokio::spawn(async move { stream.try_next().await });
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    let idle = fixture
        .engine
        .session(
            AnalysisSelectionV1::new([2; 16], vec![]),
            &self::control(),
            1,
        )
        .unwrap();
    assert!(matches!(
        idle.stream(&plan, &sources, Read::Snapshot).await,
        Err(Error::Busy {
            resource: "evaluation",
            ..
        })
    ));
    control.cancel().unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), producer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        Error::Sql { source: error }.status_code(),
        StatusCode::Cancelled
    );
    tokio::time::timeout(Duration::from_secs(2), gate.dropped.notified())
        .await
        .unwrap();
    drop(snapshot);
    assert!(fixture.engine.reserve_evaluation([2; 16]).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn local_producer_cancel() {
    let fixture = Fixture::new(Limits::default());
    let gate = Gate {
        schema: schema(),
        entered: Arc::new(Notify::new()),
        dropped: Arc::new(Notify::new()),
    };
    let (plan, _) = gate.plan(&fixture.engine).await;
    let control = control();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control, 1)
        .unwrap();
    let producer = tokio::task::spawn_blocking(move || session.execute_local(Arc::new(plan)));
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    control.cancel().unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), producer)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.status_code(), StatusCode::Cancelled);
    tokio::time::timeout(Duration::from_secs(2), gate.dropped.notified())
        .await
        .unwrap();
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(fixture.engine.limits().output_capacity)
        .is_ok());
}
