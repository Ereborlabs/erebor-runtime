use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use datafusion::arrow::array::{ArrayRef, Int64Array, RecordBatch};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::catalog::{Session as NativeSession, TableProvider};
use datafusion::common::{Result as NativeResult, ScalarValue};
use datafusion::datasource::MemTable;
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
use crate::sources::SourceSnapshot;
use crate::Error;

mod views;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(mut limits: Limits) -> Self {
        limits.input_capacity.get_or_insert(128 * 1024 * 1024);
        limits.output_capacity.get_or_insert(16 * 1024 * 1024);
        limits.extract_timeout = Some(Duration::from_secs(5));
        limits.evaluate_timeout = Some(Duration::from_secs(5));
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

#[test]
fn scoped_session_keeps_family() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let fixture = Fixture::new(Limits::default());
    let scope = fixture.engine.memory().scope();
    let session = fixture.engine.session_on(
        AnalysisSelectionV1::tenant([1; 16]),
        &control(),
        1,
        Arc::clone(&scope),
    )?;
    assert!(Arc::ptr_eq(session.memory(), &scope));
    let foreign = crate::memory::Memory::new(Some(1024), Some(1024));
    assert!(matches!(
        fixture
            .engine
            .session_on(AnalysisSelectionV1::tenant([1; 16]), &control(), 1, foreign,),
        Err(crate::Error::Invalid {
            field: "session memory owner",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn blocking_cancel_joins_worker(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let control = Arc::new(control());
    let stage = Arc::clone(&control);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let mut worker = tokio::spawn(async move {
        Engine::blocking(stage, (), move || {
            let _entered = entered.send(());
            held.recv().map_err(|source| crate::Error::Sql {
                source: datafusion::common::DataFusionError::External(Box::new(source)),
            })?;
            Ok(())
        })
        .await
    });
    ready.await?;
    control.cancel()?;
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut worker)
        .await
        .is_err());
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(2), worker)
        .await??
        .err()
        .ok_or("cancelled read must fail")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    Ok(())
}

#[tokio::test]
async fn blocking_drop_orders_cleanup(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Returned(Arc<AtomicBool>);
    impl Drop for Returned {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    struct Lease {
        dropped: Arc<AtomicBool>,
        report: Option<tokio::sync::oneshot::Sender<bool>>,
        _token: araphor_package_runtime::TaskTrackerToken,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            let dropped = self.dropped.load(Ordering::Acquire);
            if let Some(report) = self.report.take() {
                let _reported = report.send(dropped);
            }
            assert!(dropped, "returned resource outlived the worker lease");
        }
    }

    let tracker = araphor_package_runtime::TaskTracker::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let (report, observed) = tokio::sync::oneshot::channel();
    let lease = Lease {
        dropped: Arc::clone(&dropped),
        report: Some(report),
        _token: tracker.token(),
    };
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let mut work = Box::pin(Engine::blocking(
        Arc::new(AnalysisReadControl::default()),
        lease,
        move || {
            let _entered = entered.send(());
            held.recv().map_err(|source| crate::Error::Sql {
                source: datafusion::common::DataFusionError::External(Box::new(source)),
            })?;
            Ok(Returned(dropped))
        },
    ));
    tokio::select! {
        result = &mut work => {
            let _result = result?;
            return Err("blocking operation completed before release".into());
        }
        ready = ready => ready?,
    }
    drop(work);
    tracker.close();
    assert_eq!(tracker.len(), 1);
    release.send(())?;
    tracker.wait().await;
    assert!(observed.await?);
    Ok(())
}

#[tokio::test]
async fn blocking_deadline_keeps_parent(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let parent = control();
    let stage = Arc::new(parent.stage(Duration::from_millis(10))?);
    let worker_stage = Arc::clone(&stage);
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ended = Arc::clone(&stopped);
    let error = Engine::blocking(stage, (), move || {
        while worker_stage.check().is_ok() {
            std::thread::yield_now();
        }
        let result = worker_stage.check().map_err(crate::Error::from);
        ended.store(true, std::sync::atomic::Ordering::Release);
        result
    })
    .await
    .err()
    .ok_or("expired worker must fail")?;
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::DeadlineExceeded
    );
    assert!(stopped.load(std::sync::atomic::Ordering::Acquire));
    parent.stage(Duration::from_secs(1))?.check()?;
    Ok(())
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
    assert_eq!(sources, BTreeMap::from([("events".into(), None)]));
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

fn local_plan(engine: &Engine) -> (Arc<LogicalPlan>, araphor_data::AnalysisTableRequests) {
    let table: Arc<dyn TableProvider> =
        crate::sources::SourceProvider::local("local_rows", schema());
    let catalog = engine
        .catalog(BTreeMap::from([("local_rows".into(), table)]))
        .unwrap();
    let statement = Parser::default()
        .parse("SELECT value FROM local_rows")
        .unwrap();
    let sources = catalog
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| (source.table().to_owned(), None))
        .collect();
    let plan = engine.plan(&catalog, statement, vec![]).unwrap();
    (Arc::new(plan), sources)
}

#[test]
fn closed_catalog_keeps_locals() {
    let fixture = Fixture::new(Limits::default());
    let state = fixture
        .engine
        .catalog(BTreeMap::from([
            (
                "events".into(),
                crate::sources::SourceProvider::local("events", schema()),
            ),
            (
                "CaseRows".into(),
                crate::sources::SourceProvider::local("CaseRows", schema()),
            ),
        ]))
        .unwrap();
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)
        .unwrap();
    session.register("events", schema(), &[batch(7)]).unwrap();
    session.register("CaseRows", schema(), &[batch(9)]).unwrap();
    for (sql, expected) in [
        ("SELECT value FROM events", 7),
        ("SELECT value FROM public.events", 7),
        ("SELECT value FROM datafusion.public.events", 7),
        ("SELECT value FROM datafusion.public.\"CaseRows\"", 9),
    ] {
        let plan = fixture
            .engine
            .plan(&state, Parser::default().parse(sql).unwrap(), vec![])
            .unwrap();
        assert_eq!(
            value(&session.collect_local(Arc::new(plan)).unwrap()),
            expected
        );
    }
    for sql in [
        "SELECT * FROM catalog",
        "SELECT * FROM datafusion.public.catalog",
        "SELECT value FROM absent.public.events",
        "SELECT value FROM caserows",
        "SELECT source_cursor FROM events",
        "WITH unused AS (SELECT * FROM coverage) SELECT value FROM events",
    ] {
        let error = fixture
            .engine
            .plan(&state, Parser::default().parse(sql).unwrap(), vec![])
            .unwrap_err();
        assert_eq!(error.status_code(), StatusCode::InvalidArguments, "{sql}");
        assert_eq!(
            error.retry_hint(),
            erebor_runtime_error::RetryHint::NonRetryable,
            "{sql}"
        );
    }
    let empty = fixture.engine.catalog(BTreeMap::new()).unwrap();
    assert!(fixture
        .engine
        .plan(
            &empty,
            Parser::default().parse("SELECT * FROM events").unwrap(),
            vec![]
        )
        .is_err());
}

#[test]
fn native_registry_contract() {
    use datafusion::execution::session_state::SessionStateBuilder;

    let fixture = Fixture::new(Limits::default());
    let state = fixture.engine.catalog(BTreeMap::new()).unwrap();
    let native = SessionStateBuilder::new().with_default_features().build();
    macro_rules! registry {
        ($method:ident) => {
            assert_eq!(
                state
                    .$method()
                    .iter()
                    .map(|(name, function)| (
                        name,
                        (function.name(), format!("{:?}", function.signature()))
                    ))
                    .collect::<BTreeMap<_, _>>(),
                native
                    .$method()
                    .iter()
                    .map(|(name, function)| (
                        name,
                        (function.name(), format!("{:?}", function.signature()))
                    ))
                    .collect::<BTreeMap<_, _>>(),
            );
        };
    }
    registry!(scalar_functions);
    registry!(aggregate_functions);
    registry!(window_functions);
    assert_eq!(
        state
            .table_functions()
            .keys()
            .collect::<std::collections::BTreeSet<_>>(),
        native
            .table_functions()
            .keys()
            .collect::<std::collections::BTreeSet<_>>(),
    );
}

#[test]
fn evaluation_timeout_config() {
    let defaults: Limits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.evaluate_timeout, None);
    defaults.validate().unwrap();
    for timeout in [None, Some(Duration::new(2, 3))] {
        let limits: Limits = serde_json::from_value(serde_json::json!({
            "evaluate_timeout": timeout,
        }))
        .unwrap();
        assert_eq!(limits.evaluate_timeout, timeout);
        limits.validate().unwrap();
        let restored: Limits =
            serde_json::from_value(serde_json::to_value(&limits).unwrap()).unwrap();
        assert_eq!(restored, limits);
    }
}

#[test]
fn evaluation_timeout_zero() {
    let limits: Limits = serde_json::from_value(serde_json::json!({
        "evaluate_timeout": Duration::ZERO,
    }))
    .unwrap();
    assert!(matches!(
        limits.validate(),
        Err(crate::Error::Invalid {
            field: "execution limits",
            ..
        })
    ));
}

#[test]
fn extraction_timeout_config() {
    let defaults: Limits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.extract_timeout, None);
    for timeout in [None, Some(Duration::new(2, 3))] {
        let limits: Limits = serde_json::from_value(serde_json::json!({
            "extract_timeout": timeout,
        }))
        .unwrap();
        assert_eq!(limits.extract_timeout, timeout);
        limits.validate().unwrap();
        let restored: Limits =
            serde_json::from_value(serde_json::to_value(&limits).unwrap()).unwrap();
        assert_eq!(restored, limits);
    }
    assert!(Limits {
        extract_timeout: Some(Duration::ZERO),
        ..Limits::default()
    }
    .validate()
    .is_err());
}

#[test]
fn stream_limits_default_disabled() {
    let defaults: Limits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.global_streams, None);
    assert_eq!(defaults.tenant_streams, None);
    let fixture = Fixture::new(defaults);
    let permits = (0..32)
        .map(|_| fixture.engine.reserve_stream([1; 16]).unwrap())
        .collect::<Vec<_>>();
    assert!(fixture.engine.streams.is_none());
    assert!(fixture.engine.tenant([1; 16]).unwrap().streams.is_none());
    assert!(permits
        .iter()
        .all(|permit| permit._global.is_none() && permit._local.is_none()));
    drop(permits);
}

#[test]
fn stream_limits_configured() {
    for (global, tenant) in [(Some(2), Some(1)), (Some(1), None), (None, Some(1))] {
        let limits = Limits {
            global_streams: global,
            tenant_streams: tenant,
            ..Limits::default()
        };
        let restored: Limits =
            serde_json::from_value(serde_json::to_value(&limits).unwrap()).unwrap();
        assert_eq!(restored, limits);
        let fixture = Fixture::new(limits);
        let first = fixture.engine.reserve_stream([1; 16]).unwrap();
        assert!(matches!(
            fixture.engine.reserve_stream([1; 16]),
            Err(Error::Busy {
                resource: "stream",
                ..
            })
        ));
        let second = fixture.engine.reserve_stream([2; 16]);
        if global == Some(1) {
            assert!(second.is_err());
        } else {
            let second = second.unwrap();
            if global == Some(2) {
                assert!(fixture.engine.reserve_stream([3; 16]).is_err());
            } else {
                assert!(fixture.engine.reserve_stream([3; 16]).is_ok());
            }
            drop(second);
        }
        drop(first);
        assert!(fixture.engine.reserve_stream([1; 16]).is_ok());
    }
    for (global, tenant) in [(Some(0), None), (None, Some(0))] {
        let fixture = Fixture::new(Limits {
            global_streams: global,
            tenant_streams: tenant,
            ..Limits::default()
        });
        assert!(fixture.engine.reserve_stream([1; 16]).is_err());
    }
}

#[test]
fn native_memory_limit_is_optional() {
    use datafusion::execution::memory_pool::{MemoryConsumer, MemoryLimit};

    let defaults: Limits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.execution_capacity, None);
    for capacity in [None, Some(64 * 1024 * 1024)] {
        let fixture = Fixture::new(Limits {
            execution_capacity: capacity,
            ..Limits::default()
        });
        let runtime = fixture.engine.state.runtime_env();
        let pool = &runtime.memory_pool;
        let reservation = MemoryConsumer::new("native limit test").register(pool);
        match capacity {
            None => {
                assert!(matches!(pool.memory_limit(), MemoryLimit::Infinite));
                reservation.try_grow(65 * 1024 * 1024).unwrap();
            }
            Some(bytes) => {
                assert!(
                    matches!(pool.memory_limit(), MemoryLimit::Finite(limit) if limit == bytes)
                );
                reservation.try_grow(bytes).unwrap();
                assert!(reservation.try_grow(1).is_err());
            }
        }
        drop(reservation);
        assert_eq!(pool.reserved(), 0);
    }
    assert!(Limits {
        execution_capacity: Some(0),
        ..Limits::default()
    }
    .validate()
    .is_err());
}

#[test]
fn local_skips_store() {
    let fixture = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let state = fixture.engine.catalog(SourceSnapshot::providers()).unwrap();
    let clock = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::default()
                    .parse("SELECT CURRENT_TIMESTAMP AS clock")
                    .unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let constant = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::default().parse("SELECT 7 AS value").unwrap(),
                vec![],
            )
            .unwrap(),
    );
    let source = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::default()
                    .parse("SELECT source_cursor FROM events")
                    .unwrap(),
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
    assert_eq!(value(&session.collect_local(plan).unwrap()), 11);
    let now = session.collect_local(clock).unwrap();
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
    assert!(session.collect_local(source).is_err());
    let error = session
        .execute(Arc::clone(&constant), &BTreeMap::new())
        .unwrap_err();
    assert!(
        matches!(error, Error::Sql { source: datafusion::common::DataFusionError::External(source) }
        if matches!(source.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisBusy { resource: "reader", .. })))
    );
    drop(readers);
    let (receipt, rows) = session
        .execute(Arc::clone(&constant), &BTreeMap::new())
        .unwrap();
    assert_eq!(value(&rows), 7);
    assert_eq!(receipt.page.extraction.meta, meta);
    let session = fixture
        .engine
        .session(
            AnalysisSelectionV1::new([1; 16], vec![]),
            &control(),
            frozen,
        )
        .unwrap();
    let (receipt, rows) = session.execute(constant, &BTreeMap::new()).unwrap();
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
    let error = session.collect_local(plan).unwrap_err();
    assert_eq!(error.status_code(), StatusCode::InvalidArguments);
    assert!(matches!(error, Error::Sql { source }
        if matches!(source.find_root(), datafusion::common::DataFusionError::ResourcesExhausted(_))));
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
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
fn registration_reuses_input_claims() {
    let data = batch(11);
    let fixture = Fixture::new(Limits {
        input_bytes: data.get_array_memory_size(),
        input_capacity: Some(4096),
        ..Default::default()
    });
    let (plan, _) = local_plan(&fixture.engine);
    let memory = fixture.engine.memory().reserve_input(0).unwrap();
    fixture
        .engine
        .memory()
        .retain_input(&data, &memory)
        .unwrap();
    let allocated = data.column(0).to_data().buffers()[0].capacity();
    let held = fixture
        .engine
        .memory()
        .reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity")
                - allocated,
        )
        .unwrap();
    assert!(fixture.engine.memory().reserve_input(1).is_err());
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    for _ in 0..2 {
        session
            .register("local_rows", schema(), std::slice::from_ref(&data))
            .unwrap();
    }
    let error = session
        .register("local_rows", schema(), &[batch(22)])
        .unwrap_err();
    assert_eq!(error.status_code(), StatusCode::Unavailable);
    assert_eq!(crate::Failure::from(&error), crate::Failure::Busy);
    assert_eq!(
        value(&session.collect_local(Arc::clone(&plan)).unwrap()),
        11
    );
    let error = session
        .register("other", schema(), std::slice::from_ref(&data))
        .unwrap_err();
    assert!(matches!(error, Error::Sql {
        source: datafusion::common::DataFusionError::ResourcesExhausted(ref message)
    } if message == "local input bytes"));
    assert_eq!(value(&session.collect_local(plan).unwrap()), 11);
    drop(held);
    drop(session);
    drop(data);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity")
        )
        .is_ok());
}

#[test]
fn native_counts_rebind() {
    let fixture = Fixture::new(Limits::default());
    let table: Arc<dyn TableProvider> = crate::sources::SourceProvider::local("CaseRows", schema());
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("CaseRows".into(), table)]))
        .unwrap();
    let plan = Arc::new(
        fixture
            .engine
            .plan(
                &state,
                Parser::default().parse(
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
    assert!(second.collect_local(Arc::clone(&plan)).is_err());
    second.register("CaseRows", schema(), &[]).unwrap();
    for (session, expected, clock) in [(&first, 2, 1), (&second, 0, 2)] {
        let rows = session.collect_local(Arc::clone(&plan)).unwrap();
        assert_eq!(value(&rows), expected);
        assert_eq!(
            ScalarValue::try_from_array(rows[0].column(1), 0).unwrap(),
            ScalarValue::TimestampNanosecond(Some(clock), None)
        );
    }
    first.register("CaseRows", schema(), &[batch(33)]).unwrap();
    assert_eq!(value(&first.collect_local(Arc::clone(&plan)).unwrap()), 1);
    assert_eq!(value(&second.collect_local(plan).unwrap()), 0);
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
    let catalog = fixture.engine.catalog(SourceSnapshot::providers()).unwrap();
    let statement = Parser::default()
        .parse("SELECT current_timestamp AS first_clock, current_timestamp AS second_clock")
        .unwrap();
    let sources = catalog
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| (source.table().to_owned(), None))
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
        .reserve_input(limits.input_capacity.expect("configured input capacity"))
        .is_err());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(limits.output_capacity.expect("configured output capacity"))
        .is_err());
    drop(borrowed);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(limits.input_capacity.expect("configured input capacity"))
        .is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(limits.output_capacity.expect("configured output capacity"))
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
        input_capacity: Some(128 * 1024),
        output_bytes: 128,
        output_capacity: Some(128),
        ..Default::default()
    });
    let state = fixture.engine.catalog(SourceSnapshot::providers()).unwrap();
    let statement = Parser::default().parse("SELECT $1 AS payload").unwrap();
    let sources = state
        .resolve_table_references(&statement)
        .unwrap()
        .into_iter()
        .map(|source| (source.table().to_owned(), None))
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
    use araphor_analysis_sdk as sdk;

    let schema = Schema::new(vec![Field::new("payload", DataType::Utf8, false)]);
    let mut model = sdk::Model::new(
        "evaluate",
        Vec::new(),
        vec![sdk::Port::new("result", schema.clone())],
    );
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new("input", schema),
        source: sdk::InputSource::Query(format!("SELECT '{text}' AS payload")),
    }];
    let definition = Arc::new(crate::inputs::Inputs::admit(&fixture.engine, &model).unwrap());
    let input = definition
        .read(
            Arc::clone(&fixture.engine),
            AnalysisSelectionV1::tenant([1; 16]),
            "input-budget".into(),
            &control(),
            1,
        )
        .unwrap();
    let batches = &input.inputs[0].data.batches;
    assert_eq!(
        ScalarValue::try_from_array(batches[0].column(0), 0).unwrap(),
        ScalarValue::Utf8(Some(text))
    );
    assert!(
        batches[0].get_array_memory_size()
            > fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
    );
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
    let client = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    let error = client.execute(plan, &sources).unwrap_err();
    assert!(matches!(error, Error::Sql { source }
        if matches!(source.find_root(), datafusion::common::DataFusionError::ResourcesExhausted(_))));
    let borrowed = Arc::clone(batches[0].column(0));
    drop(input);
    drop(client);
    let capacity = fixture
        .engine
        .limits()
        .input_capacity
        .expect("configured input capacity");
    assert!(fixture.engine.memory().reserve_input(capacity).is_err());
    drop(borrowed);
    assert!(fixture.engine.memory().reserve_input(capacity).is_ok());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
}

#[tokio::test]
async fn physical_preserves_context() {
    use std::collections::HashMap;
    use std::sync::OnceLock;

    use datafusion::execution::config::SessionConfig;
    use datafusion::execution::runtime_env::RuntimeEnv;

    use crate::sources::{ArrowSnapshot, SourceSnapshot};

    struct Marker;

    #[derive(Debug)]
    struct Probe {
        schema: SchemaRef,
        expected: Arc<TaskContext>,
        captured: Arc<OnceLock<Arc<ArrowSnapshot>>>,
    }

    impl PartitionStream for Probe {
        fn schema(&self) -> &SchemaRef {
            &self.schema
        }

        fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
            assert_eq!(context.task_id(), self.expected.task_id());
            assert_eq!(context.session_id(), self.expected.session_id());
            assert_eq!(context.session_config().batch_size(), 17);
            let actual = context.session_config().get_extension::<Marker>().unwrap();
            let expected = self
                .expected
                .session_config()
                .get_extension::<Marker>()
                .unwrap();
            assert!(Arc::ptr_eq(&actual, &expected));
            assert!(Arc::ptr_eq(
                &context.runtime_env(),
                &self.expected.runtime_env()
            ));
            assert_eq!(
                context.scalar_functions().len(),
                self.expected.scalar_functions().len()
            );
            for (name, function) in self.expected.scalar_functions() {
                assert!(Arc::ptr_eq(&context.scalar_functions()[name], function));
            }
            assert_eq!(
                context.aggregate_functions().len(),
                self.expected.aggregate_functions().len()
            );
            for (name, function) in self.expected.aggregate_functions() {
                assert!(Arc::ptr_eq(&context.aggregate_functions()[name], function));
            }
            assert_eq!(
                context.window_functions().len(),
                self.expected.window_functions().len()
            );
            for (name, function) in self.expected.window_functions() {
                assert!(Arc::ptr_eq(&context.window_functions()[name], function));
            }
            let snapshot = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .unwrap();
            let receipt = snapshot.capture_metadata(&BTreeMap::new()).unwrap();
            assert!(self.captured.set(receipt).is_ok());
            Box::pin(RecordBatchStreamAdapter::new(
                Arc::clone(&self.schema),
                futures_util::stream::empty::<NativeResult<RecordBatch>>(),
            ))
        }
    }

    let fixture = Fixture::new(Limits::default());
    let registered = fixture
        .engine
        .catalog(SourceSnapshot::providers())
        .unwrap()
        .task_ctx();
    let context = Arc::new(TaskContext::new(
        Some("preserved-task".into()),
        "preserved-session".into(),
        SessionConfig::new()
            .with_batch_size(17)
            .with_extension(Arc::new(Marker)),
        HashMap::from([(
            "context_scalar".into(),
            Arc::clone(registered.scalar_functions().values().next().unwrap()),
        )]),
        HashMap::from([(
            "context_aggregate".into(),
            Arc::clone(registered.aggregate_functions().values().next().unwrap()),
        )]),
        HashMap::from([(
            "context_window".into(),
            Arc::clone(registered.window_functions().values().next().unwrap()),
        )]),
        Arc::new(RuntimeEnv::default()),
    ));
    let captured = Arc::new(OnceLock::new());
    let schema = schema();
    let partition: Arc<dyn PartitionStream> = Arc::new(Probe {
        schema: Arc::clone(&schema),
        expected: Arc::clone(&context),
        captured: Arc::clone(&captured),
    });
    let physical: Arc<dyn ExecutionPlan> = Arc::new(
        StreamingTableExec::try_new(schema, vec![partition], None, [], false, None).unwrap(),
    );
    let operation = control();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &operation, 1)
        .unwrap();
    let permit = Arc::new(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    let (snapshot, stream, _permit, _control, _memory) = session
        .start_physical(
            physical,
            Arc::clone(&context),
            &BTreeMap::new(),
            Read::Snapshot,
            permit,
        )
        .await
        .unwrap();
    let batches = stream.try_collect::<Vec<_>>().await.unwrap();
    assert!(batches.is_empty());
    assert!(Arc::ptr_eq(captured.get().unwrap(), &snapshot));
    assert!(context
        .session_config()
        .get_extension::<SourceSnapshot>()
        .is_none());
}

#[derive(Clone, Debug)]
struct Gate {
    schema: SchemaRef,
    entered: Arc<Notify>,
    dropped: Arc<Notify>,
}

impl Gate {
    async fn plan(&self, engine: &Engine) -> (LogicalPlan, araphor_data::AnalysisTableRequests) {
        let provider: Arc<dyn TableProvider> = Arc::new(self.clone());
        let state = engine
            .catalog(BTreeMap::from([("gate".into(), provider)]))
            .unwrap();
        let statement = Parser::default().parse("SELECT value FROM gate").unwrap();
        let sources = state
            .resolve_table_references(&statement)
            .unwrap()
            .into_iter()
            .map(|source| (source.table().to_owned(), None))
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
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
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
    let permit = Arc::new(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    let producer = tokio::spawn(async move {
        session
            .stream_local(&plan, permit)
            .await?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|source| Error::Sql { source })
    });
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
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_ok());
}

#[test]
fn local_stream_keeps_capacity() {
    let fixture = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)
        .unwrap();
    session
        .register("local_rows", schema(), &[batch(11)])
        .unwrap();
    let engine = Arc::clone(&fixture.engine);
    let permit = Arc::new(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    let (stream, batch, permit) = fixture
        .engine
        .wait(async move {
            let mut stream = session.stream_local(&plan, Arc::clone(&permit)).await?;
            assert!(engine.reserve_evaluation([1; 16]).is_err());
            let held = engine
                .memory()
                .reserve_output(
                    engine
                        .limits()
                        .output_capacity
                        .expect("configured output capacity")
                        - engine.limits().output_bytes,
                )
                .unwrap();
            assert!(engine.memory().reserve_output(1).is_err());
            drop(held);
            let batch = stream.try_next().await.unwrap().unwrap();
            assert_eq!(value(std::slice::from_ref(&batch)), 11);
            let retained = batch.column(0).to_data().buffers()[0].capacity();
            let held = engine
                .memory()
                .reserve_output(
                    engine
                        .limits()
                        .output_capacity
                        .expect("configured output capacity")
                        - retained,
                )
                .unwrap();
            assert!(engine.memory().reserve_output(1).is_err());
            drop(held);
            drop(session);
            Ok((stream, batch, permit))
        })
        .unwrap();
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    drop(stream);
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    drop(permit);
    drop(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    assert!(fixture
        .engine
        .memory()
        .reserve_output(
            fixture
                .engine
                .limits()
                .output_capacity
                .expect("configured output capacity")
        )
        .is_err());
    drop(batch);
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .expect("configured output capacity"),
            )
            .unwrap(),
    );
    drop(
        fixture
            .engine
            .memory()
            .reserve_input(
                fixture
                    .engine
                    .limits()
                    .input_capacity
                    .expect("configured input capacity"),
            )
            .unwrap(),
    );
}

#[tokio::test]
async fn local_rejects_foreign_permits() {
    let fixture = Fixture::new(Limits::default());
    let foreign = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)
        .unwrap();
    for permit in [
        foreign.engine.reserve_evaluation([1; 16]).unwrap(),
        fixture.engine.reserve_evaluation([2; 16]).unwrap(),
        fixture.engine.reserve_stream([1; 16]).unwrap(),
    ] {
        let error = session
            .stream_local(&plan, Arc::new(permit))
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            Error::Invalid {
                field: "evaluation permit",
                ..
            }
        ));
    }
    drop(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    drop(
        fixture
            .engine
            .memory()
            .reserve_output(
                fixture
                    .engine
                    .limits()
                    .output_capacity
                    .expect("configured output capacity"),
            )
            .unwrap(),
    );
}

#[test]
fn local_empty_releases_prepayment() {
    let fixture = Fixture::new(Limits::default());
    let (plan, _) = local_plan(&fixture.engine);
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)
        .unwrap();
    session.register("local_rows", schema(), &[]).unwrap();
    let engine = Arc::clone(&fixture.engine);
    let permit = Arc::new(fixture.engine.reserve_evaluation([1; 16]).unwrap());
    fixture
        .engine
        .wait(async move {
            let mut stream = session.stream_local(&plan, Arc::clone(&permit)).await?;
            assert!(engine
                .memory()
                .reserve_output(
                    engine
                        .limits()
                        .output_capacity
                        .expect("configured output capacity")
                )
                .is_err());
            assert!(stream.try_next().await.unwrap().is_none());
            drop(
                engine
                    .memory()
                    .reserve_output(
                        engine
                            .limits()
                            .output_capacity
                            .expect("configured output capacity"),
                    )
                    .unwrap(),
            );
            assert!(engine.reserve_evaluation([1; 16]).is_err());
            drop(stream);
            drop(permit);
            Ok(())
        })
        .unwrap();
    drop(fixture.engine.reserve_evaluation([1; 16]).unwrap());
}

impl super::Session {
    pub(super) fn collect_local(&self, plan: Arc<LogicalPlan>) -> crate::Result<Vec<RecordBatch>> {
        let engine = Arc::clone(&self.engine);
        let session = self.clone();
        engine.wait(async move {
            session.control.check()?;
            let permit = Arc::new(
                session
                    .engine
                    .reserve_evaluation(session.selection.tenant_id)?,
            );
            session
                .stream_local(&plan, permit)
                .await?
                .try_collect()
                .await
                .map_err(|source| crate::Error::Sql { source })
        })
    }
}

#[tokio::test]
async fn admission_uses_engine_config() {
    let limits: Limits = serde_json::from_value(serde_json::json!({
        "parser": {"bytes": 32, "depth": 64},
        "parameter_count": 1, "parameter_bytes": 512,
        "projection_columns": 1, "window_bound": 2
    }))
    .unwrap();
    let fixture = Fixture::new(limits);
    let native = fixture.engine.catalog(BTreeMap::new()).unwrap();
    let configured = native.config().get_extension::<Limits>().unwrap();
    assert!(std::ptr::eq(fixture.engine.limits(), configured.as_ref()));
    fixture
        .engine
        .prepare("SELECT $1", vec![ScalarValue::Int64(Some(1))])
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .engine
            .prepare("SELECT $1, $2", vec![ScalarValue::Int64(Some(1)); 2])
            .await,
        Err(Error::Invalid {
            field: "SQL parameters",
            ..
        })
    ));
    let sql = format!("SELECT '{}'", "x".repeat(33));
    assert!(matches!(
        fixture.engine.prepare(&sql, vec![]).await,
        Err(Error::Invalid {
            field: "SQL size",
            ..
        })
    ));
    assert!(fixture.engine.prepare("SELECT 1, 2", vec![]).await.is_err());
    let defaults: Limits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.parser, Parser::default());
    assert_eq!(defaults.parameter_count, None);
    assert_eq!(defaults.parameter_bytes, None);
    assert_eq!(defaults.projection_columns, None);
    assert_eq!(defaults.window_bound, None);
}

#[test]
fn native_tables_keep_data() {
    let fixture = Fixture::new(Limits::default());
    let table: Arc<dyn TableProvider> =
        Arc::new(MemTable::try_new(schema(), vec![vec![batch(41)]]).unwrap());
    let empty: Arc<dyn TableProvider> =
        Arc::new(MemTable::try_new(schema(), vec![vec![]]).unwrap());
    let state = fixture
        .engine
        .catalog(BTreeMap::from([
            ("literal".into(), table),
            ("empty".into(), empty),
        ]))
        .unwrap();
    let mut session = fixture
        .engine
        .session(AnalysisSelectionV1::new([1; 16], vec![]), &control(), 1)
        .unwrap();
    session.register("literal", schema(), &[batch(99)]).unwrap();
    session.register("empty", schema(), &[batch(99)]).unwrap();
    let plan = fixture
        .engine
        .plan(
            &state,
            Parser::default()
                .parse("SELECT value FROM literal")
                .unwrap(),
            vec![],
        )
        .unwrap();
    assert_eq!(value(&session.collect_local(Arc::new(plan)).unwrap()), 41);
    let plan = fixture
        .engine
        .plan(
            &state,
            Parser::default()
                .parse("SELECT count(*) AS total FROM empty")
                .unwrap(),
            vec![],
        )
        .unwrap();
    assert_eq!(value(&session.collect_local(Arc::new(plan)).unwrap()), 0);
}

#[derive(Debug)]
struct PlanningGate {
    entered: Arc<Notify>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl datafusion::optimizer::OptimizerRule for PlanningGate {
    fn name(&self) -> &str {
        "planning_gate"
    }
    fn rewrite(
        &self,
        plan: LogicalPlan,
        _: &dyn datafusion::optimizer::OptimizerConfig,
    ) -> NativeResult<datafusion::common::tree_node::Transformed<LogicalPlan>> {
        if let Some(release) = self.release.lock().unwrap().take() {
            self.entered.notify_one();
            release
                .recv_timeout(Duration::from_secs(5))
                .map_err(|error| datafusion::common::DataFusionError::External(Box::new(error)))?;
        }
        Ok(datafusion::common::tree_node::Transformed::no(plan))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn planning_cancel_joins_worker(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::StreamExt as _;

    let mut fixture = Fixture::new(Limits::default());
    let (plan, sources) = fixture
        .engine
        .prepare("SELECT * FROM catalog", Vec::new())
        .await?;
    let entered = Arc::new(Notify::new());
    let (release, held) = std::sync::mpsc::channel();
    let engine =
        Arc::get_mut(&mut fixture.engine).ok_or("engine shared before rule registration")?;
    let mut rules = engine.state.optimizers().to_vec();
    rules.push(Arc::new(PlanningGate {
        entered: Arc::clone(&entered),
        release: std::sync::Mutex::new(Some(held)),
    }));
    engine.state = super::SessionStateBuilder::new_from_existing(engine.state.clone())
        .with_optimizer_rules(rules)
        .build();
    let session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        1,
    )?;
    let mut subscription = session.subscribe(plan, sources, b"planning", true)?;
    tokio::select! {
        () = entered.notified() => {}
        result = subscription.next() => return Err(format!("planner completed before release: {result:?}").into()),
    }
    let mut joined = Box::pin(subscription.cancel_and_join());
    assert!(futures_util::poll!(joined.as_mut()).is_pending());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(5), joined).await??;
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(fixture.engine.memory().reserve_input(128 * 1024 * 1024)?);
    drop(fixture.engine.memory().reserve_output(16 * 1024 * 1024)?);
    Ok(())
}
