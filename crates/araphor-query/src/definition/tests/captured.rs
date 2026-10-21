use std::any::Any;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use araphor_data::{AnalysisSelectionV1, PackageErrorCodeV1};
use araphor_package_runtime::TaskTracker;
use async_trait::async_trait;
use datafusion::catalog::{Session as NativeSession, TableProvider};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::datasource::provider_as_source;
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{
    col, create_udf, dml::InsertOp, Expr, Extension, LogicalPlanBuilder, Partitioning, TableType,
    Volatility,
};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, ExecutionPlanProperties, SendableRecordBatchStream,
};
use futures_util::{FutureExt as _, TryStreamExt as _};

use super::execution::{component, invocation};
use super::*;
use crate::definition::{ExecutionReceipt, Invocation};

const NOW: u64 = 1_700_000_000_123_456_789;
const INPUT: usize = 4 * 1024 * 1024;
const OUTPUT: usize = 1024 * 1024;

mod managed;

#[derive(Debug)]
struct WriterGate {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[derive(Debug, Default)]
struct SinkState {
    admitted: AtomicBool,
    rebuild: AtomicBool,
    begins: AtomicUsize,
    admissions: AtomicUsize,
    begin_gate: Option<WriterGate>,
    admission_gate: Option<WriterGate>,
    input_evaluations: AtomicUsize,
    partitions: AtomicUsize,
    entries: AtomicUsize,
    commits: AtomicUsize,
    receipt: Mutex<Option<ExecutionReceipt>>,
    frontier: Mutex<Option<araphor_data::ManagedFrontier>>,
    gate: Option<WriterGate>,
}

#[derive(Clone, Debug)]
struct Sink {
    schema: sdk::arrow_schema::SchemaRef,
    calls: Vec<PackageCall>,
    state: Arc<SinkState>,
    managed: Option<araphor_data::ManagedInstance>,
}

impl DisplayAs for Sink {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapturedTestSink")
    }
}

#[async_trait]
impl TableProvider for Sink {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> sdk::arrow_schema::SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _: &dyn NativeSession,
        _: Option<&Vec<usize>>,
        _: &[Expr],
        _: Option<usize>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        Err(DataFusionError::Plan(
            "the test target has no reader".into(),
        ))
    }

    async fn insert_into(
        &self,
        _: &dyn NativeSession,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        assert!(matches!(operation, InsertOp::Append));
        assert_eq!(input.schema(), self.schema);
        self.state.partitions.store(
            input.output_partitioning().partition_count(),
            Ordering::SeqCst,
        );
        Ok(Arc::new(DataSinkExec::new(
            input,
            Arc::new(self.clone()),
            None,
        )))
    }
}

#[async_trait]
impl DataSink for Sink {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> &sdk::arrow_schema::SchemaRef {
        &self.schema
    }

    async fn write_all(
        &self,
        mut data: SendableRecordBatchStream,
        context: &Arc<TaskContext>,
    ) -> NativeResult<u64> {
        self.state.entries.fetch_add(1, Ordering::SeqCst);
        if self.managed.is_some() {
            let run = context
                .session_config()
                .get_extension::<crate::stream::Run>()
                .ok_or_else(|| DataFusionError::Internal("managed native run".into()))?;
            let (definition, _) = run
                .managed
                .as_ref()
                .ok_or_else(|| DataFusionError::Internal("managed definition".into()))?;
            assert!(std::ptr::eq(run.sources(), definition.sources()));
        }
        let mut rows = 0;
        while let Some(batch) = data.try_next().await? {
            rows += batch.num_rows() as u64;
        }
        let receipt = ExecutionReceipt::from_context(context)?;
        assert_eq!(receipt.calls().len(), self.calls.len());
        for call in &self.calls {
            assert!(receipt.calls()[&call.id()].belongs_to(call));
        }
        let previous = self.state.receipt.lock().unwrap().take();
        if let Some(previous) = previous {
            let error = previous
                .blocking(context, (), |_| Ok(()))
                .await
                .expect_err("a receipt crossed execution contexts");
            assert_eq!(
                crate::Failure::from(&crate::Error::Sql { source: error }),
                crate::Failure::InvalidQuery,
            );
        }
        *self.state.receipt.lock().unwrap() = Some(receipt.clone());
        let state = Arc::clone(&self.state);
        receipt
            .blocking(context, (), move |control| {
                if let Some(gate) = &state.gate {
                    if let Some(entered) = gate.entered.lock().unwrap().take() {
                        let _sent = entered.send(());
                    }
                    gate.release
                        .lock()
                        .unwrap()
                        .recv()
                        .map_err(|source| crate::Error::Sql {
                            source: DataFusionError::External(Box::new(source)),
                        })?;
                }
                control.check()?;
                state.commits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await?;
        Ok(rows)
    }
}

async fn fixture() -> TestResult<Fixture> {
    let mut bundle = component("wasm", "count-input")?;
    bundle.artifacts[0].descriptor.exports[0].limits.max_bytes = 16 * 1024;
    let call = r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
        input => (SELECT source_cursor AS value FROM events), mode => 'sum-input', amount => 0)"#;
    let fixture = Fixture::image_limits(
        Limits {
            global_evaluations: Some(1),
            tenant_evaluations: Some(1),
            input_bytes: INPUT,
            input_capacity: Some(INPUT),
            output_capacity: Some(OUTPUT),
            ..Default::default()
        },
        &bundle,
        &Fixture::sql(format!("{call} UNION ALL {call}")),
    )
    .await?;
    fixture.event(1)?;
    Ok(fixture)
}

async fn definition(fixture: &Fixture, state: Arc<SinkState>) -> TestResult<PreparedDefinition> {
    let call = r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
        input => (SELECT source_cursor AS value FROM events), mode => 'sum-input', amount => 0)"#;
    let mut definition = fixture
        .prepare(&Fixture::sql(format!("{call} UNION ALL {call}")))
        .await?;
    let admitted = Arc::clone(&state);
    let gate = create_udf(
        "captured_attempt_gate",
        vec![sdk::DataType::UInt64],
        sdk::DataType::UInt64,
        Volatility::Volatile,
        Arc::new(move |arguments| {
            admitted.input_evaluations.fetch_add(1, Ordering::SeqCst);
            if !admitted.admitted.load(Ordering::SeqCst) {
                return Err(DataFusionError::Execution(
                    "the guest input started before the attempt".into(),
                ));
            }
            arguments
                .first()
                .cloned()
                .ok_or_else(|| DataFusionError::Execution("test input absent".into()))
        }),
    );
    definition.plan = definition
        .plan
        .transform_up(|plan| {
            if let LogicalPlan::Extension(extension) = &plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    let mut children = call.children.clone();
                    children[0] = LogicalPlanBuilder::from(children[0].clone())
                        .project(vec![gate.call(vec![col("value")]).alias("value")])?
                        .build()?;
                    let call = call.with_exprs_and_inputs(Vec::new(), children)?;
                    return Ok(Transformed::yes(LogicalPlan::Extension(Extension {
                        node: Arc::new(call),
                    })));
                }
            }
            Ok(Transformed::no(plan))
        })?
        .data;
    definition.plan = PackageCall::seal(definition.plan)?;
    let calls = Fixture::calls(&definition.plan)?;
    assert_eq!(calls.len(), 2);
    let plan = LogicalPlanBuilder::from(definition.plan)
        .repartition(Partitioning::RoundRobinBatch(3))?
        .build()?;
    let target = Arc::new(Sink {
        schema: Arc::clone(plan.schema().inner()),
        calls,
        state,
        managed: None,
    });
    definition.plan = LogicalPlanBuilder::insert_into(
        plan,
        "captured_test_target",
        provider_as_source(target),
        InsertOp::Append,
    )?
    .build()?;
    Ok(definition)
}

fn released(fixture: &Fixture) -> TestResult {
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .ok_or("input capacity")?,
        )?,
    );
    drop(fixture.engine.memory().reserve_output(OUTPUT)?);
    Ok(())
}

#[tokio::test]
async fn native_count_precedes_commit() -> TestResult {
    use sdk::arrow_array::Array as _;

    let count = sdk::arrow_array::UInt64Array::from(vec![0]);
    let bytes = count.get_array_memory_size();
    assert_eq!(count.get_buffer_memory_size(), 8);
    for (capacity, output_bytes, succeeds) in
        [(7, bytes, false), (8, bytes - 1, false), (8, bytes, true)]
    {
        let fixture = Fixture::limits(Limits {
            output_capacity: Some(capacity),
            ..Default::default()
        })?;
        let mut definition = fixture
            .prepare(&Fixture::sql("SELECT CAST(7 AS BIGINT UNSIGNED) AS value"))
            .await?;
        let state = Arc::new(SinkState::default());
        let target = Arc::new(Sink {
            schema: Arc::clone(definition.plan.schema().inner()),
            calls: Vec::new(),
            state: Arc::clone(&state),
            managed: None,
        });
        definition.plan = LogicalPlanBuilder::insert_into(
            definition.plan,
            "captured_test_target",
            provider_as_source(target),
            InsertOp::Append,
        )?
        .build()?;
        let mut session = fixture.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::default(),
            NOW,
        )?;
        session.set_output(1, output_bytes)?;
        let captured = session
            .capture_definition(&definition, Invocation::default())
            .await;
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        if succeeds {
            let captured = captured?;
            assert!(fixture.engine.memory().reserve_output(1).is_err());
            let output = captured.execute().await?;
            assert_eq!(state.commits.load(Ordering::SeqCst), 1);
            assert_eq!(output.batches[0].get_array_memory_size(), bytes);
            assert!(fixture.engine.memory().reserve_output(1).is_err());
            drop(output);
            drop(state.receipt.lock().unwrap().take());
        } else {
            assert!(captured.is_err());
            assert_eq!(state.entries.load(Ordering::SeqCst), 0);
        }
        drop(fixture.engine.memory().reserve_output(capacity)?);
    }
    Ok(())
}

#[tokio::test]
async fn capture_precedes_native_guest() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let definition = definition(&fixture, Arc::clone(&state)).await?;
    let parent = TaskTracker::new();
    let mut session = fixture.engine.session(
        AnalysisSelectionV1::tenant([1; 16]),
        &AnalysisReadControl::default(),
        NOW,
    )?;
    session.workers = Some(parent.clone());
    let captured = session
        .capture_definition(&definition, invocation("captured"))
        .await?;
    assert_eq!(state.partitions.load(Ordering::SeqCst), 3);
    assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 0);
    assert_eq!(state.entries.load(Ordering::SeqCst), 0);
    assert_eq!(parent.len(), 0);
    let revision = captured.snapshot().page.extraction.meta.commit_revision;
    fixture.event(2)?;
    state.admitted.store(true, Ordering::SeqCst);
    let output = captured.execute().await?;
    assert_eq!(
        output.snapshot.page.extraction.meta.commit_revision,
        revision
    );
    assert_eq!(output.calls.len(), 2);
    assert_eq!(state.input_evaluations.load(Ordering::SeqCst), 2);
    for call in output.calls.values() {
        assert_eq!(call.evaluation().context.time_utc_ns, NOW as i64);
        assert_eq!(call.evaluation().context.seed, Some(7));
        assert_eq!(call.evaluation().inputs.len(), 1);
        assert_eq!(call.output().datasets.len(), 1);
        for data in [
            &call.evaluation().inputs[0].data,
            &call.output().datasets[0],
        ] {
            let mut actual = Vec::new();
            for batch in &data.batches {
                let values = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .ok_or("captured UInt64 dataset absent")?;
                actual.extend_from_slice(values.values());
            }
            assert_eq!(actual, [1]);
        }
    }
    assert_eq!(state.entries.load(Ordering::SeqCst), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert_eq!(output.batches.len(), 1);
    let count = output.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("native count result absent")?;
    assert_eq!(count.value(0), 2);
    let receipt = state
        .receipt
        .lock()
        .unwrap()
        .take()
        .ok_or("receipt absent")?;
    assert_eq!(
        receipt.snapshot().page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1
    );
    parent.close();
    assert!(parent.wait().now_or_never().is_some());
    assert_eq!(receipt.calls().len(), 2);
    assert_eq!(output.calls.len(), 2);
    drop(receipt);
    drop(output);
    drop(definition);
    released(&fixture)
}

#[tokio::test]
async fn captured_cancel_releases() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let definition = definition(&fixture, Arc::clone(&state)).await?;
    let (entry, observed) = mpsc::channel();
    fixture.engine.guest_entry(entry, None)?;
    let control = AnalysisReadControl::default();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let captured = session
        .capture_definition(&definition, invocation("unused"))
        .await?;
    captured.cancel_and_join().await?;
    control.check()?;
    assert!(matches!(
        observed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(state.entries.load(Ordering::SeqCst), 0);
    drop(definition);
    released(&fixture)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_cancel_joins_reader() -> TestResult {
    let fixture = fixture().await?;
    let definition = definition(&fixture, Arc::new(SinkState::default())).await?;
    let control = AnalysisReadControl::default();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, held) = mpsc::channel();
    control.on_read_step(move || {
        let _sent = entered.send(());
        held.recv()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("test capture release"))?;
        Ok(())
    })?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    let mut capture = Box::pin(session.capture_definition(&definition, invocation("read")));
    tokio::select! {
        result = &mut capture => return Err(format!("capture ended before entry: {:?}", result.err()).into()),
        entered = observed => entered?,
    }
    control.cancel()?;
    assert!(capture.as_mut().now_or_never().is_none());
    assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
    release.send(())?;
    let error = tokio::time::timeout(Duration::from_secs(30), capture)
        .await?
        .err()
        .ok_or("cancelled capture succeeded")?;
    assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
    drop(definition);
    released(&fixture)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_writer_cancel_joins() -> TestResult {
    for cancel in [true, false] {
        let fixture = fixture().await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, held) = mpsc::channel();
        let state = Arc::new(SinkState {
            gate: Some(WriterGate {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(held),
            }),
            ..Default::default()
        });
        let definition = definition(&fixture, Arc::clone(&state)).await?;
        let control = AnalysisReadControl::default();
        let parent = TaskTracker::new();
        let mut session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
        session.workers = Some(parent.clone());
        let captured = session
            .capture_definition(&definition, invocation("writer"))
            .await?;
        state.admitted.store(true, Ordering::SeqCst);
        let mut execution = Box::pin(captured.execute());
        tokio::select! {
            result = &mut execution => return Err(format!("execution ended before writer: {:?}", result.err()).into()),
            entered = observed => entered?,
        }
        if cancel {
            control.cancel()?;
            assert!(execution.as_mut().now_or_never().is_none());
            assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
            release.send(())?;
            let error = tokio::time::timeout(Duration::from_secs(30), execution)
                .await?
                .err()
                .ok_or("cancelled writer succeeded")?;
            assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
        } else {
            drop(execution);
            parent.close();
            assert!(parent.wait().now_or_never().is_none());
            assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(30), parent.wait()).await?;
            control.check()?;
        }
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        drop(state.receipt.lock().unwrap().take());
        drop(definition);
        released(&fixture)?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_cancel_joins_optimizer() -> TestResult {
    use datafusion::logical_expr::lit;

    for cancel in [true, false] {
        let fixture = fixture().await?;
        let mut definition = fixture.prepare(&Fixture::sql("SELECT 7 AS value")).await?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let entered = Mutex::new(Some(entered));
        let (release, held) = mpsc::channel();
        let held = Mutex::new(held);
        let gate = create_udf(
            "capture_optimizer_gate",
            vec![sdk::DataType::UInt64],
            sdk::DataType::UInt64,
            Volatility::Immutable,
            Arc::new(move |arguments| {
                if let Some(entered) = entered.lock().unwrap().take() {
                    let _sent = entered.send(());
                    held.lock()
                        .unwrap()
                        .recv()
                        .map_err(|source| DataFusionError::External(Box::new(source)))?;
                }
                arguments
                    .first()
                    .cloned()
                    .ok_or_else(|| DataFusionError::Execution("test optimizer input absent".into()))
            }),
        );
        definition.plan = LogicalPlanBuilder::from(definition.plan)
            .project(vec![gate.call(vec![lit(7_u64)]).alias("value")])?
            .build()?;
        let control = AnalysisReadControl::default();
        let parent = TaskTracker::new();
        let mut session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
        session.workers = Some(parent.clone());
        let mut capture =
            Box::pin(session.capture_definition(&definition, invocation("optimizer")));
        tokio::select! {
            result = &mut capture => return Err(format!("capture ended before optimizer: {:?}", result.err()).into()),
            entered = observed => entered?,
        }
        if cancel {
            control.cancel()?;
            assert!(capture.as_mut().now_or_never().is_none());
            release.send(())?;
            let error = tokio::time::timeout(Duration::from_secs(30), capture)
                .await?
                .err()
                .ok_or("cancelled optimizer succeeded")?;
            assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
        } else {
            drop(capture);
            parent.close();
            assert!(parent.wait().now_or_never().is_none());
            assert!(fixture.engine.reserve_evaluation([1; 16]).is_err());
            release.send(())?;
            tokio::time::timeout(Duration::from_secs(30), parent.wait()).await?;
            control.check()?;
        }
        drop(definition);
        released(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn native_receipt_keeps_context() -> TestResult {
    let fixture = fixture().await?;
    let state = Arc::new(SinkState::default());
    let definition = definition(&fixture, Arc::clone(&state)).await?;
    state.admitted.store(true, Ordering::SeqCst);
    let control = AnalysisReadControl::default();
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control, NOW)?;
    for id in ["first", "second"] {
        let output = session
            .execute_definition(&definition, invocation(id))
            .await?;
        assert_eq!(output.calls.len(), 2);
        drop(output);
        control.check()?;
    }
    assert_eq!(state.commits.load(Ordering::SeqCst), 2);
    drop(state.receipt.lock().unwrap().take());
    drop(definition);
    released(&fixture)
}
