use std::collections::BTreeMap;
use std::mem::size_of;
use std::time::Duration;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisSelectionV1, AnalysisStore,
    ContextSensitivityV1,
};
use datafusion::arrow::array::{Array as _, ArrayRef, BooleanArray, Int32Array, Int64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::ScalarValue;
use datafusion::datasource::MemTable;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::TaskContext;
use datafusion::physical_optimizer::combine_partial_final_agg::CombinePartialFinalAggregate;
use datafusion::prelude::{SessionConfig, SessionContext};
use tokio::sync::mpsc;

use super::super::SubscribeExec;
use super::*;
use crate::execution::Limits;
use crate::sources::{JournalExec, SourceData};
use crate::stream::Change;

struct Fixture {
    plan: Arc<dyn ExecutionPlan>,
    source: Arc<dyn ExecutionPlan>,
    context: Arc<TaskContext>,
    engine: Arc<Engine>,
    control: Arc<AnalysisReadControl>,
    sender: mpsc::Sender<Result<Change>>,
    output: OutputStream,
    revision: u64,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn plan(
        sql: &str,
    ) -> (
        Arc<dyn ExecutionPlan>,
        Arc<dyn ExecutionPlan>,
        Arc<TaskContext>,
    ) {
        let context =
            SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1));
        let schema = Arc::new(Schema::new(vec![
            Field::new("value", DataType::Int32, true),
            Field::new("flag", DataType::Boolean, true),
        ]));
        context
            .register_table(
                "input",
                Arc::new(MemTable::try_new(schema, vec![vec![]]).unwrap()),
            )
            .unwrap();
        let state = SessionStateBuilder::new_from_existing(context.state())
            .with_optimizer_rules(vec![])
            .with_physical_optimizer_rules(vec![Arc::new(CombinePartialFinalAggregate::new())])
            .build();
        let plan = crate::planner::Planner::new(&state)
            .build(crate::parser::Parser::parse(sql).unwrap(), Vec::new())
            .await
            .unwrap();
        let plan = state.create_physical_plan(&plan).await.unwrap();
        let mut aggregate = None;
        plan.apply(|plan| {
            if plan.as_any().is::<AggregateExec>() {
                aggregate = Some(Arc::clone(plan));
                Ok(TreeNodeRecursion::Stop)
            } else {
                Ok(TreeNodeRecursion::Continue)
            }
        })
        .unwrap();
        let aggregate = aggregate.unwrap();
        let mut source = Arc::clone(
            aggregate
                .as_any()
                .downcast_ref::<AggregateExec>()
                .unwrap()
                .input(),
        );
        loop {
            let children = source.children();
            let next = match children.as_slice() {
                [] => break,
                [child] => Arc::clone(child),
                _ => panic!("the fixture has one native source"),
            };
            source = next;
        }
        (aggregate, source, state.task_ctx())
    }

    async fn new(sql: &str) -> Self {
        Self::bounded(sql, Limits::default().input_bytes).await
    }

    async fn bounded(sql: &str, input_bytes: usize) -> Self {
        let (plan, source, context) = Self::plan(sql).await;
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(
            store,
            Limits {
                input_bytes,
                extract_timeout: Duration::from_secs(5),
                evaluate_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .unwrap();
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(30)).unwrap());
        let (sender, input) = mpsc::channel(32);
        let input = stream::unfold(input, |mut input| async {
            input.recv().await.map(|message| (message, input))
        });
        let output = execute(
            plan.as_any().downcast_ref::<AggregateExec>().unwrap(),
            Box::pin(input),
            Arc::clone(&source),
            Arc::clone(&context),
            Arc::clone(&engine),
            Arc::clone(&control),
        );
        Self {
            plan,
            source,
            context,
            engine,
            control,
            sender,
            output,
            revision: 0,
            _directory: directory,
        }
    }

    async fn canonical(&self, sql: &str) -> (Arc<dyn ExecutionPlan>, Arc<dyn ExecutionPlan>) {
        let state = SessionStateBuilder::new_from_existing(
            self.engine.catalog(Default::default()).unwrap(),
        )
        .with_optimizer_rules(vec![])
        .with_physical_optimizer_rules(vec![Arc::new(CombinePartialFinalAggregate::new())])
        .build();
        let plan = crate::planner::Planner::new(&state)
            .build(crate::parser::Parser::parse(sql).unwrap(), Vec::new())
            .await
            .unwrap();
        let plan = state.create_physical_plan(&plan).await.unwrap();
        let mut journal = None;
        plan.apply(|node| {
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                assert!(journal.is_none());
                assert_eq!(source.origin.durable(), Some("events"));
                journal =
                    Some(Arc::new(JournalExec::new(source).unwrap()) as Arc<dyn ExecutionPlan>);
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        (plan, journal.unwrap())
    }

    fn batch(&self, values: Vec<Option<i32>>, flags: Vec<Option<bool>>) -> RecordBatch {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(Int32Array::from(values)),
            Arc::new(BooleanArray::from(flags)),
        ];
        RecordBatch::try_new(self.source.schema(), columns).unwrap()
    }

    async fn send(&self, change: Change) {
        assert!(self.sender.send(Ok(change)).await.is_ok());
    }

    async fn snapshot(&mut self) -> Arc<crate::sources::ArrowSnapshot> {
        self.revision += 1;
        self.engine
            .store()
            .commit_context(&AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "kernel-test".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![2],
                    owner_revision: self.revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: vec![1],
            })
            .unwrap();
        self.engine
            .metadata(
                AnalysisSelectionV1::new([1; 16], vec![]),
                &BTreeMap::new(),
                &self.control,
                1,
            )
            .await
            .unwrap()
    }

    async fn change(&mut self, before: &[RecordBatch], after: &[RecordBatch]) -> Change {
        let snapshot = self.snapshot().await;
        let before = before.to_vec();
        let after = after.to_vec();
        let memory = self
            .engine
            .memory()
            .reserve_input((before.capacity() + after.capacity()) * size_of::<RecordBatch>())
            .unwrap();
        for batch in before.iter().chain(&after) {
            self.engine.memory().retain_input(batch, &memory).unwrap();
        }
        Change {
            before,
            after,
            position: snapshot.page.scanned_through,
            snapshot,
            control: Arc::new(
                self.control
                    .within(self.engine.limits().evaluate_timeout)
                    .unwrap(),
            ),
            _permit: None,
            _memory: memory,
        }
    }

    async fn apply(&mut self, before: &[RecordBatch], after: &[RecordBatch]) -> Vec<i64> {
        let change = self.change(before, after).await;
        let snapshot = Arc::clone(&change.snapshot);
        let control = Arc::clone(&change.control);
        self.send(change).await;
        let output = self.output.next().await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
        assert!(Arc::ptr_eq(&output._control, &control));
        let batches = output.batches.unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].schema(), self.plan.schema());
        assert_eq!(batches[0].num_rows(), 1);
        batches[0]
            .columns()
            .iter()
            .map(
                |array| match ScalarValue::try_from_array(array, 0).unwrap() {
                    ScalarValue::Int64(Some(value)) => value,
                    value => panic!("native COUNT returned {value:?}"),
                },
            )
            .collect()
    }
}

#[tokio::test]
async fn count_retains_inserts_deletes_updates() {
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    assert_eq!(fixture.apply(&[], &[]).await, vec![0]);
    let first = fixture.batch(
        vec![Some(1), None, Some(2)],
        vec![Some(true), Some(false), None],
    );
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&first)).await,
        vec![3]
    );
    assert_eq!(fixture.apply(&[first.slice(1, 1)], &[]).await, vec![2]);
    let replacement = fixture.batch(vec![Some(3)], vec![Some(false)]);
    assert_eq!(
        fixture
            .apply(&[first.slice(0, 1)], std::slice::from_ref(&replacement))
            .await,
        vec![2]
    );
    assert_eq!(
        fixture.apply(&[replacement, first.slice(2, 1)], &[]).await,
        vec![0]
    );
    assert_eq!(fixture.apply(&[], &[]).await, vec![0]);
}

#[tokio::test]
async fn counts_preserve_native_filter_nulls_coercion() {
    let mut fixture = Fixture::new(
        "SELECT COUNT(*), COUNT(value), COUNT(value + CAST(1 AS BIGINT)), \
         COUNT(value) FILTER (WHERE flag), COUNT(*) FILTER (WHERE flag), \
         COUNT(value, flag) FROM input",
    )
    .await;
    assert_eq!(fixture.apply(&[], &[]).await, vec![0; 6]);
    let first = fixture.batch(
        vec![Some(1), None, Some(2), Some(3)],
        vec![Some(true), Some(true), Some(false), None],
    );
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&first)).await,
        vec![4, 3, 3, 1, 2, 2]
    );
    assert_eq!(
        fixture.apply(&[first.slice(0, 1)], &[]).await,
        vec![3, 2, 2, 0, 1, 1]
    );
    let replacement = fixture.batch(vec![None], vec![Some(true)]);
    assert_eq!(
        fixture.apply(&[first.slice(2, 1)], &[replacement]).await,
        vec![3, 1, 1, 0, 2, 0]
    );
}

#[tokio::test]
async fn filter_precedes_native_argument_evaluation() {
    let mut fixture =
        Fixture::new("SELECT COUNT(10 / value) FILTER (WHERE value <> 0) FROM input").await;
    let batch = fixture.batch(vec![Some(0), Some(2), None], vec![None; 3]);
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&batch)).await,
        vec![1]
    );
    assert_eq!(fixture.apply(&[batch.slice(0, 1)], &[]).await, vec![1]);
    assert_eq!(fixture.apply(&[batch.slice(1, 1)], &[]).await, vec![0]);
}

#[tokio::test]
async fn native_child_completes_cut() {
    let mut fixture = Fixture::new(
        "SELECT COUNT(value), COUNT(*) FILTER (WHERE flag), COUNT(*) \
         FROM (SELECT CASE WHEN flag THEN 100 / value ELSE NULL END AS value, flag \
         FROM input WHERE flag IS NOT FALSE)",
    )
    .await;
    let native = fixture
        .plan
        .as_any()
        .downcast_ref::<AggregateExec>()
        .unwrap();
    assert!(!Arc::ptr_eq(native.input(), &fixture.source));
    let (mut filtered, mut projected) = (false, false);
    native
        .input()
        .apply(|plan| {
            filtered |= plan
                .as_any()
                .is::<datafusion::physical_plan::filter::FilterExec>();
            projected |= plan
                .as_any()
                .is::<datafusion::physical_plan::projection::ProjectionExec>();
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
    assert!(filtered && projected);
    let first = vec![
        fixture.batch(
            vec![Some(0), Some(2), None],
            vec![Some(false), Some(true), Some(true)],
        ),
        fixture.batch(vec![Some(5), Some(3)], vec![Some(true), None]),
    ];
    assert_eq!(fixture.apply(&[], &first).await, vec![2, 3, 4]);
    let replacement = vec![
        fixture.batch(vec![Some(4)], vec![Some(true)]),
        fixture.batch(
            vec![Some(0), Some(10), None],
            vec![Some(false), Some(true), None],
        ),
    ];
    assert_eq!(fixture.apply(&first, &replacement).await, vec![2, 2, 3]);
    assert_eq!(fixture.apply(&replacement, &[]).await, vec![0, 0, 0]);
}

#[tokio::test]
async fn native_error_closes_without_output() {
    let mut fixture =
        Fixture::new("SELECT COUNT(value) FROM (SELECT 10 / value AS value FROM input)").await;
    let first = fixture.batch(vec![Some(1)], vec![None]);
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&first)).await,
        vec![1]
    );
    let change = fixture
        .change(
            &[first],
            &[
                fixture.batch(vec![Some(2)], vec![None]),
                fixture.batch(vec![Some(0)], vec![None]),
            ],
        )
        .await;
    fixture.send(change).await;
    assert!(fixture.output.next().await.unwrap().is_err());
    assert!(fixture.output.next().await.is_none());
    let change = fixture
        .change(&[], &[fixture.batch(vec![Some(2)], vec![None])])
        .await;
    assert!(fixture.sender.send(Ok(change)).await.is_err());
}

#[tokio::test]
async fn replacement_counts_both_signs() {
    let limit = 4096;
    let mut fixture = Fixture::bounded(
        "SELECT COUNT(value) FROM (SELECT CAST(value AS BIGINT) AS value FROM input)",
        limit,
    )
    .await;
    let transformed = Int64Array::from(vec![Some(1); 256]);
    let bytes = transformed.get_array_memory_size();
    assert!(bytes <= limit);
    assert!(bytes * 2 > limit);
    let first = fixture.batch(vec![Some(1); 256], vec![None; 256]);
    assert!(first.get_array_memory_size() * 2 <= limit);
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&first)).await,
        vec![256]
    );
    let replacement = fixture.batch(vec![Some(2); 256], vec![None; 256]);
    let change = fixture.change(&[first], &[replacement]).await;
    fixture.send(change).await;
    assert!(matches!(
        fixture.output.next().await.unwrap(),
        Err(crate::Error::Sql { source: DataFusionError::ResourcesExhausted(reason) })
            if reason == "maintained native input"
    ));
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(fixture.output.next().await.is_none());
}

#[tokio::test]
async fn unsupported_aggregates_are_explicit() {
    let fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let (single, journal) = fixture.canonical("SELECT COUNT(*) FROM events").await;
    let compiled = SubscribeExec::compile(&single, &journal).unwrap().unwrap();
    assert_eq!(
        compiled
            .aggregate
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap()
            .mode(),
        &AggregateMode::Single
    );
    for sql in [
        "SELECT SUM(kernel_sequence) FROM events",
        "SELECT COUNT(DISTINCT kernel_sequence) FROM events",
        "SELECT operation_argument, COUNT(*) FROM events GROUP BY operation_argument",
    ] {
        let (plan, journal) = fixture.canonical(sql).await;
        if sql.contains("DISTINCT") {
            let mut distinct = false;
            plan.apply(|node| {
                if let Some(native) = node.as_any().downcast_ref::<AggregateExec>() {
                    assert!(native.aggr_expr()[0].is_distinct());
                    distinct = true;
                    return Ok(TreeNodeRecursion::Stop);
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
            assert!(distinct);
        }
        assert!(SubscribeExec::compile(&plan, &journal).unwrap().is_none());
    }
}

#[tokio::test]
async fn native_partial_mode_is_explicit() {
    let fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let (single, journal) = fixture.canonical("SELECT COUNT(*) FROM events").await;
    let compiled = SubscribeExec::compile(&single, &journal).unwrap().unwrap();
    let native = compiled
        .aggregate
        .as_any()
        .downcast_ref::<AggregateExec>()
        .unwrap();
    assert_eq!(native.mode(), &AggregateMode::Single);
    let partial = AggregateExec::try_new(
        AggregateMode::Partial,
        native.group_expr().clone(),
        native.aggr_expr().to_vec(),
        native.filter_expr().to_vec(),
        Arc::clone(native.input()),
        native.input_schema(),
    )
    .unwrap();
    assert_eq!(partial.mode(), &AggregateMode::Partial);
    let partial = Arc::new(partial) as Arc<dyn ExecutionPlan>;
    assert!(SubscribeExec::compile(&partial, &journal)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn commit_withholds_partial_changes() {
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    assert!(futures_util::poll!(fixture.output.next()).is_pending());
    let change = fixture
        .change(
            &[],
            &[
                fixture.batch(vec![Some(1)], vec![None]),
                fixture.batch(vec![Some(2)], vec![None]),
            ],
        )
        .await;
    assert!(futures_util::poll!(fixture.output.next()).is_pending());
    let snapshot = Arc::clone(&change.snapshot);
    let control = Arc::clone(&change.control);
    fixture.send(change).await;
    let output = fixture.output.next().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
    assert!(Arc::ptr_eq(&output._control, &control));
    assert_eq!(
        ScalarValue::try_from_array(output.batches.unwrap()[0].column(0), 0).unwrap(),
        ScalarValue::Int64(Some(2))
    );
    drop(fixture.sender);
    assert!(fixture.output.next().await.is_none());
}

#[tokio::test]
async fn failed_transaction_releases_source() {
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let change = fixture
        .change(&[], &[fixture.batch(vec![Some(1)], vec![None])])
        .await;
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_err());
    let producer = Arc::new(());
    let weak = Arc::downgrade(&producer);
    let input = stream::unfold((Some(change), producer), |(change, producer)| async {
        assert!(change.is_some());
        drop(change);
        Some((
            Err(crate::Error::Sql {
                source: DataFusionError::Execution("transaction failed".into()),
            }),
            (None, producer),
        ))
    });
    let mut output = execute(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Box::pin(input),
        Arc::clone(&fixture.source),
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    assert!(matches!(
        output.next().await.unwrap(),
        Err(crate::Error::Sql { source: DataFusionError::Execution(reason) })
            if reason == "transaction failed"
    ));
    assert!(weak.upgrade().is_none());
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(output.next().await.is_none());
}

#[tokio::test]
async fn upstream_error_releases_execution_before_delivery() {
    let fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let producer = Arc::new(());
    let weak = Arc::downgrade(&producer);
    let engine = Arc::clone(&fixture.engine);
    let input = stream::unfold((true, producer), move |(first, producer)| {
        let engine = Arc::clone(&engine);
        async move {
            if !first {
                return std::future::pending().await;
            }
            assert!(engine
                .memory()
                .reserve_input(engine.limits().input_capacity)
                .is_err());
            Some((
                Err(crate::Error::Sql {
                    source: DataFusionError::Execution("upstream stopped".into()),
                }),
                (false, producer),
            ))
        }
    });
    let mut output = execute(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Box::pin(input),
        Arc::clone(&fixture.source),
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    assert!(matches!(
        output.next().await.unwrap(),
        Err(crate::Error::Sql { source: DataFusionError::Execution(reason) })
            if reason == "upstream stopped"
    ));
    assert!(weak.upgrade().is_none());
    assert!(fixture
        .engine
        .memory()
        .reserve_input(fixture.engine.limits().input_capacity)
        .is_ok());
    assert!(output.next().await.is_none());
}

#[tokio::test]
async fn execute_states_are_independent() {
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let batch = fixture.batch(vec![Some(1), Some(2)], vec![None; 2]);
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&batch)).await,
        vec![2]
    );
    let change = fixture.change(&[], &[]).await;
    let snapshot = Arc::clone(&change.snapshot);
    let control = Arc::clone(&change.control);
    let independent_change = Change {
        before: Vec::new(),
        after: Vec::new(),
        position: change.position,
        snapshot: Arc::clone(&snapshot),
        control: Arc::clone(&control),
        _permit: None,
        _memory: fixture.engine.memory().reserve_input(0).unwrap(),
    };
    fixture.send(change).await;
    let mut independent = execute(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Box::pin(stream::iter([Ok(independent_change)])),
        Arc::clone(&fixture.source),
        Arc::clone(&fixture.context),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    let output = independent.next().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
    assert!(Arc::ptr_eq(&output._control, &control));
    assert_eq!(
        ScalarValue::try_from_array(output.batches.unwrap()[0].column(0), 0).unwrap(),
        ScalarValue::Int64(Some(0))
    );
    assert!(independent.next().await.is_none());
    assert!(fixture.output.next().await.unwrap().is_ok());
    assert_eq!(fixture.apply(&[batch], &[]).await, vec![0]);
}

#[tokio::test]
async fn commit_requires_complete_advancing_frontier() {
    for invalid in 0..3 {
        let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
        let change = fixture.change(&[], &[]).await;
        let snapshot = Arc::clone(&change.snapshot);
        fixture.send(change).await;
        assert!(fixture.output.next().await.unwrap().is_ok());
        let mut change = fixture.change(&[], &[]).await;
        assert!(change.position > snapshot.page.scanned_through);
        match invalid {
            0 => {
                change.position = snapshot.page.scanned_through;
                change.snapshot = snapshot;
            }
            1 => change.position.ordinal = 0,
            2 => change.snapshot = snapshot,
            _ => unreachable!(),
        }
        fixture.send(change).await;
        assert!(fixture.output.next().await.unwrap().is_err());
        assert!(fixture.output.next().await.is_none());
    }
}
