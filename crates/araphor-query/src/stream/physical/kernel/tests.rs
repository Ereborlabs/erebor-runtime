use std::collections::BTreeSet;
use std::time::Duration;

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisSelectionV1, AnalysisStore,
    ContextSensitivityV1,
};
use datafusion::arrow::array::{ArrayRef, BooleanArray, Int32Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::ScalarValue;
use datafusion::datasource::MemTable;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::physical_optimizer::combine_partial_final_agg::CombinePartialFinalAggregate;
use datafusion::prelude::{SessionConfig, SessionContext};
use tokio::sync::mpsc;

use super::*;
use crate::execution::Limits;

struct Fixture {
    plan: Arc<dyn ExecutionPlan>,
    engine: Arc<Engine>,
    control: Arc<AnalysisReadControl>,
    sender: mpsc::Sender<Result<Message>>,
    output: OutputStream,
    revision: u64,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn plan(sql: &str) -> Arc<dyn ExecutionPlan> {
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
        aggregate.unwrap()
    }

    async fn new(sql: &str) -> Self {
        let plan = Self::plan(sql).await;
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let engine = Engine::new(
            store,
            Limits {
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
            Arc::clone(&engine),
            Arc::clone(&control),
        );
        Self {
            plan,
            engine,
            control,
            sender,
            output,
            revision: 0,
            _directory: directory,
        }
    }

    fn batch(&self, values: Vec<Option<i32>>, flags: Vec<Option<bool>>) -> RecordBatch {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(Int32Array::from(values)),
            Arc::new(BooleanArray::from(flags)),
        ];
        let input = self
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap()
            .input_schema();
        RecordBatch::try_new(input, columns).unwrap()
    }

    async fn send(&self, message: Message) {
        assert!(self.sender.send(Ok(message)).await.is_ok());
    }

    async fn begin(&self) -> Arc<AnalysisReadControl> {
        let control = Arc::new(
            self.control
                .within(self.engine.limits().evaluate_timeout)
                .unwrap(),
        );
        self.send(Message::Begin(Arc::clone(&control))).await;
        control
    }

    async fn commit(&mut self) -> Arc<crate::sources::ArrowSnapshot> {
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
        let snapshot = self
            .engine
            .metadata(
                AnalysisSelectionV1::new([1; 16], vec![]),
                &BTreeSet::new(),
                &self.control,
                1,
            )
            .await
            .unwrap();
        self.send(Message::Commit {
            position: snapshot.page.scanned_through,
            snapshot: Arc::clone(&snapshot),
            _permit: None,
        })
        .await;
        snapshot
    }

    async fn apply(&mut self, before: &[RecordBatch], after: &[RecordBatch]) -> Vec<i64> {
        let control = self.begin().await;
        for batch in before {
            self.send(Message::Delete(batch.clone())).await;
        }
        for batch in after {
            self.send(Message::Insert(batch.clone())).await;
        }
        let snapshot = self.commit().await;
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
async fn native_error_closes_without_output() {
    let mut fixture = Fixture::new("SELECT COUNT(10 / value) FROM input").await;
    let first = fixture.batch(vec![Some(1)], vec![None]);
    assert_eq!(
        fixture.apply(&[], std::slice::from_ref(&first)).await,
        vec![1]
    );
    fixture.begin().await;
    fixture.send(Message::Delete(first)).await;
    fixture
        .send(Message::Insert(fixture.batch(vec![Some(0)], vec![None])))
        .await;
    assert!(fixture.output.next().await.unwrap().is_err());
    assert!(fixture.output.next().await.is_none());
    assert!(fixture
        .sender
        .send(Ok(Message::Insert(
            fixture.batch(vec![Some(2)], vec![None])
        )))
        .await
        .is_err());
}

#[tokio::test]
async fn unsupported_aggregates_are_explicit() {
    for sql in [
        "SELECT SUM(value) FROM input",
        "SELECT COUNT(DISTINCT value) FROM input",
        "SELECT flag, COUNT(*) FROM input GROUP BY flag",
    ] {
        let mut fixture = Fixture::new(sql).await;
        let native = fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap();
        if sql.contains("DISTINCT") {
            assert!(native.aggr_expr()[0].is_distinct());
        }
        let expected = if sql.contains("GROUP BY") {
            "maintained global COUNT aggregate"
        } else {
            "maintained ordinary COUNT aggregate"
        };
        assert!(matches!(
            fixture.output.next().await.unwrap(),
            Err(crate::Error::Sql { source: DataFusionError::NotImplemented(reason) })
                if reason == expected
        ));
        assert!(fixture.output.next().await.is_none());
    }
}

#[tokio::test]
async fn native_partial_mode_is_explicit() {
    let fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let native = fixture
        .plan
        .as_any()
        .downcast_ref::<AggregateExec>()
        .unwrap();
    let partial = AggregateExec::try_new(
        AggregateMode::Partial,
        native.group_expr().clone(),
        native.aggr_expr().to_vec(),
        native.filter_expr().to_vec(),
        Arc::clone(native.input()),
        native.input_schema(),
    )
    .unwrap();
    let mut output = execute(
        &partial,
        Box::pin(stream::pending()),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    assert!(matches!(
        output.next().await.unwrap(),
        Err(crate::Error::Sql { source: DataFusionError::NotImplemented(reason) })
            if reason == "maintained global COUNT aggregate"
    ));
    assert!(output.next().await.is_none());
}

#[tokio::test]
async fn commit_withholds_partial_changes() {
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    fixture.begin().await;
    fixture
        .send(Message::Insert(fixture.batch(vec![Some(1)], vec![None])))
        .await;
    assert!(futures_util::poll!(fixture.output.next()).is_pending());
    fixture
        .send(Message::Insert(fixture.batch(vec![Some(2)], vec![None])))
        .await;
    assert!(futures_util::poll!(fixture.output.next()).is_pending());
    let snapshot = fixture.commit().await;
    let output = fixture.output.next().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
    assert_eq!(
        ScalarValue::try_from_array(output.batches.unwrap()[0].column(0), 0).unwrap(),
        ScalarValue::Int64(Some(2))
    );
    drop(fixture.sender);
    assert!(fixture.output.next().await.is_none());
}

#[tokio::test]
async fn unfinished_input_releases_on_error() {
    let fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    let producer = Arc::new(());
    let weak = Arc::downgrade(&producer);
    let message = Message::Insert(fixture.batch(vec![Some(1)], vec![None]));
    let messages = vec![Message::Begin(Arc::clone(&fixture.control)), message].into_iter();
    let input = stream::unfold((messages, producer), |(mut messages, producer)| async {
        messages
            .next()
            .map(|message| (Ok(message), (messages, producer)))
    });
    let mut output = execute(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Box::pin(input),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    assert!(matches!(
        output.next().await.unwrap(),
        Err(crate::Error::Sql { source: DataFusionError::Execution(reason) })
            if reason == "maintained input ended before commit"
    ));
    assert!(weak.upgrade().is_none());
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
    fixture.begin().await;
    let snapshot = fixture.commit().await;
    let mut independent = execute(
        fixture
            .plan
            .as_any()
            .downcast_ref::<AggregateExec>()
            .unwrap(),
        Box::pin(stream::iter([
            Ok(Message::Begin(Arc::clone(&fixture.control))),
            Ok(Message::Commit {
                position: snapshot.page.scanned_through,
                snapshot: Arc::clone(&snapshot),
                _permit: None,
            }),
        ])),
        Arc::clone(&fixture.engine),
        Arc::clone(&fixture.control),
    );
    let output = independent.next().await.unwrap().unwrap();
    assert!(Arc::ptr_eq(&output.snapshot, &snapshot));
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
    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    fixture.begin().await;
    let snapshot = fixture.commit().await;
    assert!(fixture.output.next().await.unwrap().is_ok());
    fixture.begin().await;
    fixture
        .send(Message::Commit {
            position: snapshot.page.scanned_through,
            snapshot,
            _permit: None,
        })
        .await;
    assert!(fixture.output.next().await.unwrap().is_err());
    assert!(fixture.output.next().await.is_none());

    let mut fixture = Fixture::new("SELECT COUNT(*) FROM input").await;
    fixture.begin().await;
    let snapshot = fixture.commit().await;
    assert!(fixture.output.next().await.unwrap().is_ok());
    fixture.begin().await;
    let mut position = snapshot.page.scanned_through;
    position.ordinal = 0;
    fixture
        .send(Message::Commit {
            position,
            snapshot,
            _permit: None,
        })
        .await;
    assert!(fixture.output.next().await.unwrap().is_err());
    assert!(fixture.output.next().await.is_none());
}
