use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use datafusion::arrow::array::{
    ArrayRef, RecordBatch, RecordBatchOptions, StringArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DataFusionError, ScalarValue};
use datafusion::execution::SessionState;
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_plan::aggregates::AggregateExec;
use datafusion::physical_plan::{collect, ExecutionPlan};
use futures_util::TryStreamExt as _;

use super::physical::SubscribeExec;
use crate::execution::{Engine, Limits};
use crate::parser::Parser;
use crate::planner::Planner;
use crate::sources::{SourceData, SourceSnapshot};

struct Fixture {
    engine: Arc<Engine>,
    state: SessionState,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        let limits = Limits {
            evaluate_timeout: Duration::from_secs(5),
            extract_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let engine = Engine::new(store, limits).unwrap();
        let state = engine.catalog(Default::default()).unwrap();
        let options = &state.config_options().catalog;
        let schema = state
            .catalog_list()
            .catalog(&options.default_catalog)
            .unwrap()
            .schema(&options.default_schema)
            .unwrap();
        for name in ["CaseTable", "__araphor_visible"] {
            schema
                .register_table(name.into(), SourceSnapshot::providers()["events"].clone())
                .unwrap();
        }
        Self {
            engine,
            state,
            _directory: directory,
        }
    }

    async fn plan(&self, sql: &str, parameters: Vec<ScalarValue>) -> LogicalPlan {
        Planner::new(&self.state)
            .build(Parser::parse(sql).unwrap(), parameters)
            .await
            .unwrap()
    }

    async fn physical(
        &self,
        sql: &str,
        parameters: Vec<ScalarValue>,
    ) -> (Arc<dyn ExecutionPlan>, Option<Arc<dyn ExecutionPlan>>) {
        let plan = self.plan(sql, parameters).await;
        let physical = self.state.create_physical_plan(&plan).await.unwrap();
        let mut source = None;
        physical
            .apply(|node| {
                if SourceData::from_plan(node.as_ref()).is_some() {
                    assert!(source.is_none());
                    source = Some(Arc::clone(node));
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
        (physical, source)
    }

    fn batch(&self, schema: SchemaRef) -> RecordBatch {
        let columns = schema
            .fields()
            .iter()
            .map(|field| -> ArrayRef {
                match field.name().as_str() {
                    "kernel_sequence" => {
                        Arc::new(UInt64Array::from(vec![Some(1), Some(2), None, Some(4)]))
                    }
                    "catalog_state" => Arc::new(StringArray::from(vec![
                        Some("one"),
                        Some("two"),
                        Some("none"),
                        None,
                    ])),
                    "operation_argument" => {
                        Arc::new(UInt32Array::from(vec![Some(1), Some(0), None, Some(1)]))
                    }
                    "source_cursor" => Arc::new(UInt64Array::from(vec![1, 2, 3, 4])),
                    name => panic!("unexpected source field {name}"),
                }
            })
            .collect();
        RecordBatch::try_new_with_options(
            schema,
            columns,
            &RecordBatchOptions::new().with_row_count(Some(4)),
        )
        .unwrap()
    }

    async fn run(
        &self,
        plan: &Arc<dyn ExecutionPlan>,
        source: &Arc<dyn ExecutionPlan>,
        batches: Vec<RecordBatch>,
    ) -> Vec<RecordBatch> {
        SubscribeExec::bind(plan, source, batches, self.state.task_ctx())
            .unwrap()
            .try_collect()
            .await
            .unwrap()
    }
}

fn aggregate(plan: &Arc<dyn ExecutionPlan>) -> Arc<dyn ExecutionPlan> {
    let mut aggregate = None;
    plan.apply(|node| {
        if node.as_any().is::<AggregateExec>() {
            aggregate = Some(Arc::clone(node));
            Ok(TreeNodeRecursion::Stop)
        } else {
            Ok(TreeNodeRecursion::Continue)
        }
    })
    .unwrap();
    aggregate.unwrap()
}

fn values(batches: &[RecordBatch], column: usize) -> Vec<ScalarValue> {
    batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows())
                .map(move |row| ScalarValue::try_from_array(batch.column(column), row).unwrap())
        })
        .collect()
}

#[tokio::test]
async fn native_parameters_preserve_metadata() {
    let fixture = Fixture::new();
    let (plan, source) = fixture.physical(
        "SELECT CAST(e.kernel_sequence AS BIGINT) + $1 AS adjusted, e.catalog_state AS \"MiXeD\" FROM events e WHERE e.kernel_sequence > $2",
        vec![ScalarValue::Int32(Some(2)), ScalarValue::UInt64(Some(1))],
    ).await;
    let source = source.unwrap();
    for _ in 0..2 {
        let batches = fixture
            .run(&plan, &source, vec![fixture.batch(source.schema())])
            .await;
        assert_eq!(batches[0].schema(), plan.schema());
        assert_eq!(batches[0].schema().field(1).name(), "MiXeD");
        let canonical = SourceSnapshot::providers()["events"].schema();
        assert_eq!(
            batches[0].schema().field(1).metadata(),
            canonical
                .field_with_name("catalog_state")
                .unwrap()
                .metadata()
        );
        assert_eq!(
            values(&batches, 0),
            [ScalarValue::Int64(Some(4)), ScalarValue::Int64(Some(6))]
        );
        assert_eq!(
            values(&batches, 1),
            [
                ScalarValue::Utf8(Some("two".into())),
                ScalarValue::Utf8(None)
            ]
        );
    }
}

#[tokio::test]
async fn native_null_filters() {
    let fixture = Fixture::new();
    for (predicate, expected) in [
        ("operation_argument > 0", vec![Some(1), Some(4)]),
        ("NOT (operation_argument > 0)", vec![Some(2)]),
        ("kernel_sequence IS NULL", vec![None]),
        ("kernel_sequence = NULL", vec![]),
    ] {
        let (plan, source) = fixture
            .physical(
                &format!("SELECT kernel_sequence FROM events WHERE {predicate}"),
                vec![],
            )
            .await;
        let batches = match source {
            Some(source) => {
                fixture
                    .run(&plan, &source, vec![fixture.batch(source.schema())])
                    .await
            }
            None => collect(plan, fixture.state.task_ctx()).await.unwrap(),
        };
        assert_eq!(
            values(&batches, 0),
            expected
                .into_iter()
                .map(ScalarValue::UInt64)
                .collect::<Vec<_>>(),
            "{predicate}"
        );
    }
}

#[tokio::test]
async fn native_zero_column_rows() {
    let fixture = Fixture::new();
    let (plan, source) = fixture
        .physical("SELECT 7 AS value FROM events", vec![])
        .await;
    let source = source.unwrap();
    assert!(source.schema().fields().is_empty());
    let batches = fixture
        .run(&plan, &source, vec![fixture.batch(source.schema())])
        .await;
    assert_eq!(values(&batches, 0), vec![ScalarValue::Int64(Some(7)); 4]);
    let (plan, source) = fixture
        .physical("SELECT count(*) FROM events", vec![])
        .await;
    let source = source.unwrap();
    assert!(source.schema().fields().is_empty());
    let aggregate = aggregate(&plan);
    let native = aggregate.as_any().downcast_ref::<AggregateExec>().unwrap();
    let after = fixture
        .run(
            native.input(),
            &source,
            vec![fixture.batch(source.schema())],
        )
        .await;
    assert_eq!(after.iter().map(RecordBatch::num_rows).sum::<usize>(), 4);
    assert!(after
        .iter()
        .all(|batch| batch.schema() == native.input_schema()));
    let batches = fixture
        .run(&plan, &source, vec![fixture.batch(source.schema())])
        .await;
    assert_eq!(values(&batches, 0), [ScalarValue::Int64(Some(4))]);
}

#[tokio::test]
async fn native_names_and_aliases() {
    let fixture = Fixture::new();
    for (sql, rows) in [
        (
            "SELECT kernel_sequence AS \"Value\" FROM __araphor_visible",
            4,
        ),
        (
            "WITH named AS (SELECT kernel_sequence AS value, operation_argument FROM \"CaseTable\") SELECT value AS \"Value\" FROM named WHERE operation_argument > 0",
            2,
        ),
    ] {
        let (plan, source) = fixture.physical(sql, vec![]).await;
        let source = source.unwrap();
        let batches = fixture
            .run(&plan, &source, vec![fixture.batch(source.schema())])
            .await;
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            rows
        );
        assert!(batches.iter().all(|batch| batch.schema() == plan.schema()));
        assert_eq!(plan.schema().field(0).name(), "Value");
    }
}

#[tokio::test]
async fn count_projection_updates() {
    let fixture = Fixture::new();
    let (plan, source) = fixture
        .physical(
            "SELECT count(*) + 1 AS \"MiXeD\", count(kernel_sequence) AS present FROM events",
            vec![],
        )
        .await;
    let source = source.unwrap();
    let initial = fixture.run(&plan, &source, vec![]).await;
    assert_eq!(values(&initial, 0), [ScalarValue::Int64(Some(1))]);
    assert_eq!(values(&initial, 1), [ScalarValue::Int64(Some(0))]);
    let inserted = fixture
        .run(
            &plan,
            &source,
            vec![fixture.batch(source.schema()).slice(0, 3)],
        )
        .await;
    assert_eq!(inserted[0].schema(), plan.schema());
    assert_eq!(inserted[0].schema().field(0).name(), "MiXeD");
    assert_eq!(inserted[0].schema().field(1).name(), "present");
    assert_eq!(values(&inserted, 0), [ScalarValue::Int64(Some(4))]);
    assert_eq!(values(&inserted, 1), [ScalarValue::Int64(Some(2))]);
    let removed = fixture.run(&plan, &source, vec![]).await;
    assert_eq!(removed, initial);
}

#[tokio::test]
async fn nested_projection_batches() {
    let fixture = Fixture::new();
    let (plan, source) = fixture
        .physical(
            "SELECT q.total + 2 AS \"Final\" FROM (SELECT count(*) AS total FROM events) q",
            vec![],
        )
        .await;
    let aggregate = aggregate(&plan);
    let native = fixture.run(&aggregate, &source.unwrap(), vec![]).await;
    let batches = fixture
        .run(
            &plan,
            &aggregate,
            vec![native[0].clone(), native[0].clone()],
        )
        .await;
    assert_eq!(values(&batches, 0), vec![ScalarValue::Int64(Some(2)); 2]);
    assert!(batches.iter().all(|batch| batch.schema() == plan.schema()));
    assert_eq!(plan.schema().field(0).name(), "Final");
    assert!(fixture.run(&plan, &aggregate, vec![]).await.is_empty());
}

#[tokio::test]
async fn aggregate_binding_keeps_arrays() {
    let fixture = Fixture::new();
    let (plan, source) = fixture
        .physical("SELECT count(*) FROM events", vec![])
        .await;
    let aggregate = aggregate(&plan);
    let native = fixture.run(&aggregate, &source.unwrap(), vec![]).await;
    let array = Arc::clone(native[0].column(0));
    let batches = fixture.run(&aggregate, &aggregate, native).await;
    assert!(Arc::ptr_eq(&array, batches[0].column(0)));
    assert_eq!(batches[0].schema(), aggregate.schema());
    assert_eq!(values(&batches, 0), [ScalarValue::Int64(Some(0))]);
}

#[tokio::test]
async fn binding_schema_is_exact() {
    let fixture = Fixture::new();
    let (plan, source) = fixture
        .physical("SELECT count(kernel_sequence) FROM events", vec![])
        .await;
    let source = source.unwrap();
    let aggregate = aggregate(&plan);
    let native = aggregate.as_any().downcast_ref::<AggregateExec>().unwrap();
    for schema in [
        Arc::new(Schema::new(vec![Field::new(
            "wrong",
            DataType::UInt64,
            true,
        )])),
        Arc::new(
            source
                .schema()
                .as_ref()
                .clone()
                .with_metadata(HashMap::from([("wrong".into(), "metadata".into())])),
        ),
    ] {
        let wrong = RecordBatch::new_empty(schema);
        assert!(matches!(
            SubscribeExec::bind(native.input(), &source, vec![wrong], fixture.state.task_ctx()),
            Err(DataFusionError::Execution(reason)) if reason == "physical input schema changed"
        ));
    }
    let wrong = RecordBatch::new_empty(Arc::new(Schema::new(vec![Field::new(
        "wrong",
        DataType::Int64,
        false,
    )])));
    assert!(matches!(
        SubscribeExec::bind(&plan, &aggregate, vec![wrong], fixture.state.task_ctx()),
        Err(DataFusionError::Execution(reason)) if reason == "physical input schema changed"
    ));
    let batches = fixture
        .run(
            native.input(),
            &source,
            vec![fixture.batch(source.schema())],
        )
        .await;
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 4);
}

#[tokio::test]
async fn unsupported_plans_stay_batch() {
    let fixture = Fixture::new();
    for sql in [
        "SELECT sum(kernel_sequence) FROM events",
        "SELECT count(DISTINCT kernel_sequence) FROM events",
        "SELECT operation_argument, count(*) FROM events GROUP BY operation_argument",
        "SELECT count(*) FROM events a JOIN events b ON a.source_cursor = b.source_cursor",
        "SELECT count(*) AS total FROM events HAVING count(*) > 0",
    ] {
        let plan = fixture.plan(sql, vec![]).await;
        assert!(
            fixture
                .engine
                .session(
                    AnalysisSelectionV1::tenant([1; 16]),
                    &AnalysisReadControl::with_timeout(Duration::from_secs(30)).unwrap(),
                    0,
                )
                .unwrap()
                .subscribe(
                    &plan,
                    &BTreeMap::from([("events".to_owned(), None)]),
                    crate::execution::Read::Snapshot,
                    Arc::new(fixture.engine.reserve_evaluation([1; 16]).unwrap())
                )
                .await
                .unwrap()
                .is_none(),
            "{sql}"
        );
    }
}
