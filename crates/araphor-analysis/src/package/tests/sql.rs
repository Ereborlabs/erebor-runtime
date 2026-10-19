#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use araphor_analysis_builtins::discovery::sql::{
    COVERAGE_RANGES_SQL, MERGE_SQL, OBSERVED_EFFECTS_SQL, RECORDED_SNAPSHOT_SQL, VIEWS_SQL,
};
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryArray, Int32Array, Int64Array, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::compute::concat_batches;
use datafusion::arrow::datatypes::{DataType, Schema};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::Result;
use datafusion::datasource::MemTable;
use datafusion::execution::config::SessionConfig;
use datafusion::execution::context::SessionContext;
use datafusion::logical_expr::LogicalPlan;

use crate::package::builtin::{query, LIVE_SQL};

mod coverage;
mod recorded;

const INPUTS: [&str; 18] = [
    "tenant_id",
    "node_id",
    "node_boot_id",
    "label_epoch",
    "source_id",
    "source_epoch",
    "cpu_id",
    "binding_id",
    "coverage_interval_id",
    "effect_family",
    "operation",
    "temporal_coverage",
    "exact_object_id",
    "destination_id",
    "decision",
    "kernel_result",
    "source_cursor",
    "received_at",
];

struct Fixture {
    context: SessionContext,
    schema: Arc<Schema>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let canonical = &araphor_data::AnalysisStore::table_schemas()["events"];
        let fields = INPUTS
            .iter()
            .map(|name| canonical.field_with_name(name).cloned())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            context: SessionContext::new_with_config(
                SessionConfig::new().with_target_partitions(1),
            ),
            schema: Arc::new(Schema::new(fields)),
        })
    }

    fn batch(&self, rows: &[(u8, Option<u8>, u32, u64, i64)]) -> Result<RecordBatch> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|_| [1u8; 16]),
            )),
            Arc::new(StringArray::from_iter_values(rows.iter().map(|_| "node"))),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|_| [2u8; 16]),
            )),
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|_| 1))),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|row| [row.0; 16]),
            )),
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|_| 1))),
            Arc::new(UInt32Array::from_iter_values(rows.iter().map(|_| 0))),
            Arc::new(BinaryArray::from_iter(
                rows.iter().map(|row| row.1.map(|binding| [binding; 16])),
            )),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|_| [3u8; 16]),
            )),
            Arc::new(UInt32Array::from_iter_values(rows.iter().map(|row| row.2))),
            Arc::new(UInt32Array::from_iter_values(rows.iter().map(|_| 7))),
            Arc::new(Int32Array::from_iter_values(rows.iter().map(|_| 1))),
            Arc::new(BinaryArray::from_iter_values(
                rows.iter().map(|_| [4u8; 16]),
            )),
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|_| 0))),
            Arc::new(UInt32Array::from_iter_values(rows.iter().map(|_| 1))),
            Arc::new(Int32Array::from_iter_values(rows.iter().map(|_| 0))),
            Arc::new(UInt64Array::from_iter_values(rows.iter().map(|row| row.3))),
            Arc::new(TimestampMicrosecondArray::from_iter_values(
                rows.iter().map(|row| row.4),
            )),
        ];
        Ok(RecordBatch::try_new(Arc::clone(&self.schema), columns)?)
    }

    fn replace(&self, partitions: Vec<Vec<RecordBatch>>) -> Result<()> {
        let _previous = self.context.deregister_table("events")?;
        self.context.register_table(
            "events",
            Arc::new(MemTable::try_new(Arc::clone(&self.schema), partitions)?),
        )?;
        Ok(())
    }

    async fn query(&self, input: &str) -> Result<RecordBatch> {
        let relation = if input == "SELECT * FROM events" {
            self.view("observed_effects", OBSERVED_EFFECTS_SQL).await?;
            "discovery.observed_effects".to_owned()
        } else {
            format!(
                "(WITH events AS ({input}) {})",
                query(OBSERVED_EFFECTS_SQL)?
            )
        };
        let sql = format!(
            "SELECT * FROM {relation} AS effects \
            ORDER BY source_id, binding_id NULLS FIRST, effect_family NULLS FIRST"
        );
        let dataframe = self.context.sql(&sql).await?;
        dataframe.logical_plan().apply(|plan| {
            assert!(!matches!(plan, LogicalPlan::Extension(_)));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let schema = Arc::new(dataframe.schema().as_arrow().clone());
        let physical = dataframe.create_physical_plan().await?;
        let mut aggregate = false;
        physical.apply(|plan| {
            assert!(!plan.name().contains("Observed") && !plan.name().contains("Package"));
            aggregate |= plan.name() == "AggregateExec";
            Ok(TreeNodeRecursion::Continue)
        })?;
        assert!(aggregate);
        let batches = datafusion::physical_plan::collect(physical, self.context.task_ctx()).await?;
        Ok(concat_batches(&schema, &batches)?)
    }

    async fn view(&self, name: &str, sql: &str) -> Result<()> {
        self.context
            .sql("CREATE SCHEMA IF NOT EXISTS discovery")
            .await?;
        self.context
            .sql(&format!(
                "CREATE OR REPLACE VIEW discovery.{name} AS {}",
                query(sql)?
            ))
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn native_aggregate_keeps_sources() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.replace(vec![vec![fixture.batch(&[
        (9, None, 2, 3, 30),
        (9, None, 2, 1, 10),
        (8, None, 2, 1, 15),
        (9, Some(5), 2, 2, 20),
    ])?]])?;
    let result = fixture.query("SELECT * FROM events").await?;
    assert_eq!(result.num_rows(), 3);
    assert_eq!(
        result.schema().field_with_name("event_count")?.data_type(),
        &DataType::Int64
    );
    let sources = result
        .column_by_name("source_id")
        .unwrap()
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap();
    let bindings = result
        .column_by_name("binding_id")
        .unwrap()
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap();
    let counts = result
        .column_by_name("event_count")
        .unwrap()
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    let first = result
        .column_by_name("first_cursor")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let last = result
        .column_by_name("last_cursor")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let start = result
        .column_by_name("first_received_at")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    let end = result
        .column_by_name("last_received_at")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
    assert_eq!(
        (sources.value(0), sources.value(1), sources.value(2)),
        (&[8u8; 16][..], &[9u8; 16][..], &[9u8; 16][..])
    );
    assert!(bindings.is_null(0) && bindings.is_null(1));
    assert_eq!(bindings.value(2), &[5u8; 16]);
    assert_eq!(counts.values().as_ref(), &[1, 2, 1]);
    assert_eq!(
        (first.value(1), last.value(1), start.value(1), end.value(1)),
        (1, 3, 10, 30)
    );
    Ok(())
}

#[tokio::test]
async fn batches_do_not_define_groups() -> Result<()> {
    let fixture = Fixture::new()?;
    let rows = [
        (9, None, 2, 3, 30),
        (9, None, 2, 1, 10),
        (8, None, 3, 1, 15),
    ];
    fixture.replace(vec![vec![fixture.batch(&rows)?]])?;
    let whole = fixture.query("SELECT * FROM events").await?;
    fixture.replace(vec![
        vec![fixture.batch(&rows[..1])?],
        vec![fixture.batch(&rows[1..])?],
    ])?;
    let split = fixture.query("SELECT * FROM events").await?;
    assert_eq!(whole, split);
    fixture.replace(vec![vec![fixture.batch(&rows[..1])?]])?;
    let fresh = fixture.query("SELECT * FROM events").await?;
    assert_eq!(fresh.num_rows(), 1);
    assert_eq!(
        fresh
            .column_by_name("event_count")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0),
        1
    );
    Ok(())
}

#[tokio::test]
async fn empty_and_null_effects() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.replace(vec![vec![fixture.batch(&[])?]])?;
    assert_eq!(fixture.query("SELECT * FROM events").await?.num_rows(), 0);
    fixture.replace(vec![vec![fixture.batch(&[(9, None, 2, 1, 10)])?]])?;
    let nulls = fixture
        .query("SELECT * REPLACE (CAST(NULL AS INT UNSIGNED) AS effect_family) FROM events")
        .await?;
    assert_eq!(nulls.num_rows(), 1);
    assert_eq!(
        nulls.column_by_name("effect_family").unwrap().null_count(),
        1
    );
    assert_eq!(nulls.column_by_name("binding_id").unwrap().null_count(), 1);
    Ok(())
}

#[tokio::test]
async fn sql_filters_before_aggregation() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.replace(vec![vec![fixture.batch(&[
        (9, None, 2, 3, 30),
        (9, None, 2, 1, 10),
        (9, None, 2, 2, 20),
    ])?]])?;
    for input in [
        "SELECT * FROM events WHERE source_cursor <= 2",
        "SELECT * EXCLUDE (position) FROM (SELECT *, ROW_NUMBER() OVER \
            (PARTITION BY source_id ORDER BY source_cursor) AS position FROM events) \
            WHERE position <= 2",
    ] {
        let result = fixture.query(input).await?;
        assert_eq!(result.num_rows(), 1);
        assert_eq!(
            result
                .column_by_name("event_count")
                .unwrap()
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap()
                .value(0),
            2
        );
        assert_eq!(
            result
                .column_by_name("last_cursor")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .value(0),
            2
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_cte_scope_and_admission() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.replace(vec![vec![fixture.batch(&[(9, None, 2, 1, 10)])?]])?;
    fixture
        .view("observed_effects", OBSERVED_EFFECTS_SQL)
        .await?;
    let sql = "WITH records AS (SELECT 42 AS unused), events AS (SELECT 42 AS unused) \
        SELECT result.event_count FROM discovery.observed_effects AS result";
    assert_eq!(
        fixture.context.sql(sql).await?.collect().await?[0].num_rows(),
        1
    );
    let provider = fixture
        .context
        .table_provider("discovery.observed_effects")
        .await?;
    assert!(provider
        .as_any()
        .is::<datafusion::datasource::view::ViewTable>());
    let ordinary = fixture
        .context
        .sql("SELECT COUNT(*) FROM events")
        .await?
        .collect()
        .await?;
    assert_eq!(
        ordinary[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0),
        1
    );
    assert!(fixture
        .context
        .sql("SELECT * FROM discovery.observed_effects((SELECT * FROM events))")
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn catalog_views_use_providers() -> Result<()> {
    let context = SessionContext::new();
    for (name, schema) in araphor_data::AnalysisStore::table_schemas() {
        let schema = Arc::clone(schema);
        context.register_table(
            name.as_str(),
            Arc::new(MemTable::try_new(
                Arc::clone(&schema),
                vec![vec![RecordBatch::new_empty(schema)]],
            )?),
        )?;
    }
    context.sql("CREATE SCHEMA discovery").await?;
    let statements = datafusion::sql::parser::DFParserBuilder::new(VIEWS_SQL)
        .with_recursion_limit(usize::MAX)
        .build()?
        .parse_statements()?;
    for statement in statements {
        let plan = context.state().statement_to_plan(statement).await?;
        context.execute_logical_plan(plan).await?;
    }
    for name in ["observed_effects", "coverage_ranges", "context_bindings"] {
        let name = format!("discovery.{name}");
        let provider = context.table_provider(name.as_str()).await?;
        assert!(provider
            .as_any()
            .is::<datafusion::datasource::view::ViewTable>());
        assert!(context
            .sql(&format!("SELECT * FROM {name}"))
            .await?
            .collect()
            .await?
            .iter()
            .all(|batch| batch.num_rows() == 0));
    }
    Ok(())
}
