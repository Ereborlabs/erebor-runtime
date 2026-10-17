use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use araphor_data::AnalysisStore;
use datafusion::arrow::array::{
    ArrayRef, Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::catalog::default_table_source::source_as_provider;
use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::ScalarValue;
use datafusion::dataframe::DataFrame;
use datafusion::datasource::MemTable;
use datafusion::execution::SessionState;
use datafusion::logical_expr::LogicalPlan;
use datafusion::sql::parser::Statement;

use crate::execution::{Engine, Limits};
use crate::parser::Parser;
use crate::planner::Planner;
use crate::{Error, Result};

fn catalog() -> SessionState {
    let operation = Field::new("operation", DataType::Utf8, false).with_metadata(HashMap::from([
        ("araphor.owner".into(), "events".into()),
        ("araphor.description".into(), "Recorded operation".into()),
    ]));
    let schema = Arc::new(Schema::new(vec![
        Field::new("pid", DataType::UInt32, false),
        operation,
        Field::new("source_cursor", DataType::UInt64, false),
        Field::new("MiXeD", DataType::Int64, false),
        Field::new("__row_index", DataType::UInt64, false),
    ]));
    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt32Array::from(vec![7])),
        Arc::new(StringArray::from(vec!["open"])),
        Arc::new(UInt64Array::from(vec![19])),
        Arc::new(Int64Array::from(vec![3])),
        Arc::new(UInt64Array::from(vec![11])),
    ];
    let batch = RecordBatch::try_new(Arc::clone(&schema), columns).unwrap();
    let events: Arc<dyn TableProvider> =
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());
    let schema = Arc::new(Schema::new(vec![
        Field::new("first_cursor", DataType::UInt64, false),
        Field::new("state", DataType::Utf8, false),
    ]));
    let coverage: Arc<dyn TableProvider> = Arc::new(
        MemTable::try_new(
            Arc::clone(&schema),
            vec![vec![RecordBatch::new_empty(schema)]],
        )
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
    let engine = Engine::new(store, Limits::default()).unwrap();
    engine
        .catalog(BTreeMap::from([
            ("events".into(), Arc::clone(&events)),
            ("coverage".into(), coverage),
            ("CaseTable".into(), Arc::clone(&events)),
            ("__araphor_private".into(), events),
        ]))
        .unwrap()
}

async fn plan(
    state: &SessionState,
    sql: &str,
    parameters: Vec<ScalarValue>,
) -> Result<LogicalPlan> {
    Planner::new(state)
        .build(Parser::parse(sql)?, parameters)
        .await
}

#[test]
fn parser_returns_native_statements() {
    assert!(matches!(
        Parser::parse("SELECT 1;").unwrap(),
        Statement::Statement(_)
    ));
    assert!(Parser::parse("CREATE TABLE local_table (value BIGINT)").is_ok());
    for sql in ["", ";", "SELECT (", "SELECT 1; SELECT 2"] {
        assert!(Parser::parse(sql).is_err(), "{sql}");
    }
    assert!(matches!(
        Parser::parse(&"x".repeat(Parser::SQL_BYTES + 1)),
        Err(Error::Invalid {
            field: "SQL size",
            ..
        })
    ));
    let depth = Parser::RECURSION_LIMIT + 1;
    let sql = format!("SELECT {}1{}", "(".repeat(depth), ")".repeat(depth));
    assert!(Parser::parse(&sql).is_err());
}

#[tokio::test]
async fn unused_ctes_record_providers() {
    let catalog = catalog();
    let statement = Parser::parse(
        "WITH ignored AS (SELECT state FROM coverage) SELECT operation FROM events WHERE false",
    )
    .unwrap();
    let sources = catalog.resolve_table_references(&statement).unwrap();
    assert_eq!(
        sources.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["coverage", "events"]
    );
    let options = &catalog.config_options().catalog;
    let schema = catalog
        .catalog_list()
        .catalog(&options.default_catalog)
        .unwrap()
        .schema(&options.default_schema)
        .unwrap();
    let events = schema.table("events").await.unwrap().unwrap();
    let coverage = schema.table("coverage").await.unwrap().unwrap();
    let plan = Planner::new(&catalog)
        .build(statement, vec![])
        .await
        .unwrap();
    let mut scans = Vec::new();
    plan.apply_with_subqueries(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            scans.push(scan.table_name.table().to_owned());
            let provider = source_as_provider(&scan.source)?;
            assert!(Arc::ptr_eq(&provider, &events));
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .unwrap();
    assert_eq!(scans, ["events"]);
    assert_eq!(coverage.schema().field(0).name(), "first_cursor");
    let scan = events.as_any().downcast_ref::<MemTable>().unwrap();
    assert_eq!(scan.schema().field(4).name(), "__row_index");
}

#[tokio::test]
async fn native_ctes_scope_catalog() {
    for (sql, expected) in [
        (
            "WITH events AS (SELECT state FROM coverage) SELECT state FROM events",
            vec!["coverage"],
        ),
        (
            "WITH events AS (SELECT operation FROM events) SELECT operation FROM events",
            vec!["events"],
        ),
        (
            "WITH first AS (SELECT state FROM coverage), second AS (SELECT state FROM first) SELECT state FROM second",
            vec!["coverage"],
        ),
    ] {
        let catalog = catalog();
        let statement = Parser::parse(sql).unwrap();
        let sources = catalog.resolve_table_references(&statement).unwrap();
        Planner::new(&catalog)
            .build(statement, vec![])
            .await
            .unwrap();
        assert_eq!(
            sources.iter().map(ToString::to_string).collect::<Vec<_>>(),
            expected,
            "{sql}"
        );
    }
    let catalog = catalog();
    assert!(plan(&catalog,
        "WITH first AS (SELECT operation FROM later), later AS (SELECT operation FROM events) SELECT operation FROM first",
        vec![],
    ).await.is_err());
}

#[tokio::test]
async fn catalog_closes_sources_functions() {
    for sql in [
        "SELECT * FROM missing_source",
        "WITH ignored AS (SELECT * FROM missing_source) SELECT 1",
        "SELECT * FROM other.events",
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM __araphor_missing",
        "SELECT * FROM read_csv('/tmp/not-a-query-source')",
        "WITH ignored AS (SELECT * FROM read_csv('/tmp/not-a-query-source')) SELECT 1",
        "SELECT current_user",
    ] {
        assert!(plan(&catalog(), sql, vec![]).await.is_err(), "{sql}");
    }
    let catalog = catalog();
    plan(
        &catalog,
        "WITH ignored AS (SELECT current_timestamp) SELECT lower(operation) FROM events",
        vec![],
    )
    .await
    .unwrap();
    for sql in [
        "SELECT * FROM __araphor_private",
        "SELECT * FROM public.events",
        "SELECT * FROM datafusion.public.events",
    ] {
        let output = plan(&catalog, sql, vec![]).await.unwrap();
        assert_eq!(output.schema().field(0).data_type(), &DataType::UInt32);
        let batches = DataFrame::new(catalog.clone(), output)
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        let pid = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt32Array>()
            .unwrap();
        assert_eq!(pid.value(0), 7);
    }
    for (sql, name) in [
        (
            "SELECT operation AS __araphor_private FROM events",
            "__araphor_private",
        ),
        (
            "SELECT operation AS \"__ARAPHOR_private\" FROM events",
            "__ARAPHOR_private",
        ),
    ] {
        let output = plan(&catalog, sql, vec![]).await.unwrap();
        assert_eq!(output.schema().field(0).name(), name);
        assert_eq!(output.schema().field(0).data_type(), &DataType::Utf8);
    }
    let length = plan(
        &catalog,
        "SELECT length(operation) AS text_length FROM events",
        vec![],
    )
    .await
    .unwrap();
    let batches = DataFrame::new(catalog.clone(), length)
        .collect()
        .await
        .unwrap();
    assert_eq!(
        ScalarValue::try_from_array(batches[0].column(0), 0).unwrap(),
        ScalarValue::Int32(Some(4))
    );
    assert!(catalog.scalar_functions().contains_key("lower"));
    assert!(catalog.scalar_functions().contains_key("random"));
}

#[tokio::test]
async fn unused_windows_skip_resolution() {
    let catalog = catalog();
    plan(
        &catalog,
        "SELECT operation FROM events WINDOW ignored AS (ORDER BY random())",
        vec![],
    )
    .await
    .unwrap();
    assert!(catalog.scalar_functions().contains_key("random"));
    let statement =
        Parser::parse("SELECT operation FROM events WINDOW ignored AS (ORDER BY random())")
            .unwrap();
    assert_eq!(
        catalog
            .resolve_table_references(&statement)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["events"]
    );
}

#[tokio::test]
async fn native_parameters_bind_once() {
    let catalog = catalog();
    let output = plan(
        &catalog,
        "SELECT $1 AS value, $1 AS repeated, $2 AS text",
        vec![
            ScalarValue::UInt64(Some(9)),
            ScalarValue::Utf8(Some("hello".into())),
        ],
    )
    .await
    .unwrap();
    assert!(output.get_parameter_names().unwrap().is_empty());
    assert_eq!(output.schema().field(0).data_type(), &DataType::UInt64);
    assert_eq!(output.schema().field(1).data_type(), &DataType::UInt64);
    assert_eq!(output.schema().field(2).data_type(), &DataType::Utf8);
    assert_eq!(output.schema().field(0).name(), "value");
    for (sql, parameters) in [
        ("SELECT $0", vec![ScalarValue::Int64(Some(1))]),
        ("SELECT $1", vec![]),
        ("SELECT $2", vec![ScalarValue::Int64(Some(1))]),
        ("SELECT ?", vec![ScalarValue::Int64(Some(1))]),
        ("SELECT $named", vec![ScalarValue::Int64(Some(1))]),
    ] {
        assert!(plan(&catalog, sql, parameters).await.is_err(), "{sql}");
    }
    assert!(
        plan(&catalog, "SELECT 1", vec![ScalarValue::Int64(Some(2))])
            .await
            .is_ok()
    );
    assert!(plan(
        &catalog,
        "WITH ignored AS (SELECT $2) SELECT $1",
        vec![ScalarValue::UInt64(Some(9))],
    )
    .await
    .is_ok());
    assert!(
        plan(&catalog, "SELECT '?' AS question, '$1' AS literal", vec![])
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn star_exposes_row_index() {
    let catalog = catalog();
    for sql in ["SELECT * FROM events", "SELECT e.* FROM events AS e"] {
        let plan = plan(&catalog, sql, vec![]).await.unwrap();
        assert_eq!(
            plan.schema()
                .fields()
                .iter()
                .map(|field| field.name().as_str())
                .collect::<Vec<_>>(),
            ["pid", "operation", "source_cursor", "MiXeD", "__row_index"]
        );
        let batches = DataFrame::new(catalog.clone(), plan)
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        let index = batches[0].schema().index_of("__row_index").unwrap();
        let values = batches[0]
            .column(index)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap();
        assert_eq!(values.value(0), 11);
    }
}

#[tokio::test]
async fn native_case_types_metadata() {
    let catalog = catalog();
    let output = plan(
        &catalog,
        "SELECT operation AS \"OpLabel\", \"MiXeD\" AS \"CaseLabel\" FROM \"CaseTable\"",
        vec![],
    )
    .await
    .unwrap();
    assert_eq!(output.schema().field(0).name(), "OpLabel");
    assert_eq!(output.schema().field(1).name(), "CaseLabel");
    assert_eq!(
        output.schema().field(0).metadata()["araphor.owner"],
        "events"
    );
    assert_eq!(
        output.schema().field(0).metadata()["araphor.description"],
        "Recorded operation"
    );
    for sql in [
        "SELECT operation FROM CaseTable",
        "SELECT operation FROM \"EVENTS\"",
        "SELECT mixed FROM events",
        "SELECT \"mixed\" FROM events",
    ] {
        assert!(plan(&catalog, sql, vec![]).await.is_err(), "{sql}");
    }
    let output = plan(&catalog,
        "SELECT 1 AS integer_value, CAST(1 AS BIGINT UNSIGNED) AS unsigned_value, 0.25 AS fraction, NULL AS null_value, CAST('native' AS VARCHAR) AS text_value",
        vec![],
    ).await.unwrap();
    assert_eq!(output.schema().field(0).data_type(), &DataType::Int64);
    assert_eq!(output.schema().field(1).data_type(), &DataType::UInt64);
    assert_eq!(output.schema().field(2).data_type(), &DataType::Float64);
    assert_eq!(output.schema().field(3).data_type(), &DataType::Null);
    assert_eq!(output.schema().field(4).data_type(), &DataType::Utf8View);
}

#[tokio::test]
async fn planning_denies_writes_redacts() {
    for sql in [
        "CREATE TABLE local_table (value BIGINT)",
        "CREATE TABLE copied AS SELECT * FROM events",
        "DROP TABLE events",
        "DELETE FROM events",
        "SELECT operation INTO copied FROM events",
        "EXPLAIN SELECT operation FROM events",
        "COPY (SELECT operation FROM events) TO '/tmp/not-a-query-output'",
    ] {
        let statement = Parser::parse(sql).unwrap();
        assert!(
            Planner::new(&catalog())
                .build(statement, vec![])
                .await
                .is_err(),
            "{sql}"
        );
    }
    for sql in [
        "SELECT missing_field FROM events",
        "WITH ignored AS (SELECT missing_field FROM events) SELECT 1",
    ] {
        let error = plan(&catalog(), sql, vec![]).await.unwrap_err();
        let Error::Sql { source, .. } = &error else {
            panic!("expected structured native error: {error:?}");
        };
        assert!(source.to_string().contains("missing_field"));
        let display = error.to_string();
        assert!(!display.contains("missing_field"));
        assert!(!display.contains("__araphor_"));
        assert!(!display.contains(sql));
    }
}

#[tokio::test]
async fn native_joins_require_keys() {
    for sql in [
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor = c.first_cursor",
        "SELECT e.operation FROM events e JOIN coverage c ON (e.source_cursor) = c.first_cursor",
        "SELECT e.operation FROM events e JOIN coverage c ON source_cursor = c.first_cursor",
        "SELECT e.operation FROM events e LEFT JOIN coverage c ON e.source_cursor = c.first_cursor",
    ] {
        plan(&catalog(), sql, vec![]).await.unwrap();
    }
    for sql in [
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor = e.source_cursor",
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor + 1 = c.first_cursor",
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor = c.first_cursor AND c.first_cursor = c.first_cursor",
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor = e.source_cursor WHERE false LIMIT 0",
        "SELECT e.operation FROM events e JOIN coverage c ON e.source_cursor = c.first_cursor JOIN coverage d ON e.source_cursor = c.first_cursor",
        "SELECT e.operation FROM events e CROSS JOIN coverage c",
    ] {
        assert!(plan(&catalog(), sql, vec![]).await.is_err(), "{sql}");
    }
}

#[tokio::test]
async fn native_windows_require_bounds() {
    for sql in [
        "SELECT lag(source_cursor, 200) OVER (ORDER BY source_cursor) FROM events",
        "SELECT sum(pid) OVER (ORDER BY source_cursor ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM events",
        "SELECT sum(pid) OVER bounded FROM events WINDOW bounded AS (ORDER BY source_cursor ROWS 2 PRECEDING)",
    ] {
        plan(&catalog(), sql, vec![]).await.unwrap();
    }
    plan(
        &catalog(),
        "SELECT lead(source_cursor, $1) OVER (ORDER BY source_cursor) FROM events",
        vec![ScalarValue::UInt32(Some(2))],
    )
    .await
    .unwrap();
    for sql in [
        "SELECT lag(source_cursor, 201) OVER (ORDER BY source_cursor) FROM events",
        "SELECT lead(source_cursor, -1) OVER (ORDER BY source_cursor) FROM events",
        "SELECT lag(source_cursor) OVER () FROM events",
        "SELECT sum(pid) OVER (ORDER BY source_cursor) FROM events",
        "SELECT sum(pid) OVER unbounded FROM events WINDOW unbounded AS (ORDER BY source_cursor)",
        "SELECT sum(pid) OVER (ORDER BY source_cursor ROWS UNBOUNDED PRECEDING) FROM events",
        "SELECT sum(pid) OVER (ORDER BY source_cursor ROWS 201 PRECEDING) FROM events",
        "SELECT sum(pid) OVER (ORDER BY source_cursor RANGE 2 PRECEDING) FROM events",
    ] {
        assert!(plan(&catalog(), sql, vec![]).await.is_err(), "{sql}");
    }
}

#[tokio::test]
async fn planning_enforces_resource_limits() {
    for parameters in [
        vec![ScalarValue::Int64(Some(1)); Planner::PARAMETER_COUNT + 1],
        vec![ScalarValue::Utf8(Some(
            "x".repeat(Planner::PARAMETER_BYTES),
        ))],
        vec![ScalarValue::Float64(Some(f64::NAN))],
        vec![ScalarValue::Float64(Some(f64::INFINITY))],
    ] {
        assert!(matches!(
            plan(&catalog(), "SELECT $1", parameters).await,
            Err(Error::Invalid {
                field: "SQL parameters",
                ..
            })
        ));
    }
    let sql = (0..257)
        .map(|index| format!("1 AS column_{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(plan(&catalog(), &format!("SELECT {sql}"), vec![])
        .await
        .is_err());
    let schema = Arc::new(Schema::new(
        (0..257)
            .map(|index| Field::new(format!("column_{index}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    ));
    let table: Arc<dyn TableProvider> = Arc::new(
        MemTable::try_new(
            Arc::clone(&schema),
            vec![vec![RecordBatch::new_empty(schema)]],
        )
        .unwrap(),
    );
    let catalog = catalog();
    let options = &catalog.config_options().catalog;
    catalog
        .catalog_list()
        .catalog(&options.default_catalog)
        .unwrap()
        .schema(&options.default_schema)
        .unwrap()
        .register_table("wide".into(), table)
        .unwrap();
    assert!(plan(&catalog, "SELECT * FROM wide", vec![]).await.is_err());
    assert!(plan(&catalog, "SELECT column_0 FROM wide", vec![])
        .await
        .is_ok());
    assert!(plan(
        &catalog,
        "WITH ignored AS (SELECT * FROM wide) SELECT 1",
        vec![]
    )
    .await
    .is_ok());
    let statement = Parser::parse("WITH ignored AS (SELECT * FROM wide) SELECT 1").unwrap();
    assert_eq!(
        catalog
            .resolve_table_references(&statement)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["wide"]
    );
}

#[tokio::test]
async fn native_functions_are_available() {
    let catalog = catalog();
    for sql in [
        "SELECT sqrt(9.0)",
        "SELECT stddev_pop(pid) FROM events",
        "SELECT first_value(operation) OVER (ORDER BY pid) FROM events",
        "SELECT random()",
        "SELECT * FROM generate_series(1, 2)",
        "SELECT * FROM range(2)",
        "WITH ignored AS (SELECT random()) SELECT 1",
        "WITH ignored AS (SELECT * FROM generate_series(1, 2)) SELECT 1",
    ] {
        let logical = plan(&catalog, sql, vec![]).await.unwrap();
        let rows = DataFrame::new(catalog.clone(), logical)
            .collect()
            .await
            .unwrap();
        assert!(!rows.is_empty(), "{sql}");
    }
}
