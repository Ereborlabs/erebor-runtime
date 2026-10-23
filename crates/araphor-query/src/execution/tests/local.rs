use araphor_analysis_sdk as sdk;
use datafusion::arrow::array::UInt64Array;
use datafusion::catalog::memory::MemoryCatalogProvider;

use super::*;
use erebor_runtime_error::{RetryHint, StatusCode};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn dataset() -> sdk::Result<sdk::Dataset> {
    let schema = Arc::new(Schema::new_with_metadata(
        vec![Field::new("value", DataType::Int64, false)],
        std::collections::HashMap::from([("contract".into(), "retained".into())]),
    ));
    Ok(sdk::Dataset {
        name: "Rows".into(),
        batches: [vec![11, 22], vec![33, 44]]
            .into_iter()
            .map(|values| {
                RecordBatch::try_new(
                    Arc::clone(&schema),
                    vec![Arc::new(Int64Array::from(values))],
                )
                .map_err(sdk::Error::from)
            })
            .collect::<sdk::Result<_>>()?,
    })
}

#[tokio::test]
async fn local_query_keeps_indices() -> TestResult {
    let fixture = Fixture::new(Limits::default());
    let before = fixture.engine.store().meta()?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let data = dataset()?;
    let output = session
        .query_local(
            std::slice::from_ref(&data),
            "WITH selected AS (SELECT * FROM \"Rows\")
         SELECT value, __row_index FROM selected WHERE value > 20 ORDER BY value DESC",
        )
        .await?;
    let values: Vec<_> = output
        .data
        .batches
        .iter()
        .flat_map(|batch| {
            let value = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap();
            let index = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            (0..batch.num_rows())
                .map(|row| (value.value(row), index.value(row)))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(values, vec![(44, 3), (33, 2), (22, 1)]);
    assert_eq!(fixture.engine.store().meta()?, before);
    for table in ["\"Rows\"", "public.\"Rows\"", "datafusion.public.\"Rows\""] {
        assert_eq!(
            session
                .query_local(
                    std::slice::from_ref(&data),
                    &format!("SELECT * FROM {table}"),
                )
                .await?
                .data
                .rows(),
            4
        );
    }
    let schema = data.batches[0].schema();
    let empty = session
        .query_local(&[data], "SELECT value FROM \"Rows\" WHERE false")
        .await?;
    assert_eq!(empty.data.rows(), 0);
    assert_eq!(empty.data.batches.len(), 1);
    assert_eq!(empty.data.batches[0].schema_ref().field(0).name(), "value");
    assert!(empty.data.batches[0].column(0).as_any().is::<Int64Array>());
    assert_eq!(
        empty.data.batches[0].schema_ref().metadata(),
        schema.metadata()
    );
    let interval = session
        .query_local(&[], "SELECT INTERVAL '1 day' AS duration")
        .await?;
    assert!(matches!(
        interval.data.batches[0].schema_ref().field(0).data_type(),
        DataType::Interval(_)
    ));
    Ok(())
}

#[tokio::test]
async fn local_query_closes_catalog() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    let engine = Arc::get_mut(&mut fixture.engine).ok_or("shared engine")?;
    engine
        .state
        .catalog_list()
        .register_catalog("archive".into(), Arc::new(MemoryCatalogProvider::new()));
    engine.register_views(
        "CREATE VIEW inherited AS SELECT 99 AS value;
        CREATE VIEW archive.private.hidden AS SELECT 99 AS value;
        CREATE VIEW private.hidden AS SELECT 99 AS value;",
    )?;
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let data = dataset()?;
    session.register("undeclared", data.batches[0].schema(), &data.batches)?;
    for table in [
        "events",
        "datafusion.public.catalog",
        "inherited",
        "private.hidden",
        "archive.private.hidden",
        "undeclared",
    ] {
        for sql in [
            format!("SELECT * FROM {table}"),
            format!("WITH unused AS (SELECT * FROM {table}) SELECT 1"),
        ] {
            let error = session
                .query_local(std::slice::from_ref(&data), &sql)
                .await
                .err()
                .ok_or_else(|| format!("accepted: {sql}"))?;
            assert_eq!(
                error.status_code(),
                StatusCode::InvalidArguments,
                "{sql}: {error:?}"
            );
            assert_eq!(
                error.retry_hint(),
                RetryHint::NonRetryable,
                "{sql}: {error:?}"
            );
        }
    }
    for sql in [
        "CREATE TABLE bad AS SELECT 1",
        "INSERT INTO \"Rows\" VALUES (99)",
        "DELETE FROM \"Rows\"",
        "SELECT 1; SELECT 2",
    ] {
        assert!(
            session
                .query_local(std::slice::from_ref(&data), sql)
                .await
                .is_err(),
            "accepted: {sql}"
        );
    }
    assert_eq!(
        session
            .query_local(&[], "SELECT 1 AS value")
            .await?
            .data
            .rows(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn local_query_releases_capacity() -> TestResult {
    let capacity = 64 * 1024;
    let fixture = Fixture::new(Limits {
        input_capacity: Some(capacity),
        output_capacity: Some(capacity),
        global_evaluations: Some(1),
        ..Limits::default()
    });
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let data = dataset()?;
    session.set_output(1, usize::MAX)?;
    assert!(session
        .query_local(std::slice::from_ref(&data), "SELECT * FROM \"Rows\"",)
        .await
        .is_err());
    for (sql, rows, bytes) in [
        ("VALUES (1), (2)", 1, usize::MAX),
        ("SELECT repeat('x', 4096)", usize::MAX, 32),
    ] {
        session.set_output(rows, bytes)?;
        let error = session
            .query_local(&[], sql)
            .await
            .err()
            .ok_or("output limit ignored")?;
        assert!(
            matches!(
                error,
                Error::Sql {
                    source: datafusion::common::DataFusionError::ResourcesExhausted(_),
                    ..
                }
            ),
            "{error:?}"
        );
    }
    let cancelled = control();
    let stopped = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &cancelled, 1)?;
    cancelled.cancel()?;
    assert!(stopped
        .query_local(std::slice::from_ref(&data), "SELECT 1",)
        .await
        .is_err());
    drop(session);
    drop(stopped);
    drop(data);
    drop(fixture.engine.reserve_evaluation([1; 16])?);
    drop(fixture.engine.memory().reserve_input(capacity)?);
    drop(fixture.engine.memory().reserve_output(capacity)?);
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let data = dataset()?;
    let output = session
        .query_local(&[data], "SELECT * FROM \"Rows\"")
        .await?;
    let alias = output.data.batches[0].column(0).slice(0, 1);
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    drop(output);
    assert!(fixture.engine.memory().reserve_output(capacity).is_err());
    assert_eq!(
        alias
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("output type")?
            .value(0),
        11
    );
    drop(alias);
    drop(fixture.engine.memory().reserve_input(capacity)?);
    drop(fixture.engine.memory().reserve_output(capacity)?);
    Ok(())
}

#[tokio::test]
async fn local_sql_controls_rows() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .state
        .config_mut()
        .options_mut()
        .execution
        .batch_size = 1;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let selected = session
        .query_local(&[], "SELECT * FROM (VALUES (1), (2), (3)) LIMIT 1")
        .await?;
    assert_eq!(selected.data.rows(), 1);
    let output = session.query_local(&[], "VALUES (1), (2), (3)").await?;
    assert_eq!(output.data.rows(), 3);
    assert!(output.data.batches.len() > 1);
    Ok(())
}
