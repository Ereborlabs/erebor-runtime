use araphor_analysis_sdk as sdk;
use datafusion::catalog::memory::MemoryCatalogProvider;

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn native_views_keep_defaults() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views("CREATE VIEW answer AS SELECT CAST(22 AS BIGINT) AS value")?;
    let (_plan, sources) = fixture
        .engine
        .prepare("SELECT * FROM answer", Vec::new())
        .await?;
    assert!(sources.is_empty());
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views("CREATE VIEW doubled AS SELECT value * 2 AS value FROM answer")?;
    let (plan, sources) = fixture
        .engine
        .prepare(
            "SELECT answer.value, doubled.value AS twice FROM answer CROSS JOIN doubled",
            Vec::new(),
        )
        .await?;
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let (_snapshot, batches) = session.execute(Arc::new(plan), &sources)?;
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    for (column, expected) in batches[0].columns().iter().zip([22, 44]) {
        assert_eq!(
            column
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or("Int64 view required")?
                .value(0),
            expected
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_views_capture_sources() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    let engine = Arc::get_mut(&mut fixture.engine).ok_or("shared engine")?;
    engine
        .state
        .catalog_list()
        .register_catalog("archive".into(), Arc::new(MemoryCatalogProvider::new()));
    engine.register_views(
        "CREATE VIEW derived.counts AS
             SELECT COUNT(*) AS records,
                 (SELECT COUNT(*) FROM coverage) AS reports FROM events;
         CREATE VIEW derived.empty_rows AS
             SELECT source_cursor FROM events WHERE FALSE;
         CREATE VIEW archive.derived.answer AS SELECT CAST(22 AS BIGINT) AS value;",
    )?;
    let (plan, sources) = fixture
        .engine
        .prepare(
            "WITH events AS (SELECT 99 AS source_cursor), coverage AS (SELECT 99 AS value)
             SELECT * FROM derived.counts",
            Vec::new(),
        )
        .await?;
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["coverage", "events"]
    );
    let session = fixture
        .engine
        .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let (_snapshot, batches) = session.execute(Arc::new(plan), &sources)?;
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    for column in batches[0].columns() {
        assert_eq!(
            column
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or("Int64 count required")?
                .value(0),
            0
        );
    }
    let (_plan, sources) = fixture
        .engine
        .prepare("SELECT * FROM derived.empty_rows", Vec::new())
        .await?;
    assert_eq!(
        sources.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["events"]
    );
    let (plan, sources) = fixture
        .engine
        .prepare("SELECT * FROM archive.derived.answer", Vec::new())
        .await?;
    assert!(sources.is_empty());
    let (_snapshot, batches) = session.execute(Arc::new(plan), &sources)?;
    assert_eq!(
        batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("Int64 answer required")?
            .value(0),
        22
    );

    let mut model = sdk::Model::new("counts", Vec::new(), Vec::new());
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![sdk::InputPort {
        port: sdk::Port::new(
            "counts",
            sdk::Schema::new(vec![
                sdk::Field::new("records", sdk::DataType::Int64, false),
                sdk::Field::new("reports", sdk::DataType::Int64, false),
            ]),
        ),
        source: sdk::InputSource::Query("SELECT * FROM derived.counts".into()),
    }];
    let inputs = Arc::new(crate::inputs::Inputs::admit(&fixture.engine, &model)?);
    let input = inputs.read(
        Arc::clone(&fixture.engine),
        AnalysisSelectionV1::tenant([1; 16]),
        "native-views".into(),
        &control(),
        1,
    )?;
    let snapshot = input.snapshot.as_ref().ok_or("input capture absent")?;
    assert!(snapshot.page.tables.is_empty());
    let revision = snapshot.page.extraction.meta.commit_revision;
    let revisions = input.source_revisions();
    for name in ["events", "coverage"] {
        assert!(
            revisions.contains(&(name.into(), revision)),
            "captured source revision absent: {name}; {revisions:?}"
        );
    }
    assert_eq!(input.inputs.len(), 1);
    assert_eq!(
        input.inputs[0]
            .data
            .batches
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    for column in input.inputs[0].data.batches[0].columns() {
        assert_eq!(
            column
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or("Int64 input count required")?
                .value(0),
            0
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_views_keep_clocks() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE VIEW \"TiMiNg\".\"MoMeNt\" AS SELECT CURRENT_TIMESTAMP AS moment;",
        )?;
    let (plan, sources) = fixture
        .engine
        .prepare(
            "SELECT arrow_cast(moment, 'Int64') AS value FROM \"TiMiNg\".\"MoMeNt\"",
            Vec::new(),
        )
        .await?;
    assert!(crate::inputs::Inputs::clocked(&plan)?);
    assert!(sources.is_empty());
    for now in [1_000_000_000, 2_000_000_000] {
        let session =
            fixture
                .engine
                .session(AnalysisSelectionV1::tenant([1; 16]), &control(), now)?;
        let (_snapshot, batches) = session.execute(Arc::new(plan.clone()), &sources)?;
        assert_eq!(
            batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or("Int64 clock required")?
                .value(0),
            i64::try_from(now)?
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_views_keep_limits() -> TestResult {
    let mut fixture = Fixture::new(Limits {
        projection_columns: Some(1),
        ..Limits::default()
    });
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE SCHEMA derived;
             CREATE VIEW derived.wide AS SELECT source_cursor, operation FROM events;",
        )?;
    let error = fixture
        .engine
        .prepare("SELECT source_cursor FROM derived.wide", Vec::new())
        .await
        .err()
        .ok_or("view projection quota ignored")?;
    assert!(
        matches!(&error, crate::Error::Sql {
            source: datafusion::common::DataFusionError::Plan(message),
        } if message == "SQL projection is too wide"),
        "unexpected view quota error: {error:?}"
    );
    for sql in [
        "SELECT 1",
        "CREATE SCHEMA unexpected; CREATE TABLE unexpected.values AS SELECT 1 AS value",
    ] {
        assert!(matches!(
            Arc::get_mut(&mut fixture.engine)
                .ok_or("shared engine")?
                .register_views(sql),
            Err(crate::Error::Invalid {
                field: "view registration statement",
                ..
            })
        ));
    }
    Ok(())
}
