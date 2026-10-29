use datafusion::catalog::memory::MemoryCatalogProvider;
use datafusion::datasource::view::ViewTable;
use datafusion::logical_expr::Extension;
use datafusion::physical_plan::empty::EmptyExec;

use super::*;
use crate::sources::{PortSource, SourceDependenciesExec, SourceOrigin, SourcePort};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug)]
struct PreparedView(Arc<dyn ExecutionPlan>);

impl PortSource for PreparedView {
    fn reusable(&self) -> bool {
        true
    }

    fn plan(
        &self,
        _: usize,
        inputs: &[Arc<dyn ExecutionPlan>],
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        assert!(inputs.is_empty());
        let port: Arc<dyn ExecutionPlan> = Arc::new(EmptyExec::new(self.0.schema()));
        Ok(Arc::new(SourceDependenciesExec::new(
            port,
            vec![Arc::clone(&self.0)],
        )))
    }
}

#[tokio::test]
async fn prepared_view_port_admits_and_captures_its_source() -> TestResult {
    let mut fixture = Fixture::new(Limits::default());
    Arc::get_mut(&mut fixture.engine)
        .ok_or("shared engine")?
        .register_views(
            "CREATE VIEW derived.empty_rows AS SELECT source_cursor FROM events WHERE FALSE",
        )?;
    let (view, _) = fixture
        .engine
        .prepare("SELECT source_cursor FROM derived.empty_rows", Vec::new())
        .await?;
    let mut session =
        fixture
            .engine
            .session(AnalysisSelectionV1::tenant([1; 16]), &control(), 1)?;
    let physical = session
        .prepare_reusable_inputs(std::slice::from_ref(&view))
        .await?
        .ok_or("view source must be reusable")?
        .pop()
        .ok_or("prepared view source")?;
    let port = SourcePort::prepared(
        "prepared_view".into(),
        Arc::clone(view.schema().inner()),
        &[view],
        Arc::new(PreparedView(physical)),
    )?;
    assert!(port
        .origins()
        .contains(&SourceOrigin::Durable("events".into())));
    session.register_table(
        "prepared_view",
        Arc::new(ViewTable::new(
            LogicalPlan::Extension(Extension {
                node: Arc::new(port),
            }),
            None,
        )),
    )?;
    let definition = araphor_discovery_definition::Definition {
        name: "prepared-view".into(),
        description: String::new(),
        labels: Default::default(),
        program: araphor_discovery_definition::Program::Sql {
            source: araphor_discovery_definition::Source::Inline {
                inline: "SELECT * FROM prepared_view".into(),
            },
        },
    };
    let prepared = session.prepare_definition(&definition).await?;
    assert_eq!(
        prepared
            .sources()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["events"]
    );
    let input = session
        .execute_definition(&prepared, crate::definition::Invocation::default())
        .await?;
    let revision = input.snapshot.page.extraction.meta.commit_revision;
    assert!(input
        .snapshot
        .selection
        .source_revisions(revision)
        .contains(&("events".into(), revision)));
    assert!(input.batches.iter().all(|batch| batch.num_rows() == 0));
    Ok(())
}

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

    {
        let definition = araphor_discovery_definition::Definition {
            name: "native-views".into(),
            description: "Capture native view input.".into(),
            labels: Default::default(),
            program: araphor_discovery_definition::Program::Sql {
                source: araphor_discovery_definition::Source::Inline {
                    inline: "SELECT * FROM derived.counts".into(),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let input = session
            .execute_definition(&prepared, crate::definition::Invocation::default())
            .await?;
        let snapshot = &input.snapshot;
        assert!(snapshot.page.tables.is_empty());
        let revision = snapshot.page.extraction.meta.commit_revision;
        let revisions = snapshot.selection.source_revisions(revision);
        for name in ["events", "coverage"] {
            assert!(
                revisions.contains(&(name.into(), revision)),
                "captured source revision absent: {name}; {revisions:?}"
            );
        }
        assert!(input.calls.is_empty());
        assert_eq!(
            input
                .batches
                .iter()
                .map(RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        assert_eq!(input.batches[0].num_columns(), 2);
        for (index, column) in input.batches[0].columns().iter().enumerate() {
            assert_eq!(
                input.batches[0].schema().field(index).name(),
                ["records", "reports"][index]
            );
            assert_eq!(column.null_count(), 0);
            assert_eq!(
                column
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or("Int64 input count required")?
                    .value(0),
                0
            );
        }
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
    assert!(crate::follow::Window::clocks(&plan)? > 0);
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
