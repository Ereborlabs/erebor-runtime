use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisReadControl, AnalysisStore};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
    SqlReasonV1,
};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::{LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::physical_plan::collect;

use super::{PackageCall, PreparedDefinition};
use crate::execution::{Engine, Limits};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        Ok(Self {
            engine: Engine::new(store, Limits::default())?,
            _directory: directory,
        })
    }

    fn installed(bundle: &PackageBundleV1) -> TestResult<Self> {
        let fixture = Self::new()?;
        fixture.install(bundle)?;
        Ok(fixture)
    }

    fn install(&self, bundle: &PackageBundleV1) -> TestResult {
        self.engine
            .store()
            .install_package_image([1; 16], bundle, || Ok(()))?;
        Ok(())
    }

    async fn prepare(&self, definition: &Definition) -> crate::Result<PreparedDefinition> {
        self.engine
            .prepare_definition(
                [1; 16],
                definition,
                Arc::new(AnalysisReadControl::default()),
            )
            .await
    }

    fn schema(name: &str) -> sdk::Schema {
        sdk::Schema::new(vec![sdk::Field::new(name, sdk::DataType::UInt64, false)])
    }

    fn bundle() -> PackageBundleV1 {
        let mut model = sdk::Model::new(
            "count",
            vec![sdk::Port::new("source", Self::schema("value"))],
            vec![sdk::Port::new("result", Self::schema("value"))],
        );
        model.parameters = Self::schema("increment");
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 2,
            datasets: vec![sdk::Port::new("state", Self::schema("total"))],
        });
        model.reasons.push(sdk::Reason {
            code: "fixture.note".into(),
            details: Self::schema("value"),
        });
        PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 { package_id: "fixture".into(), revision: "r1".into() },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("fixture", "r1", vec![model]),
                implementations: vec![PackageImplementationV1::Sql {
                    export: "count".into(),
                    program: SqlModelV1 {
                        outputs: BTreeMap::from([("result".into(), "SELECT source.value + parameters.increment AS value FROM source CROSS JOIN parameters".into())]),
                        checkpoint: BTreeMap::from([("state".into(), "SELECT value AS total FROM output_result".into())]),
                        evidence: Some("SELECT 'result' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source".into()),
                        reasons: vec![SqlReasonV1 { output: "result".into(), code: "fixture.note".into(), sql: "SELECT CAST(0 AS BIGINT UNSIGNED) AS output_row, value FROM output_result".into() }],
                    },
                }],
                fixtures: Vec::new(),
            }],
        }
    }

    fn definition() -> Definition {
        Definition {
            name: "count-events".into(),
            description: "Count selected events.".into(),
            labels: BTreeMap::from([("team".into(), "security".into())]),
            program: Program::Sql {
                source: Source::Inline {
                    inline: r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE source_cursor >= CAST(1 AS BIGINT UNSIGNED)), increment => 2)"#.into(),
                },
            },
        }
    }

    fn sql(inline: impl Into<String>) -> Definition {
        let mut definition = Self::definition();
        definition.program = Program::Sql {
            source: Source::Inline {
                inline: inline.into(),
            },
        };
        definition
    }

    fn calls(plan: &LogicalPlan) -> datafusion::common::Result<Vec<PackageCall>> {
        let mut calls = Vec::new();
        plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = plan {
                if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    calls.push(call.clone());
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(calls)
    }
}

#[tokio::test]
async fn native_package_call_contract() -> TestResult {
    let bundle = Fixture::bundle();
    let fixture = Fixture::installed(&bundle)?;
    let definition = Fixture::definition();
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(prepared.resolved.definition, definition);
    assert_eq!(prepared.resolved.sql, definition.program.sql()?);
    assert_eq!(prepared.resolved.images.len(), 1);
    assert_eq!(prepared.resolved.images[0].image, bundle.root);
    assert_eq!(prepared.resolved.images[0].digest, bundle.digest()?);
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.image(), &prepared.resolved.images[0]);
    assert_eq!(call.package(), &bundle.root);
    assert_eq!(call.export(), "count");
    assert_eq!(call.output(), "result");
    assert_eq!(call.descriptor(), &bundle.artifacts[0].descriptor);
    assert_eq!(call.schema().as_arrow(), &Fixture::schema("value"));
    let inputs = call.inputs();
    assert_eq!(inputs.len(), 2);
    let sources = crate::sources::SourceSnapshot::providers();
    let source = sources["events"].schema();
    let expected = sdk::Schema::new(vec![source
        .field_with_name("source_cursor")?
        .clone()
        .with_name("value")]);
    assert_eq!(inputs[0].schema().as_arrow(), &expected);
    assert_eq!(inputs[1].schema().as_arrow(), &Fixture::schema("increment"));
    let display = inputs[0].display_indent().to_string();
    assert!(display.contains("events"), "{display}");
    assert!(display.contains("Filter"), "{display}");
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    assert!(state.create_physical_plan(inputs[0]).await.is_ok());
    let parameters = collect(
        state.create_physical_plan(inputs[1]).await?,
        state.task_ctx(),
    )
    .await?;
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0].num_rows(), 1);
    let increment = parameters[0]
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("UInt64 parameter required")?;
    assert_eq!(increment.value(0), 2);
    let Err(error) = state.create_physical_plan(&prepared.plan).await else {
        return Err("package execution must remain unsupported".into());
    };
    assert_eq!(crate::Failure::native(&error), crate::Failure::Unsupported);
    Ok(())
}

#[tokio::test]
async fn native_package_call_rejections() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    for (name, sql) in [
        (
            "unknown input",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), unknown => (SELECT 1), increment => 2)"#,
        ),
        (
            "input type",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT 'wrong' AS value), increment => 2)"#,
        ),
        (
            "unknown parameter",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => 2, unknown => 3)"#,
        ),
        (
            "parameter type",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => 'wrong')"#,
        ),
        (
            "parameter cast",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => CAST('wrong' AS BIGINT UNSIGNED))"#,
        ),
        (
            "parameter null",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => NULL)"#,
        ),
        (
            "parameter cast null",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => CAST(NULL AS BIGINT UNSIGNED))"#,
        ),
        (
            "missing parameter",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events))"#,
        ),
        (
            "predicate column",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE absent > 1), increment => 2)"#,
        ),
        (
            "predicate type",
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE source_cursor), increment => 2)"#,
        ),
        (
            "output",
            r#"SELECT * FROM "fixture"."r1".count('absent', source => (SELECT source_cursor AS value FROM events), increment => 2)"#,
        ),
        (
            "revision",
            r#"SELECT * FROM "fixture"."r2".count(source => (SELECT source_cursor AS value FROM events), increment => 2)"#,
        ),
        (
            "export",
            r#"SELECT * FROM "fixture"."r1".absent(source => (SELECT source_cursor AS value FROM events), increment => 2)"#,
        ),
    ] {
        assert!(fixture.prepare(&Fixture::sql(sql)).await.is_err(), "{name}");
    }
    assert!(fixture
        .engine
        .prepare_definition(
            [2; 16],
            &Fixture::definition(),
            Arc::new(AnalysisReadControl::default())
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_output_selection() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0]
        .outputs
        .push(sdk::Port::new("second", Fixture::schema("value")));
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program
        .outputs
        .insert("second".into(), "SELECT value FROM source".into());
    let fixture = Fixture::installed(&bundle)?;
    assert!(fixture.prepare(&Fixture::definition()).await.is_err());
    for output in ["result", "second"] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count('{output}', source => (SELECT source_cursor AS value FROM events), increment => 2)"#
        ));
        let prepared = fixture.prepare(&definition).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].output(), output);
        assert_eq!(calls[0].schema().as_arrow(), &Fixture::schema("value"));
        assert_eq!(prepared.resolved.sql, definition.program.sql()?);
    }
    Ok(())
}

#[tokio::test]
async fn native_package_descriptor_inputs() -> TestResult {
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0].source =
        sdk::InputSource::Query("SELECT source_cursor AS value FROM events".into());
    let fixture = Fixture::installed(&bundle)?;
    let definition = Fixture::sql(r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#);
    let prepared = fixture.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].inputs().len(), 2);
    assert!(calls[0].inputs()[0]
        .display_indent()
        .to_string()
        .contains("events"));
    Ok(())
}

#[tokio::test]
async fn native_definition_sql_prql() -> TestResult {
    let fixture = Fixture::new()?;
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    for program in [
        Program::Sql {
            source: Source::Inline {
                inline: "SELECT source_cursor FROM events WHERE task_cookie > 0".into(),
            },
        },
        Program::Prql {
            source: Source::Inline {
                inline: "from events | filter task_cookie > 0 | select {source_cursor}".into(),
            },
        },
    ] {
        let mut definition = Fixture::definition();
        definition.program = program;
        let prepared = fixture.prepare(&definition).await?;
        assert!(prepared.resolved.images.is_empty());
        assert!(Fixture::calls(&prepared.plan)?.is_empty());
        assert_eq!(prepared.plan.schema().fields().len(), 1);
        assert_eq!(prepared.plan.schema().field(0).name(), "source_cursor");
        assert!(prepared
            .plan
            .display_indent()
            .to_string()
            .contains("events"));
        assert!(state.create_physical_plan(&prepared.plan).await.is_ok());
    }
    for inline in [
        "SELECT absent FROM events",
        "DELETE FROM events",
        "SELECT 1; SELECT 2",
    ] {
        assert!(fixture.prepare(&Fixture::sql(inline)).await.is_err());
    }
    let mut definition = Fixture::definition();
    definition.program = Program::Sql {
        source: Source::File {
            file: "/unread/server/path.sql".into(),
        },
    };
    assert!(fixture.prepare(&definition).await.is_err());
    Ok(())
}

#[tokio::test]
async fn native_definition_captured_file() -> TestResult {
    let fixture = Fixture::new()?;
    let path = fixture._directory.path().join("definition.json");
    let source = fixture._directory.path().join("query.sql");
    std::fs::write(&source, "SELECT source_cursor FROM events")?;
    let mut definition = Fixture::definition();
    definition.program = Program::Sql {
        source: Source::File {
            file: "query.sql".into(),
        },
    };
    std::fs::write(&path, serde_json::to_vec(&definition)?)?;
    let captured = Definition::read(&path)?;
    let admitted = fixture
        .engine
        .admit_definition(
            [1; 16],
            captured.clone(),
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    std::fs::write(&source, "SELECT absent FROM events")?;
    assert_eq!(
        fixture
            .engine
            .admit_definition([1; 16], captured, Arc::new(AnalysisReadControl::default()))
            .await?,
        admitted
    );
    assert!(fixture
        .engine
        .admit_definition(
            [1; 16],
            Definition::read(&path)?,
            Arc::new(AnalysisReadControl::default())
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_wasm_contract() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["count".into()],
        artifact: vec![0, 97, 115, 109, 1, 0, 0, 0],
    }];
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture.prepare(&Fixture::definition()).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].descriptor(), &bundle.artifacts[0].descriptor);
    assert_eq!(calls[0].inputs().len(), 2);
    assert_eq!(calls[0].schema().as_arrow(), &Fixture::schema("value"));
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    let Err(error) = state.create_physical_plan(&prepared.plan).await else {
        return Err("Wasm execution must remain unsupported".into());
    };
    assert_eq!(crate::Failure::native(&error), crate::Failure::Unsupported);
    Ok(())
}

#[tokio::test]
async fn native_package_window_contract() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    for predicate in [
        "received_at >= now() - INTERVAL '5 minutes'",
        "received_at < now()",
    ] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE {predicate}), increment => 2)"#
        ));
        let prepared = fixture.prepare(&definition).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let display = calls[0].inputs()[0].display_indent().to_string();
        assert!(display.contains("received_at"), "{display}");
        assert!(display.contains("Filter"), "{display}");
    }
    Ok(())
}

#[tokio::test]
async fn native_package_locked_dependency() -> TestResult {
    let mut bundle = Fixture::bundle();
    bundle.root.package_id = "consumer".into();
    let root = &mut bundle.artifacts[0];
    root.descriptor.id = "consumer".into();
    root.descriptor.exports[0].reasons[0].code = "consumer.note".into();
    root.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: "fixture".into(),
            revision: "r1".into(),
            export: "count".into(),
            output: "result".into(),
        }));
    let PackageImplementationV1::Sql { program, .. } = &mut root.implementations[0] else {
        return Err("SQL required".into());
    };
    program.reasons[0].code = "consumer.note".into();
    bundle.artifacts.push(PackageArtifactV1 {
        descriptor: sdk::Package::new(
            "fixture",
            "r1",
            vec![sdk::Model::new(
                "count",
                vec![],
                vec![sdk::Port::new("result", Fixture::schema("value"))],
            )],
        ),
        implementations: vec![PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                ..SqlModelV1::default()
            },
        }],
        fixtures: vec![],
    });
    let definition = Fixture::sql(r#"SELECT * FROM "consumer"."r1".count(increment => 2)"#);
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(prepared.resolved.images.len(), 1);
    assert_eq!(prepared.resolved.images[0].image, bundle.root);
    assert_eq!(prepared.resolved.images[0].digest, bundle.digest()?);
    assert_eq!(prepared.plan.schema().as_arrow(), &Fixture::schema("value"));
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs.push(sdk::InputPort {
        port: sdk::Port::new(
            "indexed",
            sdk::Schema::new(vec![
                sdk::Field::new("value", sdk::DataType::UInt64, false),
                sdk::Field::new("row_index", sdk::DataType::UInt64, false),
            ]),
        ),
        source: sdk::InputSource::Query(
            "SELECT value, __row_index AS row_index FROM source".into(),
        ),
    });
    let indexed = Fixture::installed(&bundle)?;
    let prepared = indexed.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    let call = calls
        .iter()
        .find(|call| call.package() == &bundle.root)
        .ok_or("consumer call absent")?;
    assert_eq!(call.inputs().len(), 3);
    assert_eq!(
        call.inputs()[1].schema().as_arrow(),
        &bundle.artifacts[0].descriptor.exports[0].inputs[1]
            .port
            .schema
    );
    assert!(call.inputs()[1]
        .display_indent()
        .to_string()
        .contains("row_index"));
    let invalid = Fixture::sql(
        r#"SELECT * FROM "consumer"."r1".count(source => (SELECT absent FROM events), increment => 2)"#,
    );
    assert!(indexed.prepare(&invalid).await.is_err());
    bundle.artifacts[1].descriptor.revision = "r2".into();
    assert!(Fixture::new()?.install(&bundle).is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_input_order() -> TestResult {
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.inputs[0] = sdk::Port::new("events", Fixture::schema("value")).into();
    model
        .inputs
        .push(sdk::Port::new("other", Fixture::schema("value")).into());
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT value FROM events UNION ALL SELECT value FROM other".into(),
    );
    program.evidence = Some("SELECT 'result' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'events' AS input_dataset, __row_index AS input_row FROM events".into());
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(events => (SELECT source_cursor AS value FROM events WHERE source_cursor > 100), other => (SELECT source_cursor AS value FROM events), increment => 2)"#,
    );
    for _ in 0..2 {
        let fixture = Fixture::installed(&bundle)?;
        let prepared = fixture.prepare(&definition).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let inputs = calls[0].inputs();
        assert_eq!(inputs.len(), 3);
        for (slot, input) in bundle.artifacts[0].descriptor.exports[0]
            .inputs
            .iter()
            .enumerate()
        {
            let display = inputs[slot].display_indent().to_string();
            assert_eq!(
                display.contains("100"),
                input.port.name == "events",
                "{display}"
            );
        }
        bundle.artifacts[0].descriptor.exports[0].inputs.reverse();
    }
    Ok(())
}

#[tokio::test]
async fn native_package_no_input_predicates() -> TestResult {
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.inputs.clear();
    model.checkpoint = None;
    model.reasons.clear();
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Sql {
        export: "count".into(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "result".into(),
                "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..SqlModelV1::default()
        },
    }];
    let fixture = Fixture::installed(&bundle)?;
    for predicate in ["absent > 0", "not valid SQL"] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count(increment => 2) WHERE {predicate}"#
        ));
        assert!(fixture.prepare(&definition).await.is_err());
    }
    for suffix in ["", " WHERE value > 0"] {
        let definition = Fixture::sql(format!(
            r#"SELECT * FROM "fixture"."r1".count(increment => 2){suffix}"#
        ));
        let prepared = fixture.prepare(&definition).await?;
        assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_package_named_projection() -> TestResult {
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0] = sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema("source_cursor")),
        source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
    };
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT source_cursor AS value FROM source".into(),
    );
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#,
        ))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    let sources = crate::sources::SourceSnapshot::providers();
    let source = sources["events"].schema();
    let expected = sdk::Schema::new(vec![source.field_with_name("source_cursor")?.clone()]);
    assert_eq!(calls[0].inputs()[0].schema().as_arrow(), &expected);
    Ok(())
}

#[tokio::test]
async fn native_package_zero_column_input() -> TestResult {
    use datafusion::catalog::TableProvider;
    use datafusion::datasource::MemTable;
    use sdk::arrow_array::UInt64Array;

    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.inputs[0] = sdk::Port::new("events", sdk::Schema::empty()).into();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL required".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
    );
    program.evidence = None;
    let definition = Fixture::sql(r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#);
    let fixture = Fixture::installed(&bundle)?;
    let batch = sdk::RecordBatch::try_new(
        Arc::new(Fixture::schema("source_cursor")),
        vec![Arc::new(UInt64Array::from(vec![1, 2, 3]))],
    )?;
    let provider =
        Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]])?) as Arc<dyn TableProvider>;
    let plan = crate::inputs::Inputs::scan("events", Arc::clone(&provider), &sdk::Schema::empty())?;
    let state = fixture
        .engine
        .catalog(BTreeMap::from([("events".into(), provider)]))?;
    let batches = collect(state.create_physical_plan(&plan).await?, state.task_ctx()).await?;
    assert!(batches.iter().all(|batch| batch.num_columns() == 0));
    assert_eq!(
        batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        3
    );
    let prepared = fixture.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert!(calls[0].inputs()[0].schema().fields().is_empty());
    bundle.artifacts[0].descriptor.exports[0]
        .checkpoint
        .as_mut()
        .ok_or("checkpoint fixture absent")?
        .datasets[0]
        .schema = sdk::Schema::empty();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.checkpoint.insert(
        "state".into(),
        "SELECT * EXCLUDE (__row_index) FROM prior_state".into(),
    );
    let checkpoint = Fixture::installed(&bundle)?;
    let prepared = checkpoint.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert!(calls[0].descriptor().exports[0]
        .checkpoint
        .as_ref()
        .ok_or("checkpoint absent")?
        .datasets[0]
        .schema
        .fields()
        .is_empty());
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.outputs[0].schema = sdk::Schema::empty();
    model.reasons.clear();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT * EXCLUDE (__row_index) FROM events".into(),
    );
    program.reasons.clear();
    let output = Fixture::installed(&bundle)?;
    let prepared = output.prepare(&definition).await?;
    assert!(prepared.plan.schema().fields().is_empty());
    Ok(())
}

#[tokio::test]
async fn native_package_output_reason_index() -> TestResult {
    let mut bundle = Fixture::bundle();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.reasons[0].sql = "SELECT __row_index AS output_row, value FROM output_result".into();
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture.prepare(&Fixture::definition()).await?;
    assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn native_package_cte_input() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let definition = Fixture::sql(
        r#"WITH selected AS (SELECT source_cursor AS value FROM events WHERE source_cursor > 100) SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM selected), increment => 2)"#,
    );
    let prepared = fixture.prepare(&definition).await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    let display = calls[0].inputs()[0].display_indent().to_string();
    assert!(display.contains("events"), "{display}");
    assert!(display.contains("100"), "{display}");
    Ok(())
}

#[tokio::test]
async fn native_package_multiple_calls() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    for sql in [
        r#"SELECT left_call.value AS first, right_call.value AS second FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE source_cursor > 100), increment => 2) AS left_call CROSS JOIN "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE source_cursor < 10), increment => 3) AS right_call"#,
        r#"SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events WHERE source_cursor > 100), increment => 2)), increment => 3)"#,
    ] {
        let prepared = fixture.prepare(&Fixture::sql(sql)).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 2);
        assert_eq!(prepared.resolved.images.len(), 1);
        let state = fixture
            .engine
            .catalog(crate::sources::SourceSnapshot::providers())?;
        let mut increments = Vec::new();
        for call in &calls {
            let inputs = call.inputs();
            assert_eq!(inputs.len(), 2);
            let batches = collect(
                state.create_physical_plan(inputs[1]).await?,
                state.task_ctx(),
            )
            .await?;
            let values = batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
                .ok_or("UInt64 parameter required")?;
            increments.push(values.value(0));
        }
        increments.sort_unstable();
        assert_eq!(increments, [2, 3]);
        if sql.contains("CROSS JOIN") {
            let displays = calls
                .iter()
                .map(|call| call.inputs()[0].display_indent().to_string())
                .collect::<Vec<_>>();
            assert!(displays.iter().any(|display| display.contains("100")));
            assert!(displays
                .iter()
                .any(|display| display.contains("10") && !display.contains("100")));
        } else {
            assert!(
                calls
                    .iter()
                    .any(|call| Fixture::calls(call.inputs()[0])
                        .is_ok_and(|nested| nested.len() == 1))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_package_recursion_rejected() -> TestResult {
    let recursive = r#"SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => 2)"#;
    for sql_body in [true, false] {
        let mut bundle = Fixture::bundle();
        let artifact = &mut bundle.artifacts[0];
        let definition = if sql_body {
            let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0]
            else {
                return Err("SQL fixture absent".into());
            };
            program.outputs.insert("result".into(), recursive.into());
            artifact.descriptor.exports.push(sdk::Model::new(
                "safe",
                vec![],
                vec![sdk::Port::new("result", Fixture::schema("value"))],
            ));
            artifact.implementations.push(PackageImplementationV1::Sql {
                export: "safe".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "result".into(),
                        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
                    )]),
                    ..SqlModelV1::default()
                },
            });
            Fixture::definition()
        } else {
            let model = &mut artifact.descriptor.exports[0];
            model.input_mode = sdk::InputMode::Resolved;
            model.inputs[0].source = sdk::InputSource::Query(recursive.into());
            Fixture::sql(r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#)
        };
        let fixture = Fixture::installed(&bundle)?;
        let Err(error) = fixture.prepare(&definition).await else {
            return Err("recursive package SQL must fail".into());
        };
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut cycle = false;
        while let Some(error) = source {
            cycle |= matches!(
                error.downcast_ref::<crate::Error>(),
                Some(crate::Error::Invalid {
                    field: "package SQL cycle",
                    ..
                })
            );
            source = error.source();
        }
        assert!(cycle, "{error:?}");
        let valid = if sql_body {
            Fixture::sql(r#"SELECT * FROM "fixture"."r1".safe()"#)
        } else {
            Fixture::definition()
        };
        let prepared = fixture.prepare(&valid).await?;
        assert_eq!(prepared.plan.schema().as_arrow(), &Fixture::schema("value"));
        assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_package_lexical_scope() -> TestResult {
    let mut bundle = Fixture::bundle();
    let artifact = &mut bundle.artifacts[0];
    let outer = &mut artifact.descriptor.exports[0];
    outer.inputs.clear();
    outer.checkpoint = None;
    outer.reasons.clear();
    artifact.descriptor.exports.push(sdk::Model::new(
        "inner",
        vec![],
        vec![sdk::Port::new("result", Fixture::schema("value"))],
    ));
    artifact.implementations = vec![
        PackageImplementationV1::Sql {
            export: "count".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    r#"SELECT * FROM "fixture"."r1".inner()"#.into(),
                )]),
                ..SqlModelV1::default()
            },
        },
        PackageImplementationV1::Sql {
            export: "inner".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT increment AS value FROM parameters".into(),
                )]),
                ..SqlModelV1::default()
            },
        },
    ];
    let fixture = Fixture::installed(&bundle)?;
    for sql in [
        r#"SELECT * FROM "fixture"."r1".inner()"#,
        r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#,
    ] {
        let Err(error) = fixture.prepare(&Fixture::sql(sql)).await else {
            return Err("undeclared parameter table must fail".into());
        };
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut missing = false;
        while let Some(error) = source {
            if let Some(datafusion::common::DataFusionError::Plan(message)) =
                error.downcast_ref::<datafusion::common::DataFusionError>()
            {
                missing |= message.contains("table")
                    && message.contains("parameters")
                    && message.contains("not found");
            }
            source = error.source();
        }
        assert!(missing, "{error:?}");
    }
    bundle.artifacts[0].descriptor.exports[1].parameters = Fixture::schema("increment");
    for implementation in &mut bundle.artifacts[0].implementations {
        let PackageImplementationV1::Sql { export, program } = implementation else {
            return Err("SQL fixture absent".into());
        };
        program.outputs.insert(
            "result".into(),
            if export == "count" {
                r#"SELECT * FROM "fixture"."r1".inner(increment => 7)"#.into()
            } else {
                "SELECT increment AS value FROM datafusion.public.parameters".into()
            },
        );
    }
    let own = Fixture::installed(&bundle)?;
    for (sql, export, expected) in [
        (
            r#"SELECT * FROM "fixture"."r1".inner(increment => 7)"#,
            "inner",
            7,
        ),
        (
            r#"SELECT * FROM "fixture"."r1".count(increment => 2)"#,
            "count",
            2,
        ),
    ] {
        let prepared = own.prepare(&Fixture::sql(sql)).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].export(), export);
        assert_eq!(calls[0].schema().as_arrow(), &Fixture::schema("value"));
        let inputs = calls[0].inputs();
        assert_eq!(inputs.len(), 1);
        let state = own
            .engine
            .catalog(crate::sources::SourceSnapshot::providers())?;
        let batches = collect(
            state.create_physical_plan(inputs[0]).await?,
            state.task_ctx(),
        )
        .await?;
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 1);
        let values = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("UInt64 parameter required")?;
        assert_eq!(values.value(0), expected);
    }
    Ok(())
}

#[tokio::test]
async fn native_package_body_optimization() -> TestResult {
    for literal in ["wrong", "0"] {
        let mut bundle = Fixture::bundle();
        let artifact = &mut bundle.artifacts[0];
        let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0] else {
            return Err("SQL fixture absent".into());
        };
        program.outputs.insert(
            "result".into(),
            format!(
                r#"SELECT value + CAST('{literal}' AS BIGINT UNSIGNED) AS value FROM "fixture"."r1".inner()"#
            ),
        );
        artifact.descriptor.exports.push(sdk::Model::new(
            "inner",
            vec![],
            vec![sdk::Port::new("result", Fixture::schema("value"))],
        ));
        artifact.implementations.push(PackageImplementationV1::Sql {
            export: "inner".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "result".into(),
                    "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                ..SqlModelV1::default()
            },
        });
        let fixture = Fixture::installed(&bundle)?;
        let prepared = fixture.prepare(&Fixture::definition()).await;
        if literal == "wrong" {
            let Err(error) = prepared else {
                return Err("invalid body cast must fail native optimization".into());
            };
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            let mut invalid_cast = false;
            while let Some(error) = source {
                let message = error.to_string().to_ascii_lowercase();
                invalid_cast |= message.contains("cast") && message.contains("wrong");
                source = error.source();
            }
            assert!(invalid_cast, "{error:?}");
        } else {
            let prepared = prepared?;
            assert_eq!(prepared.plan.schema().as_arrow(), &Fixture::schema("value"));
            assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
            assert_eq!(prepared.resolved.images[0].digest, bundle.digest()?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_package_prql_call() -> TestResult {
    let fixture = Fixture::installed(&Fixture::bundle())?;
    let mut definition = Fixture::definition();
    definition.program = Program::Prql { source: Source::Inline {
        inline: r#"from s"""SELECT * FROM "fixture"."r1".count(source => (SELECT source_cursor AS value FROM events), increment => 2)""""#.into(),
    } };
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(Fixture::calls(&prepared.plan)?.len(), 1);
    assert_eq!(prepared.resolved.images[0].image, Fixture::bundle().root);
    assert!(prepared.resolved.sql.contains(r#""fixture"."r1".count"#));
    Ok(())
}
