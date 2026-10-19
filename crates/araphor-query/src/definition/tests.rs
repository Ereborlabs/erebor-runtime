use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::AnalysisStore;
use araphor_discovery_definition::{Definition, PackageCall as DefinitionCall, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
    SqlReasonV1,
};
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::{LogicalPlan, UserDefinedLogicalNodeCore};

use super::PackageCall;
use crate::execution::{Engine, Limits};

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(AnalysisStore::open(directory.path().join("data")).unwrap());
        Self {
            engine: Engine::new(store, Limits::default()).unwrap(),
            _directory: directory,
        }
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
            program: Program::Package {
                call: DefinitionCall {
                    image: Self::bundle().root,
                    export: "count".into(),
                    inputs: BTreeMap::from([(
                        "source".into(),
                        "SELECT source_cursor AS value FROM events".into(),
                    )]),
                    parameters: serde_json::json!({ "increment": 2 }),
                    window: Some("value >= CAST(1 AS BIGINT UNSIGNED)".into()),
                    output: None,
                },
            },
        }
    }

    fn call(definition: &mut Definition) -> &mut DefinitionCall {
        let Program::Package { call } = &mut definition.program else {
            panic!("package definition required")
        };
        call
    }
}

#[tokio::test]
async fn native_package_call_contract() -> TestResult {
    let fixture = Fixture::new();
    let bundle = Fixture::bundle();
    let definition = Fixture::definition();
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert_eq!(prepared.resolved.definition, definition);
    assert_eq!(prepared.resolved.images[0].digest, bundle.digest()?);
    assert!(prepared
        .resolved
        .sql
        .contains("araphor.package_call('fixture', 'r1', 'count', 'result')"));
    let mut calls = 0;
    prepared.plan.apply_with_subqueries(|plan| {
        if let LogicalPlan::Extension(extension) = plan {
            if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                calls += 1;
                assert_eq!(call.inputs().len(), 1);
                assert_eq!(call.output(), "result");
                assert_eq!(call.descriptor(), &bundle.artifacts[0].descriptor);
                assert_eq!(
                    call.definition().parameters,
                    serde_json::json!({"increment": 2})
                );
                assert_eq!(call.schema().as_arrow(), &Fixture::schema("value"));
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    assert_eq!(calls, 1);
    let sql = prepared
        .sql_plan
        .as_ref()
        .ok_or("native SQL plan required")?;
    assert!(sql.display_indent().to_string().contains("events"));
    assert!(prepared
        .plan
        .display_indent()
        .to_string()
        .contains("Filter"));
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    assert!(state.create_physical_plan(sql).await.is_ok());
    let error = state
        .create_physical_plan(&prepared.plan)
        .await
        .expect_err("package execution is separate");
    assert_eq!(crate::Failure::native(&error), crate::Failure::Unsupported);
    Ok(())
}

#[tokio::test]
async fn native_package_call_rejections() -> TestResult {
    let fixture = Fixture::new();
    let bundle = Fixture::bundle();
    for (name, mutate) in [
        ("unknown input", 0),
        ("input type", 1),
        ("unknown parameter", 2),
        ("parameter type", 3),
        ("missing parameter", 4),
        ("window column", 5),
        ("window type", 6),
        ("output", 7),
        ("revision", 8),
        ("export", 9),
    ] {
        let mut definition = Fixture::definition();
        let call = Fixture::call(&mut definition);
        match mutate {
            0 => {
                call.inputs.insert("unknown".into(), "SELECT 1".into());
            }
            1 => {
                call.inputs
                    .insert("source".into(), "SELECT 'wrong' AS value".into());
            }
            2 => call.parameters = serde_json::json!({ "increment": 2, "unknown": 3 }),
            3 => call.parameters = serde_json::json!({ "increment": "wrong" }),
            4 => call.parameters = serde_json::json!({}),
            5 => call.window = Some("absent > 1".into()),
            6 => call.window = Some("value".into()),
            7 => call.output = Some("absent".into()),
            8 => call.image.revision = "r2".into(),
            _ => call.export = "absent".into(),
        }
        assert!(
            fixture
                .engine
                .prepare_definition(&definition, std::slice::from_ref(&bundle))
                .await
                .is_err(),
            "{name}"
        );
    }
    assert!(fixture
        .engine
        .prepare_definition(&Fixture::definition(), &[bundle.clone(), bundle])
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_output_selection() -> TestResult {
    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].descriptor.exports[0]
        .outputs
        .push(sdk::Port::new("second", Fixture::schema("value")));
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        panic!("SQL required")
    };
    program
        .outputs
        .insert("second".into(), "SELECT value FROM source".into());
    let mut definition = Fixture::definition();
    assert!(fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await
        .is_err());
    Fixture::call(&mut definition).output = Some("second".into());
    let prepared = fixture
        .engine
        .prepare_definition(&definition, &[bundle])
        .await?;
    assert!(prepared.resolved.sql.contains("'second'"));
    Ok(())
}

#[tokio::test]
async fn native_package_descriptor_inputs() -> TestResult {
    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0].source =
        sdk::InputSource::Query("SELECT source_cursor AS value FROM events".into());
    let mut definition = Fixture::definition();
    Fixture::call(&mut definition).inputs.clear();
    let prepared = fixture
        .engine
        .prepare_definition(&definition, &[bundle])
        .await?;
    assert!(prepared
        .plan
        .display_indent()
        .to_string()
        .contains("events"));
    Ok(())
}

#[tokio::test]
async fn native_definition_sql_prql() -> TestResult {
    let fixture = Fixture::new();
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
        let prepared = fixture.engine.prepare_definition(&definition, &[]).await?;
        assert!(prepared.resolved.images.is_empty());
        assert!(prepared.sql_plan.is_some());
        assert!(prepared
            .plan
            .display_indent()
            .to_string()
            .contains("events"));
    }
    for inline in [
        "SELECT absent FROM events",
        "DELETE FROM events",
        "SELECT 1; SELECT 2",
    ] {
        let mut definition = Fixture::definition();
        definition.program = Program::Sql {
            source: Source::Inline {
                inline: inline.into(),
            },
        };
        assert!(fixture
            .engine
            .prepare_definition(&definition, &[])
            .await
            .is_err());
    }
    let mut definition = Fixture::definition();
    definition.program = Program::Sql {
        source: Source::File {
            file: "/unread/server/path.sql".into(),
        },
    };
    assert!(fixture
        .engine
        .prepare_definition(&definition, &[])
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_definition_captured_file() -> TestResult {
    let fixture = Fixture::new();
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
        .admit_definition(captured.clone(), &[])
        .await?;
    std::fs::write(&source, "SELECT absent FROM events")?;
    assert_eq!(
        fixture.engine.admit_definition(captured, &[]).await?,
        admitted
    );
    assert!(fixture
        .engine
        .admit_definition(Definition::read(&path)?, &[])
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_wasm_contract() -> TestResult {
    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0].implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["count".into()],
        artifact: vec![0, 97, 115, 109, 1, 0, 0, 0],
    }];
    let prepared = fixture
        .engine
        .prepare_definition(&Fixture::definition(), &[bundle])
        .await?;
    assert!(prepared.sql_plan.is_none());
    assert!(prepared
        .plan
        .display_indent()
        .to_string()
        .contains("PackageCall"));
    Ok(())
}

#[tokio::test]
async fn native_package_window_contract() -> TestResult {
    let fixture = Fixture::new();
    let bundle = Fixture::bundle();
    let mut definition = Fixture::definition();
    let call = Fixture::call(&mut definition);
    call.inputs.insert(
        "source".into(),
        "SELECT source_cursor AS value FROM events".into(),
    );
    call.window = Some("received_at >= now() - INTERVAL '5 minutes'".into());
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert!(prepared.sql_plan.is_some());
    for window in [
        "now() > TIMESTAMP '2020-01-01'",
        "received_at < now()",
        "received_at >= now() - INTERVAL '1 month'",
    ] {
        Fixture::call(&mut definition).window = Some(window.into());
        assert!(
            fixture
                .engine
                .prepare_definition(&definition, std::slice::from_ref(&bundle))
                .await
                .is_err(),
            "{window}"
        );
    }
    let mut named = bundle;
    named.artifacts[0].descriptor.exports[0].inputs[0]
        .port
        .schema = Fixture::schema("source_cursor");
    named.artifacts[0].descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Named("events".into()));
    let PackageImplementationV1::Sql { program, .. } = &mut named.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.outputs.insert("result".into(),
        "SELECT source.source_cursor + parameters.increment AS value FROM source CROSS JOIN parameters".into());
    let call = Fixture::call(&mut definition);
    call.inputs.clear();
    call.window = Some("received_at >= now() - INTERVAL '5 minutes'".into());
    assert!(fixture
        .engine
        .prepare_definition(&definition, &[named])
        .await?
        .sql_plan
        .is_some());
    Ok(())
}

#[tokio::test]
async fn native_package_locked_dependency() -> TestResult {
    let fixture = Fixture::new();
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
        panic!("SQL required")
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
    let mut definition = Fixture::definition();
    let call = Fixture::call(&mut definition);
    call.image = bundle.root.clone();
    call.inputs.clear();
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert_eq!(prepared.resolved.images[0].digest, bundle.digest()?);
    assert!(prepared.sql_plan.is_some());
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
    let indexed = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert!(indexed.sql_plan.is_some());
    assert!(indexed
        .plan
        .display_indent()
        .to_string()
        .contains("row_index"));
    let mut invalid = definition.clone();
    Fixture::call(&mut invalid).window = Some("absent > 0".into());
    assert!(fixture
        .engine
        .prepare_definition(&invalid, std::slice::from_ref(&bundle))
        .await
        .is_err());
    bundle.artifacts[1].descriptor.revision = "r2".into();
    assert!(fixture
        .engine
        .prepare_definition(&definition, &[bundle])
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn native_package_input_order() -> TestResult {
    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.inputs[0] = sdk::Port::new("events", Fixture::schema("value")).into();
    model
        .inputs
        .push(sdk::Port::new("other", Fixture::schema("value")).into());
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        panic!("SQL required")
    };
    program.outputs.insert(
        "result".into(),
        "SELECT value FROM events UNION ALL SELECT value FROM other".into(),
    );
    program.evidence = Some("SELECT 'result' AS output_dataset, CAST(0 AS BIGINT UNSIGNED) AS output_row, 'events' AS input_dataset, __row_index AS input_row FROM events".into());
    let mut definition = Fixture::definition();
    Fixture::call(&mut definition).inputs = BTreeMap::from([
        (
            "events".into(),
            "SELECT source_cursor AS value FROM events WHERE source_cursor > 100".into(),
        ),
        (
            "other".into(),
            "SELECT source_cursor AS value FROM events".into(),
        ),
    ]);
    for _ in 0..2 {
        let prepared = fixture
            .engine
            .prepare_definition(&definition, std::slice::from_ref(&bundle))
            .await?;
        assert!(prepared.sql_plan.is_some());
        bundle.artifacts[0].descriptor.exports[0].inputs.reverse();
    }
    Ok(())
}

#[tokio::test]
async fn native_package_window_requires_input() -> TestResult {
    let fixture = Fixture::new();
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
    let mut definition = Fixture::definition();
    Fixture::call(&mut definition).inputs.clear();
    for window in ["absent > 0", "not valid SQL"] {
        Fixture::call(&mut definition).window = Some(window.into());
        assert!(matches!(
            fixture
                .engine
                .prepare_definition(&definition, std::slice::from_ref(&bundle))
                .await,
            Err(crate::Error::Invalid {
                field: "package window input",
                ..
            })
        ));
    }
    Fixture::call(&mut definition).window = None;
    assert!(fixture
        .engine
        .prepare_definition(&definition, &[bundle])
        .await
        .is_ok());
    Ok(())
}

#[tokio::test]
async fn native_package_named_projection() -> TestResult {
    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs[0] = sdk::InputPort {
        port: sdk::Port::new("source", Fixture::schema("source_cursor")),
        source: sdk::InputSource::Table(sdk::TableRef::Named("events".into())),
    };
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        panic!("SQL required")
    };
    program.outputs.insert(
        "result".into(),
        "SELECT source_cursor AS value FROM source".into(),
    );
    let mut definition = Fixture::definition();
    let call = Fixture::call(&mut definition);
    call.inputs.clear();
    call.window = None;
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert!(prepared.sql_plan.is_some());
    Ok(())
}

#[tokio::test]
async fn native_package_zero_column_input() -> TestResult {
    use datafusion::catalog::TableProvider;
    use datafusion::datasource::MemTable;
    use datafusion::physical_plan::collect;
    use sdk::arrow_array::UInt64Array;

    let fixture = Fixture::new();
    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.inputs[0] = sdk::Port::new("events", sdk::Schema::empty()).into();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        panic!("SQL required")
    };
    program.outputs.insert(
        "result".into(),
        "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
    );
    program.evidence = None;
    let mut definition = Fixture::definition();
    let call = Fixture::call(&mut definition);
    call.inputs.clear();
    call.window = None;
    let batch = sdk::RecordBatch::try_new(
        Arc::new(Fixture::schema("source_cursor")),
        vec![Arc::new(UInt64Array::from(vec![1, 2, 3]))],
    )?;
    let tables = BTreeMap::from([(
        "events".into(),
        Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]])?) as Arc<dyn TableProvider>,
    )]);
    let (plan, _) = super::package::PackagePlanner::named(
        &bundle.artifacts[0].descriptor.exports[0].inputs[0],
        call,
        &tables,
    )?
    .ok_or("named input required")?;
    let state = fixture.engine.catalog(tables)?;
    let physical = state.create_physical_plan(&plan).await?;
    let batches = collect(physical, state.task_ctx()).await?;
    assert!(batches.iter().all(|batch| batch.num_columns() == 0));
    assert_eq!(
        batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        3
    );
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert!(prepared.sql_plan.is_some());
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
    let prepared = fixture
        .engine
        .prepare_definition(&definition, std::slice::from_ref(&bundle))
        .await?;
    assert!(prepared.sql_plan.is_some());
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
    let prepared = fixture
        .engine
        .prepare_definition(&definition, &[bundle])
        .await?;
    assert!(prepared
        .sql_plan
        .ok_or("SQL output plan absent")?
        .schema()
        .fields()
        .is_empty());
    Ok(())
}
