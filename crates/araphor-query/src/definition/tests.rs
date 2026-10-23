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

mod capacity;
mod captured;
mod collision;
mod execution;
mod guest;
mod managed;
mod parity;
mod replay;
mod retained;
mod subscription;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::limits(Limits::default())
    }

    fn limits(limits: Limits) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        Ok(Self {
            engine: Engine::new(store, limits)?,
            _directory: directory,
        })
    }

    async fn image_limits(
        mut limits: Limits,
        bundle: &PackageBundleV1,
        definition: &Definition,
    ) -> TestResult<Self> {
        let mut fixture = Self::new()?;
        fixture.install(bundle)?;
        if let Some(capacity) = limits.input_capacity {
            let prepared = fixture.prepare(definition).await?;
            let retained = fixture.engine.memory().input_reserved();
            limits.input_capacity = Some(capacity.checked_add(retained).ok_or("image capacity")?);
            drop(prepared);
            assert_eq!(fixture.engine.memory().input_reserved(), 0);
        }
        fixture.engine = Engine::new(Arc::clone(fixture.engine.store()), limits)?;
        Ok(fixture)
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
                        evidence: Some("SELECT 'result' AS output_dataset, __row_index AS output_row, 'source' AS input_dataset, __row_index AS input_row FROM source".into()),
                        reasons: vec![SqlReasonV1 { output: "result".into(), code: "fixture.note".into(), sql: "SELECT __row_index AS output_row, value FROM output_result".into() }],
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
async fn package_debug_omits_payload() -> TestResult {
    let mut bundle = Fixture::bundle();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program
        .outputs
        .get_mut("result")
        .ok_or("SQL output absent")?
        .push_str(&format!(" /* {} */", "PRIVATE_PACKAGE_BODY".repeat(4096)));
    for (bundle, definition) in [
        (bundle, Fixture::definition()),
        (
            execution::component("wasm", "count-input")?,
            Fixture::sql(
                r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
                input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value),
                mode => 'sum-input', amount => 0)"#,
            ),
        ),
    ] {
        let fixture = Fixture::installed(&bundle)?;
        let prepared = fixture.prepare(&definition).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(
            format!("{call:?}"),
            format!(
                "PackageCall: {}@{} {}/{}",
                call.package().package_id,
                call.package().revision,
                call.export(),
                call.output(),
            ),
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_package_call_contract() -> TestResult {
    let bundle = Fixture::bundle();
    let fixture = Fixture::installed(&bundle)?;
    let definition = Fixture::definition();
    let prepared = fixture.prepare(&definition).await?;
    assert_eq!(prepared.resolved().definition, definition);
    assert_eq!(prepared.resolved().sql, definition.program.sql()?);
    assert_eq!(prepared.resolved().images.len(), 1);
    assert_eq!(prepared.resolved().images[0].image, bundle.root);
    assert_eq!(prepared.resolved().images[0].digest, bundle.digest()?);
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.image(), &prepared.resolved().images[0]);
    assert_eq!(call.package(), &bundle.root);
    assert_eq!(call.export(), "count");
    assert_eq!(call.output(), "result");
    assert!(!call.arguments().is_empty());
    assert_eq!(call.descriptor(), &bundle.artifacts[0].descriptor);
    assert_eq!(call.schema().as_arrow(), &Fixture::schema("value"));
    let inputs = call.inputs();
    assert_eq!(inputs.len(), 6);
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
    state.create_physical_plan(&prepared.plan).await?;
    let output = fixture
        .execute(&prepared, execution::invocation("contract"))
        .await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(
        output
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        0
    );
    assert_eq!(
        output
            .calls
            .values()
            .next()
            .ok_or("call output absent")?
            .output()
            .checkpoint
            .as_ref()
            .ok_or("checkpoint absent")?
            .version,
        2
    );
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
    for implementation in [
        PackageImplementationV1::Python {
            export: "count".into(),
            artifact: vec![1],
        },
        PackageImplementationV1::Native {
            export: "count".into(),
            artifact: vec![1],
            qualification: None,
        },
    ] {
        let mut bundle = Fixture::bundle();
        bundle.artifacts[0].implementations = vec![implementation];
        assert!(!bundle.artifacts[0].prepared("count"));
        let fixture = Fixture::installed(&bundle)?;
        let before = fixture.engine.store().meta()?;
        let Err(error) = fixture.prepare(&Fixture::definition()).await else {
            return Err("unsupported selected target accepted".into());
        };
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut unsupported = false;
        while let Some(error) = source {
            let package = match error.downcast_ref::<crate::Error>() {
                Some(crate::Error::Data { source }) => Some(source),
                _ => error.downcast_ref::<araphor_data::Error>(),
            };
            unsupported |= matches!(
                package,
                Some(araphor_data::Error::Package {
                    code: araphor_data::PackageErrorCodeV1::Unsupported,
                    field: "model target",
                    ..
                })
            );
            source = error.source();
        }
        assert!(unsupported, "{error:?}");
        assert_eq!(fixture.engine.store().meta()?, before);
        assert_eq!(fixture.engine.memory().input_reserved(), 0);
    }
    let mut bundle = Fixture::bundle();
    bundle.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            artifact: vec![1],
        });
    assert!(!bundle.artifacts[0].prepared("count"));
    assert!(!bundle.artifacts[0].prepared("absent"));
    assert!(matches!(
        bundle.artifacts[0].implementation("count"),
        Err(araphor_package::Error::Package {
            code: araphor_package::ErrorCode::Invalid,
            field: "plugin execution type",
            ..
        })
    ));
    let before = fixture.engine.store().meta()?;
    assert!(matches!(
        fixture
            .engine
            .store()
            .install_package_image([1; 16], &bundle, || Ok(())),
        Err(araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Invalid,
            field: "plugin execution type",
            ..
        })
    ));
    assert_eq!(fixture.engine.store().meta()?, before);
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
        assert_eq!(prepared.resolved().sql, definition.program.sql()?);
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
    assert_eq!(calls[0].inputs().len(), 6);
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
        assert!(prepared.resolved().images.is_empty());
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
    let path = fixture._directory.path().join("definition.yaml");
    let source = fixture._directory.path().join("query.sql");
    std::fs::write(&source, "SELECT source_cursor FROM events")?;
    std::fs::write(
        &path,
        "name: count-events\ndescription: Count selected events.\nlabels:\n  team: security\nsql:\n  file: query.sql\n",
    )?;
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
async fn native_definition_call_file() -> TestResult {
    let bundle = Fixture::bundle();
    let fixture = Fixture::installed(&bundle)?;
    let path = fixture._directory.path().join("definition.yaml");
    let source = fixture._directory.path().join("query.sql");
    std::fs::write(
        &source,
        "SELECT source_cursor AS value FROM events WHERE source_cursor > 100",
    )?;
    std::fs::write(
        &path,
        "name: count-events\ndescription: Count selected events.\nlabels:\n  team: security\ncall:\n  package: fixture\n  revision: r1\n  export: count\n  inputs:\n    source:\n      file: query.sql\n  parameters:\n    increment: 18446744073709551615\n  output: result\n",
    )?;
    let captured = Definition::read(&path)?;
    assert_eq!(captured.name, "count-events");
    assert_eq!(captured.description, "Count selected events.");
    assert_eq!(
        captured.labels,
        BTreeMap::from([("team".into(), "security".into())])
    );
    assert!(matches!(&captured.program, Program::Sql { .. }));
    std::fs::write(&source, "SELECT absent FROM events")?;
    std::fs::remove_file(&source)?;
    std::fs::remove_file(&path)?;
    let prepared = fixture.prepare(&captured).await?;
    assert_eq!(prepared.resolved().definition, captured);
    assert_eq!(prepared.resolved().images.len(), 1);
    assert_eq!(prepared.resolved().images[0].image, bundle.root);
    assert_eq!(prepared.resolved().images[0].digest, bundle.digest()?);
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].output(), "result");
    assert_eq!(calls[0].schema().as_arrow(), &Fixture::schema("value"));
    assert_eq!(calls[0].inputs().len(), 6);
    let display = calls[0].inputs()[0].display_indent().to_string();
    assert!(display.contains("100"), "{display}");
    assert!(!display.contains("absent"), "{display}");
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    let inputs = calls[0].inputs();
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
    assert_eq!(increment.value(0), u64::MAX);
    let output = fixture
        .execute(&prepared, execution::invocation("captured-call-file"))
        .await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(
        output
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    for value in ["'2 + 1'", "null"] {
        std::fs::write(
            &path,
            format!(
                "name: count-events\ncall:\n  package: fixture\n  revision: r1\n  export: count\n  inputs:\n    source: SELECT source_cursor AS value FROM events\n  parameters:\n    increment: {value}\n"
            ),
        )?;
        let definition = Definition::read(&path)?;
        assert!(fixture.prepare(&definition).await.is_err(), "{value}");
    }
    Ok(())
}

#[tokio::test]
async fn native_package_wasm_contract() -> TestResult {
    let bundle = execution::component("wasm", "count-input")?;
    let fixture = Fixture::installed(&bundle)?;
    let prepared = fixture
        .prepare(&Fixture::sql(
            r#"SELECT * FROM "runtime-fixture"."1"."count-input"(
            input => (SELECT CAST(7 AS BIGINT UNSIGNED) AS value),
            mode => 'sum-input', amount => 0)"#,
        ))
        .await?;
    let calls = Fixture::calls(&prepared.plan)?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].descriptor(), &bundle.artifacts[0].descriptor);
    assert_eq!(calls[0].inputs().len(), 2);
    assert_eq!(calls[0].schema().as_arrow(), &Fixture::schema("value"));
    let state = fixture
        .engine
        .catalog(crate::sources::SourceSnapshot::providers())?;
    state.create_physical_plan(&prepared.plan).await?;
    let output = fixture
        .execute(&prepared, execution::invocation("wasm-contract"))
        .await?;
    assert_eq!(output.calls.len(), 1);
    let values = output.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("UInt64 output required")?;
    assert_eq!(values.values().as_ref(), &[7]);
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
    assert_eq!(prepared.resolved().images.len(), 1);
    assert_eq!(prepared.resolved().images[0].image, bundle.root);
    assert_eq!(prepared.resolved().images[0].digest, bundle.digest()?);
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
    assert_eq!(call.inputs().len(), 7);
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
async fn native_package_bound_inputs() -> TestResult {
    use sdk::arrow_array::UInt64Array;

    let mut bundle = Fixture::bundle();
    let model = &mut bundle.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Resolved;
    model.inputs = vec![
        sdk::InputPort {
            port: sdk::Port::new("source", Fixture::schema("value")),
            source: sdk::InputSource::Query(
                "SELECT value + CAST(1 AS BIGINT UNSIGNED) AS value FROM middle WHERE row_index IN (SELECT row_index FROM middle WHERE row_index = 1)".into(),
            ),
        },
        sdk::InputPort {
            port: sdk::Port::new(
                "middle",
                sdk::Schema::new(vec![
                    sdk::Field::new("value", sdk::DataType::UInt64, false),
                    sdk::Field::new("tag", sdk::DataType::Utf8, false),
                    sdk::Field::new("row_index", sdk::DataType::UInt64, false),
                ]),
            ),
            source: sdk::InputSource::Query(
                "SELECT value + CAST(1 AS BIGINT UNSIGNED) AS value, tag, __row_index AS row_index FROM base".into(),
            ),
        },
        sdk::InputPort {
            port: sdk::Port::new(
                "base",
                sdk::Schema::new(vec![
                    sdk::Field::new("value", sdk::DataType::UInt64, false),
                    sdk::Field::new("tag", sdk::DataType::Utf8, false),
                ]),
            ),
            source: sdk::InputSource::Query(
                "SELECT source_cursor AS value, 'sample' AS tag FROM events".into(),
            ),
        },
    ];
    let definition = Fixture::sql(
        r#"SELECT * FROM "fixture"."r1".count(base => (SELECT value, arrow_cast('sample', 'Utf8View') AS tag FROM (VALUES (CAST(10 AS BIGINT UNSIGNED)), (CAST(20 AS BIGINT UNSIGNED)), (CAST(30 AS BIGINT UNSIGNED))) AS supplied(value) ORDER BY value), increment => 2)"#,
    );
    for _ in 0..2 {
        let mut fixture = Fixture::installed(&bundle)?;
        let prepared = fixture.prepare(&definition).await?;
        let calls = Fixture::calls(&prepared.plan)?;
        assert_eq!(calls.len(), 1);
        let slot = bundle.artifacts[0].descriptor.exports[0]
            .inputs
            .iter()
            .position(|input| input.port.name == "source")
            .ok_or("source input absent")?;
        let inputs = calls[0].inputs();
        let middle = bundle.artifacts[0].descriptor.exports[0]
            .inputs
            .iter()
            .position(|input| input.port.name == "middle")
            .ok_or("middle input absent")?;
        assert_eq!(
            inputs[middle]
                .schema()
                .as_arrow()
                .field_with_name("tag")?
                .data_type(),
            &sdk::DataType::Utf8View
        );
        let state = fixture
            .engine
            .catalog(crate::sources::SourceSnapshot::providers())?;
        let batches = collect(
            state.create_physical_plan(inputs[slot]).await?,
            state.task_ctx(),
        )
        .await?;
        let values = batches
            .iter()
            .map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("UInt64 input required")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(
            values
                .into_iter()
                .flat_map(|array| array.iter())
                .collect::<Vec<_>>(),
            vec![Some(22)]
        );
        fixture.engine = Engine::new(
            Arc::clone(fixture.engine.store()),
            Limits {
                projection_columns: Some(3),
                ..Limits::default()
            },
        )?;
        let error = fixture
            .prepare(&definition)
            .await
            .err()
            .ok_or("projection quota ignored")?;
        assert!(snafu::ChainCompat::new(&error).any(|cause| matches!(
            cause.downcast_ref::<datafusion::common::DataFusionError>(),
            Some(datafusion::common::DataFusionError::Plan(message))
                if message == "SQL projection is too wide"
        )));
        bundle.artifacts[0].descriptor.exports[0].inputs.reverse();
    }
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
        assert_eq!(inputs.len(), 7);
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
        assert_eq!(prepared.resolved().images.len(), 1);
        let state = fixture
            .engine
            .catalog(crate::sources::SourceSnapshot::providers())?;
        let mut increments = Vec::new();
        for call in &calls {
            let inputs = call.inputs();
            assert_eq!(inputs.len(), 6);
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
            assert!(calls.iter().any(|call| {
                Fixture::calls(call.inputs()[0]).is_ok_and(|nested| nested.len() == 1)
            }));
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
            program.outputs.insert(
                "result".into(),
                r#"SELECT * FROM "fixture"."r1".count(source => (SELECT value FROM source), increment => 2)"#.into(),
            );
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
        assert_eq!(calls.len(), if export == "count" { 2 } else { 1 });
        let call = calls
            .iter()
            .find(|call| call.export() == export)
            .ok_or("caller export absent")?;
        assert_eq!(call.schema().as_arrow(), &Fixture::schema("value"));
        let inputs = call.inputs();
        assert_eq!(inputs.len(), 2);
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
            let calls = Fixture::calls(&prepared.plan)?;
            assert_eq!(calls.len(), 2);
            let root = calls
                .iter()
                .find(|call| call.export() == "count")
                .ok_or("root call absent")?;
            let nested = calls
                .iter()
                .find(|call| call.export() == "inner")
                .ok_or("nested call absent")?;
            assert_ne!(root.id(), nested.id());
            let children = root.inputs();
            let body_calls = Fixture::calls(children[2])?;
            assert_eq!(body_calls.len(), 1);
            assert_eq!(body_calls[0].id(), nested.id());
            assert_eq!(prepared.resolved().images[0].digest, bundle.digest()?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn unused_call_follows_native() -> TestResult {
    let mut bundle = Fixture::bundle();
    let PackageImplementationV1::Sql { program, .. } = &mut bundle.artifacts[0].implementations[0]
    else {
        return Err("SQL fixture absent".into());
    };
    program.outputs.insert(
        "result".into(),
        "SELECT CAST('wrong' AS BIGINT UNSIGNED) AS value".into(),
    );
    let fixture = Fixture::installed(&bundle)?;
    let called = Fixture::definition();
    let Err(error) = fixture.prepare(&called).await else {
        return Err("called invalid body must fail native optimization".into());
    };
    let message = format!("{error:?}").to_ascii_lowercase();
    assert!(
        message.contains("cast") && message.contains("wrong"),
        "{error:?}"
    );
    let prepared = fixture
        .prepare(&Fixture::sql(format!(
            "WITH unused AS ({}) SELECT CAST(1 AS BIGINT UNSIGNED) AS untouched",
            called.program.sql()?,
        )))
        .await?;
    assert!(Fixture::calls(&prepared.plan)?.is_empty());
    assert!(prepared.sources().contains_key("events"));
    assert_eq!(prepared.resolved().images.len(), 1);
    assert_eq!(prepared.resolved().images[0].image, bundle.root);
    assert_eq!(prepared.resolved().images[0].digest, bundle.digest()?);
    fixture.event(1)?;
    let output = fixture
        .execute(&prepared, execution::invocation("unused-call"))
        .await?;
    assert!(output.calls.is_empty());
    assert_eq!(output.snapshot.page.extraction.sources.len(), 1);
    assert_eq!(
        output.snapshot.page.extraction.sources[0]
            .receipt
            .contiguous_cursor,
        1,
    );
    assert_eq!(
        output
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1,
    );
    let batch = output.batches.first().ok_or("native result absent")?;
    let values = batch
        .column(0)
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("UInt64 result required")?;
    assert_eq!(values.value(0), 1);
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
    assert_eq!(prepared.resolved().images[0].image, Fixture::bundle().root);
    assert!(prepared.resolved().sql.contains(r#""fixture"."r1".count"#));
    let output = fixture
        .execute(&prepared, execution::invocation("prql"))
        .await?;
    assert_eq!(output.calls.len(), 1);
    assert_eq!(
        output
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    Ok(())
}
