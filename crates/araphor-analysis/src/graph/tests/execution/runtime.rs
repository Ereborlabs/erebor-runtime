use super::*;
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageFixtureV1, PackageImplementationV1, SqlModelV1,
    SqlReasonV1,
};
use datafusion::sql::sqlparser::ast::Value;
use sdk::arrow_array::{Array as _, BinaryArray};

#[derive(Clone, Copy, Debug)]
pub(super) enum Target {
    Sql,
    Wasm,
    Native,
}

pub(super) struct Fixture {
    pub(super) engine: Arc<Engine>,
    store: Arc<AnalysisStore>,
    package: sdk::Package,
    target: Target,
    tenant: [u8; 16],
    metadata: araphor_data::AnalysisStoreMetaV1,
    _directory: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn new(
        detector: algorithm::Detector,
        target: Target,
        evaluation: &sdk::Evaluation,
        expected: &sdk::Output,
        output: Option<usize>,
    ) -> TestResult<Self> {
        let package = detector.descriptor();
        let (filename, wasm) = match detector {
            algorithm::Detector::Process => {
                ("process", araphor_analysis_builtins::components::PROCESS)
            }
            algorithm::Detector::Credentials => (
                "credentials",
                araphor_analysis_builtins::components::CREDENTIALS,
            ),
            algorithm::Detector::Kubernetes => (
                "kubernetes",
                araphor_analysis_builtins::components::KUBERNETES,
            ),
        };
        let implementation = match target {
            Target::Sql => PackageImplementationV1::Sql {
                export: "detect".into(),
                program: Self::sql(expected)?,
            },
            Target::Wasm => PackageImplementationV1::Wasm {
                exports: vec!["detect".into()],
                artifact: wasm.to_vec(),
            },
            Target::Native => {
                let directory = std::env::var_os("ARAPHOR_NATIVE_DIR")
                    .ok_or("ARAPHOR_NATIVE_DIR is required")?;
                let artifact = std::fs::read(
                    std::path::PathBuf::from(directory)
                        .join(format!("{filename}.{}", std::env::consts::DLL_EXTENSION)),
                )?;
                let qualification = araphor_data::native::Qualification::inspect(
                    &artifact,
                    vec!["detect".into()],
                    std::env::var("ARAPHOR_NATIVE_TARGET")?,
                )?;
                PackageImplementationV1::Native {
                    export: "detect".into(),
                    artifact,
                    qualification: Some(qualification),
                }
            }
        };
        assert_eq!(
            implementation.target(),
            match target {
                Target::Sql => "sql",
                Target::Wasm => "wasm",
                Target::Native => "native",
            }
        );
        assert_eq!(
            implementation.identity()?.is_some(),
            !matches!(target, Target::Sql)
        );
        let artifact = PackageArtifactV1 {
            descriptor: package.clone(),
            implementations: vec![implementation],
            fixtures: Vec::new(),
        };
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        };
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let tenant = super::fixture::source().tenant_id;
        store.install_package_image(
            tenant,
            &araphor_package::PackageBundle::try_from(bundle)?,
            || Ok(()),
        )?;
        let engine = Engine::new(
            Arc::clone(&store),
            Limits {
                output_capacity: output,
                global_evaluations: Some(1),
                evaluate_timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        )?;
        package
            .check_evaluation(evaluation)?
            .validate_output(expected)?;
        let metadata = store.meta()?;
        Ok(Self {
            engine,
            store,
            package,
            target,
            tenant,
            metadata,
            _directory: directory,
        })
    }

    pub(super) async fn run(
        &self,
        evaluation: &sdk::Evaluation,
    ) -> TestResult<(PackageCall, DefinitionOutput)> {
        let mut session = self.engine.session(
            AnalysisSelectionV1::tenant(self.tenant),
            &AnalysisReadControl::default(),
            u64::try_from(evaluation.context.time_utc_ns)?,
        )?;
        for input in &evaluation.inputs {
            let schema = input.data.batches.first().ok_or("input schema")?.schema();
            session.register(
                &format!("origin_{}", input.data.name),
                schema,
                &input.data.batches,
            )?;
        }
        let definition = Definition {
            name: "graph-adapter".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        r#"SELECT * FROM "{}"."{}".detect('subjects',
                records => (SELECT * FROM origin_records),
                facts => (SELECT * FROM origin_facts),
                manifest => (SELECT * FROM origin_manifest))"#,
                        self.package.id, self.package.revision
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let mut call = None;
        PackageCall::any(&prepared.plan, &mut |node| {
            call = Some(node.clone());
            Ok(true)
        })?;
        let call = call.ok_or("admitted graph call")?;
        assert_eq!(call.descriptor(), &self.package);
        assert_eq!(call.image().image.package_id, self.package.id);
        assert_eq!(call.export(), evaluation.export);
        assert_eq!(prepared.images().count(), 1);
        let invocation = Invocation {
            id: evaluation.context.id.clone(),
            seed: evaluation.context.seed,
            time_utc_ns: Some(evaluation.context.time_utc_ns),
            inputs: BTreeMap::from([(call.id(), evaluation.inputs.clone())]),
            checkpoints: evaluation
                .checkpoint
                .clone()
                .map(|checkpoint| BTreeMap::from([(call.id(), checkpoint)]))
                .unwrap_or_default(),
        };
        let output = session.execute_definition(&prepared, invocation).await?;
        assert_eq!(output.calls.len(), 1);
        assert!(output
            .calls
            .get(&call.id())
            .ok_or("native call result")?
            .belongs_to(&call));
        Ok((call, output))
    }

    pub(super) fn compare(
        &self,
        evaluation: &sdk::Evaluation,
        expected: &sdk::Output,
        actual: &CallResult,
    ) -> TestResult {
        let saved = actual.evaluation();
        assert_eq!(saved.export, evaluation.export);
        assert_eq!(saved.context, evaluation.context);
        assert_eq!(saved.parameters, evaluation.parameters);
        assert_eq!(saved.inputs.len(), evaluation.inputs.len());
        for input in &evaluation.inputs {
            let stored = saved.input(&input.data.name)?;
            assert_eq!(stored.data.batches, input.data.batches);
            assert_eq!(stored.revision, input.revision);
            assert_eq!(stored.coverage, input.coverage);
        }
        let checked = self.package.check_evaluation(evaluation)?.encode()?;
        assert_eq!(
            self.package.check_evaluation(saved)?.encode()?.checkpoint,
            checked.checkpoint
        );
        let fixture = PackageFixtureV1 {
            name: "graph-native-return".into(),
            export: evaluation.export.clone(),
            time_utc_ns: evaluation.context.time_utc_ns,
            seed: evaluation.context.seed,
            inputs: checked.inputs,
            parameters: None,
            checkpoint: checked.checkpoint,
            expected: sdk::wire::Output::encode(&self.package, evaluation, expected)?,
        };
        assert!(fixture.compare_output(&self.package, saved, actual.output())?);
        assert_eq!(
            actual.output().datasets.len(),
            self.package.exports[0].outputs.len()
        );
        for data in &actual.output().datasets {
            let port = self.package.exports[0]
                .outputs
                .iter()
                .find(|port| port.name == data.name)
                .ok_or("declared output")?;
            assert!(!data.batches.is_empty());
            assert!(data
                .batches
                .iter()
                .all(|batch| batch.schema().as_ref() == &port.schema));
        }
        if !matches!(self.target, Target::Sql) {
            assert_eq!(
                serde_json::to_value(sdk::wire::Output::encode(
                    &self.package,
                    evaluation,
                    actual.output()
                )?)?,
                serde_json::to_value(fixture.expected)?
            );
        }
        Ok(())
    }

    pub(super) fn released(&self) -> TestResult {
        assert_eq!(self.engine.memory().input_reserved(), 0);
        let _permit = self.engine.reserve_evaluation(self.tenant)?;
        assert_eq!(self.store.meta()?, self.metadata);
        Ok(())
    }

    fn sql(output: &sdk::Output) -> TestResult<SqlModelV1> {
        let mut sql = SqlModelV1::default();
        for data in &output.datasets {
            sql.outputs
                .insert(data.name.clone(), Self::rows(&data.batches)?);
        }
        if let Some(checkpoint) = &output.checkpoint {
            for data in &checkpoint.datasets {
                sql.checkpoint
                    .insert(data.name.clone(), Self::rows(&data.batches)?);
            }
        }
        if !output.evidence.is_empty() {
            let rows = output
                .evidence
                .iter()
                .map(|link| {
                    format!(
                        "({}, CAST({} AS BIGINT UNSIGNED), {}, CAST({} AS BIGINT UNSIGNED))",
                        Value::SingleQuotedString(link.output.dataset.clone()),
                        link.output.row,
                        Value::SingleQuotedString(link.input.dataset.clone()),
                        link.input.row,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            sql.evidence = Some(format!("SELECT * FROM (VALUES {rows}) AS links(output_dataset, output_row, input_dataset, input_row)"));
        }
        let mut reasons = BTreeMap::<_, Vec<_>>::new();
        for reason in &output.reasons {
            reasons
                .entry((reason.output.dataset.clone(), reason.code.clone()))
                .or_default()
                .push(format!(
                    "(CAST({} AS BIGINT UNSIGNED), CAST({} AS BYTEA))",
                    reason.output.row,
                    Self::literal(&reason.details, 0)?,
                ));
        }
        for ((output, code), rows) in reasons {
            sql.reasons.push(SqlReasonV1 {
                output,
                code,
                sql: format!(
                    "SELECT * FROM (VALUES {}) AS details(output_row, value)",
                    rows.join(", ")
                ),
            });
        }
        Ok(sql)
    }

    fn rows(batches: &[sdk::RecordBatch]) -> TestResult<String> {
        let mut values = Vec::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                values.push(format!("(CAST({} AS BYTEA))", Self::literal(batch, row)?));
            }
        }
        Ok(if values.is_empty() {
            "SELECT value FROM records WHERE FALSE".into()
        } else {
            format!(
                "SELECT * FROM (VALUES {}) AS rows(value)",
                values.join(", ")
            )
        })
    }

    fn literal(batch: &sdk::RecordBatch, row: usize) -> TestResult<Value> {
        let array = batch
            .column(0)
            .as_any()
            .downcast_ref::<BinaryArray>()
            .ok_or("Rows Binary field")?;
        assert_eq!(array.null_count(), 0);
        Ok(Value::SingleQuotedString(
            std::str::from_utf8(array.value(row))?.into(),
        ))
    }
}
