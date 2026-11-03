use super::*;
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, SqlModelV1, SqlReasonV1,
};
use datafusion::sql::sqlparser::ast::Value;
use datafusion::{common::ScalarValue, logical_expr::lit, sql::unparser::expr_to_sql};
use sdk::arrow_array::Array;

#[derive(Clone, Copy, Debug)]
pub(super) enum Target {
    Sql,
    Wasm,
    Native,
}

pub(in crate::graph) struct Fixture {
    pub(super) engine: Arc<Engine>,
    store: Arc<AnalysisStore>,
    package: sdk::Package,
    detector: algorithm::Detector,
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
                program: Self::sql(evaluation, expected)?,
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
            detector,
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
        let records = &evaluation.input("records")?.data;
        session.register(
            "graph_records",
            records.batches[0].schema(),
            &records.batches,
        )?;
        let values = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
        let facts =
            algorithm::Fact::encode_source(&values, &algorithm::Observation::decode(records)?)?;
        session.register("graph_facts", facts.batches[0].schema(), &facts.batches)?;
        for (name, data) in [
            ("graph_dirty", &evaluation.input("affected")?.data),
            ("graph_window", &evaluation.input("window")?.data),
        ] {
            session.register(name, data.batches[0].schema(), &data.batches)?;
        }
        let settings = algorithm::Manifest::encode(&[algorithm::Manifest {
            window_ns: GRAPH_WINDOW_NS,
        }])?;
        let mut fields = settings.batches[0].schema().fields().to_vec();
        fields.push(Arc::new(sdk::Field::new(
            "restricted",
            sdk::DataType::Boolean,
            false,
        )));
        let mut columns = settings.batches[0].columns().to_vec();
        columns.push(Arc::new(sdk::arrow_array::BooleanArray::from(vec![values
            .iter()
            .any(|fact| {
                fact.sensitivity == araphor_data::ContextSensitivityV1::HostRestricted
            })])));
        let settings = sdk::RecordBatch::try_new(Arc::new(sdk::Schema::new(fields)), columns)?;
        session.register("graph_settings", settings.schema(), &[settings])?;
        let definition = Definition {
            name: "graph-adapter".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        r#"SELECT * FROM "{}"."{}".detect('subjects',
                units => (SELECT * FROM origin_units))"#,
                        self.package.id, self.package.revision
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition, None).await?;
        let mut call = None;
        PackageCall::any(prepared.plan(), &mut |_, node| {
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
            inputs: BTreeMap::new(),
            previous_outputs: if evaluation.previous_outputs.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(call.id(), evaluation.previous_outputs.clone())])
            },
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
        assert_eq!(Self::inputs(saved)?, Self::inputs(evaluation)?);
        for input in &saved.inputs {
            assert!(!input.revision.owner.is_empty());
            assert!(!input.revision.id.is_empty());
            assert_eq!(input.coverage.state, sdk::CoverageState::Unknown);
        }
        let checked = self.package.check_evaluation(saved)?;
        checked.validate_output(actual.output())?;
        let encoded = checked.encode()?;
        let restored = encoded.decode(&self.package)?;
        let replay = self.package.check_evaluation(&restored)?.encode()?;
        assert_eq!(replay.export_name, encoded.export_name);
        assert_eq!(replay.context, encoded.context);
        assert_eq!(replay.inputs, encoded.inputs);
        assert_eq!(replay.parameters, encoded.parameters);
        assert_eq!(replay.checkpoint, encoded.checkpoint);
        assert_eq!(replay.previous_outputs, encoded.previous_outputs);
        let returned = Self::semantics(saved, actual.output())?;
        assert_eq!(returned, Self::semantics(evaluation, expected)?);
        let trusted = self.detector.evaluate(saved)?;
        assert_eq!(returned, Self::semantics(saved, &trusted)?);
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
                sdk::wire::Output::encode(&self.package, saved, actual.output())?,
                sdk::wire::Output::encode(&self.package, saved, &trusted)?,
            );
        }
        Ok(())
    }

    fn unique<K: Ord, T>(rows: impl IntoIterator<Item = (K, T)>) -> TestResult<BTreeMap<K, T>> {
        let mut values = BTreeMap::new();
        for (key, value) in rows {
            if values.insert(key, value).is_some() {
                return Err("duplicate fixture identity".into());
            }
        }
        Ok(values)
    }

    fn inputs(evaluation: &sdk::Evaluation) -> TestResult<serde_json::Value> {
        let records = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
        let indexed = Self::unique(records.iter().map(|row| (row.id.clone(), row)))?;
        assert_eq!(indexed.len(), records.len());
        let facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
        let facts = Self::unique(
            facts
                .iter()
                .map(|fact| {
                    Ok((
                        fact.key.clone(),
                        (
                            &records
                                .get(fact.record as usize)
                                .ok_or("fixture fact record")?
                                .id,
                            fact.sensitivity,
                            &fact.value,
                        ),
                    ))
                })
                .collect::<TestResult<Vec<_>>>()?,
        )?;
        let mut units = Vec::new();
        for name in ["units", "unit_removals"] {
            let rows = algorithm::Unit::decode(&evaluation.input(name)?.data)?;
            let count = rows.len();
            let rows = Self::unique(rows.into_iter().map(|row| (row.record.clone(), row)))?;
            assert_eq!(rows.len(), count);
            units.push((name, rows.into_values().collect::<Vec<_>>()));
        }
        Ok(serde_json::to_value((
            indexed.into_values().collect::<Vec<_>>(),
            facts.into_iter().collect::<Vec<_>>(),
            units,
            sdk::ChangeInputs {
                reset: "reset".into(),
                ports: Vec::new(),
            }
            .is_reset(evaluation)?,
        ))?)
    }

    fn values<T: serde::Serialize>(rows: impl IntoIterator<Item = T>) -> TestResult<Vec<String>> {
        let mut values = rows
            .into_iter()
            .map(|row| serde_json::to_string(&row))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        values.sort();
        Ok(values)
    }

    fn semantics(
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> TestResult<serde_json::Value> {
        let records = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
        let facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
        let data = |name: &str| {
            output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| Box::<dyn std::error::Error>::from("fixture output absent"))
        };
        let subjects = algorithm::SubjectChange::decode(data("subjects")?)?;
        let edges = algorithm::RelationshipChange::decode(data("relationships")?)?;
        let findings = algorithm::FindingChange::decode(data("findings")?)?;
        let contributions = algorithm::Contribution::decode(data("contributions")?)?;
        let units = algorithm::Unit::decode(&evaluation.input("units")?.data)?;
        algorithm::Contribution::validate(
            &units,
            &records,
            &facts,
            &contributions,
            [subjects.len(), edges.len(), findings.len()],
        )?;
        let mut owners = Vec::new();
        for row in contributions {
            owners.push((
                row.record,
                row.state,
                Self::values(row.subjects.iter().map(|&i| &subjects[i as usize]))?,
                Self::values(row.relationships.iter().map(|&i| &edges[i as usize]))?,
                Self::values(row.findings.iter().map(|&i| &findings[i as usize]))?,
            ));
        }
        owners.sort_by(|a, b| a.0.cmp(&b.0));
        let record = |row: u64| {
            records
                .get(row as usize)
                .map(|record| record.id.clone())
                .ok_or_else(|| Box::<dyn std::error::Error>::from("fixture record coordinate"))
        };
        let context = |row: u32| -> TestResult<_> {
            let fact = facts.get(row as usize).ok_or("fixture fact coordinate")?;
            Ok((fact.key.clone(), record(u64::from(fact.record))?))
        };
        let finding = |reference: &sdk::RowRef| -> TestResult<_> {
            if reference.dataset != "findings" {
                return Err("fixture output coordinate".into());
            }
            Ok(serde_json::to_string(
                findings
                    .get(reference.row as usize)
                    .ok_or("fixture finding coordinate")?,
            )?)
        };
        let evidence = output
            .evidence
            .iter()
            .map(|link| -> TestResult<_> {
                if link.input.dataset != "records" {
                    return Err("fixture evidence dataset".into());
                }
                Ok((finding(&link.output)?, record(link.input.row)?))
            })
            .collect::<TestResult<Vec<_>>>()?;
        let reasons = output
            .reasons
            .iter()
            .map(|reason| -> TestResult<_> {
                let rows = algorithm::ReasonDetails::decode(&sdk::Dataset {
                    name: algorithm::ReasonDetails::port().name,
                    batches: vec![reason.details.clone()],
                })?;
                let [details] = rows.as_slice() else {
                    return Err("fixture reason cardinality".into());
                };
                Ok((
                    finding(&reason.output)?,
                    &reason.code,
                    record(u64::from(details.record))?,
                    details.context.map(context).transpose()?,
                    details.reason.clone(),
                    details.confirmed,
                    details
                        .evidence
                        .iter()
                        .map(|&row| record(u64::from(row)))
                        .collect::<TestResult<Vec<_>>>()?,
                    details.limits.clone(),
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        assert!(output.checkpoint.is_none());
        Ok(serde_json::to_value((
            owners,
            Self::values(evidence)?,
            Self::values(reasons)?,
            algorithm::GraphPackageStateV1::decode(data("state")?)?,
        ))?)
    }

    pub(super) fn graph(
        &self,
        input: &GraphReplayInputV1,
        evaluation: &sdk::Evaluation,
        expected: &sdk::Output,
        call: &PackageCall,
        actual: &CallResult,
    ) -> TestResult<GraphSnapshotV1> {
        let mut graph = Graph::new(input)?;
        graph.apply_output(&self.package, evaluation, expected)?;
        let expected = graph.finish()?;
        let actual = Graph::new(input)?.apply(call, actual)?.finish()?;
        assert_eq!(
            serde_json::to_value(actual)?,
            serde_json::to_value(&expected)?
        );
        Ok(expected)
    }

    pub(super) fn released(&self) -> TestResult {
        assert_eq!(self.engine.memory().input_reserved(), 0);
        let _permit = self.engine.reserve_evaluation(self.tenant)?;
        assert_eq!(self.store.meta()?, self.metadata);
        Ok(())
    }

    pub(in crate::graph::tests) fn sql(
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> TestResult<SqlModelV1> {
        let mut sql = SqlModelV1::default();
        for data in &output.datasets {
            sql.outputs
                .insert(data.name.clone(), Self::rows(&data.batches)?);
        }
        let findings = output
            .datasets
            .iter()
            .find(|data| data.name == "findings")
            .ok_or("fixture findings absent")?;
        let findings = algorithm::FindingChange::decode(findings)?;
        Self::unique(
            findings
                .iter()
                .map(|finding| (&finding.finding_id, finding)),
        )?;
        let records = &evaluation.input("records")?.data;
        let facts = &evaluation.input("facts")?.data;
        let fact_rows = algorithm::Fact::decode(facts)?;
        let finding = |reference: &sdk::RowRef| -> TestResult<String> {
            if reference.dataset != "findings" {
                return Err("fixture output coordinate".into());
            }
            Ok(Value::SingleQuotedString(
                findings
                    .get(reference.row as usize)
                    .ok_or("fixture finding coordinate")?
                    .finding_id
                    .clone(),
            )
            .to_string())
        };
        let refs = "finding_refs AS (SELECT finding_id,min(__row_index) AS row_id,count(*) AS matches FROM output_findings GROUP BY finding_id), record_refs AS (SELECT id,min(__row_index) AS row_id,count(*) AS matches FROM records GROUP BY id)";
        let coordinate = |table: &str, count: u64, kind: &str| {
            format!(
            "arrow_cast(CASE WHEN {table}.matches=1 THEN coalesce({table}.row_id,{count}) ELSE {count} END, '{kind}')")
        };
        let output_row = coordinate("f", findings.len() as u64, "UInt64");
        let record_row = coordinate("r", records.rows(), "UInt32");
        let evidence_row = coordinate("r", records.rows(), "UInt64");
        if !output.evidence.is_empty() {
            let rows = output
                .evidence
                .iter()
                .map(|link| -> TestResult<_> {
                    if link.input.dataset != "records" {
                        return Err("fixture evidence dataset".into());
                    }
                    Ok(format!(
                        "({}, {})",
                        finding(&link.output)?,
                        Self::field(records, "id", Some(link.input.row))?
                    ))
                })
                .collect::<TestResult<Vec<_>>>()?
                .join(", ");
            sql.evidence = Some(format!("WITH {refs} SELECT 'findings' AS output_dataset,{output_row} AS output_row,'records' AS input_dataset,{evidence_row} AS input_row FROM (VALUES {rows}) AS links(finding_id,record_id) LEFT JOIN finding_refs f ON f.finding_id=links.finding_id LEFT JOIN record_refs r ON r.id=links.record_id"));
        }
        let mut reasons = BTreeMap::<_, (String, Vec<String>)>::new();
        let mut seen = std::collections::BTreeSet::new();
        for reason in &output.reasons {
            let data = sdk::Dataset {
                name: algorithm::ReasonDetails::port().name,
                batches: vec![reason.details.clone()],
            };
            let details = algorithm::ReasonDetails::decode(&data)?;
            let [details] = details.as_slice() else {
                return Err("fixture reason cardinality".into());
            };
            let id = finding(&reason.output)?;
            if !seen.insert((id.clone(), reason.code.clone())) {
                return Err("duplicate fixture reason".into());
            }
            let record = Self::field(records, "id", Some(u64::from(details.record)))?;
            let context = Self::field(facts, "key", details.context.map(u64::from))?;
            let owner = details
                .context
                .map(|row| {
                    fact_rows
                        .get(row as usize)
                        .map(|fact| u64::from(fact.record))
                        .ok_or_else(|| {
                            Box::<dyn std::error::Error>::from("fixture fact coordinate")
                        })
                })
                .transpose()?;
            let owner = Self::field(records, "id", owner)?;
            let evidence = details
                .evidence
                .iter()
                .map(|&row| Self::field(records, "id", Some(u64::from(row))))
                .collect::<TestResult<Vec<_>>>()?
                .join(", ");
            let kind = data.batches[0]
                .schema()
                .field_with_name("evidence")?
                .data_type()
                .to_string();
            let rows = reasons
                .entry((reason.output.dataset.clone(), reason.code.clone()))
                .or_insert((kind, Vec::new()));
            rows.1.push(format!(
                "({id},{record},{context},{owner},{},{},make_array({evidence}),{})",
                Self::field(&data, "reason", Some(0))?,
                Self::field(&data, "confirmed", Some(0))?,
                Self::field(&data, "limits", Some(0))?
            ));
        }
        for ((output, code), (kind, rows)) in reasons {
            let context = coordinate("x", facts.rows(), "UInt32");
            let witness = coordinate("r", records.rows(), "UInt32");
            let kind = Value::SingleQuotedString(kind).to_string();
            sql.reasons.push(SqlReasonV1 { output,code,sql:format!(
                "WITH {refs}, details(finding_id,record_id,context_key,context_record,reason,confirmed,evidence,limits) AS (VALUES {}), fact_refs AS (SELECT facts.key,records.id AS record_id,min(facts.__row_index) AS row_id,count(*) AS matches FROM facts LEFT JOIN records ON arrow_cast(facts.record,'UInt64')=records.__row_index GROUP BY facts.key,records.id), wanted AS (SELECT finding_id,UNNEST(evidence) AS id FROM details), witnesses AS (SELECT wanted.finding_id,array_agg({witness} ORDER BY wanted.id) AS evidence FROM wanted LEFT JOIN record_refs r ON r.id=wanted.id GROUP BY wanted.finding_id) SELECT {output_row} AS output_row,{record_row} AS record,CASE WHEN details.context_key IS NULL THEN arrow_cast(NULL,'UInt32') ELSE {context} END AS context,details.reason,details.confirmed,arrow_cast(coalesce(witnesses.evidence,make_array()),{kind}) AS evidence,details.limits FROM details LEFT JOIN finding_refs f ON f.finding_id=details.finding_id LEFT JOIN record_refs r ON r.id=details.record_id LEFT JOIN fact_refs x ON x.key=details.context_key AND x.record_id=details.context_record LEFT JOIN witnesses ON witnesses.finding_id=details.finding_id",
                rows.join(", ")) });
        }
        Ok(sql)
    }

    fn field(data: &sdk::Dataset, name: &str, row: Option<u64>) -> TestResult<String> {
        let mut remaining = match row {
            Some(row) => row,
            None => {
                let schema = data.batches.first().ok_or("fixture input schema")?.schema();
                return Ok(format!(
                    "arrow_cast(NULL, {})",
                    Value::SingleQuotedString(
                        schema.field_with_name(name)?.data_type().to_string()
                    )
                ));
            }
        };
        for batch in &data.batches {
            if remaining < batch.num_rows() as u64 {
                return Self::literal(
                    batch.column_by_name(name).ok_or("fixture column")?.as_ref(),
                    remaining as usize,
                );
            }
            remaining -= batch.num_rows() as u64;
        }
        Err("fixture coordinate is out of range".into())
    }

    pub(in crate::graph) fn rows(batches: &[sdk::RecordBatch]) -> TestResult<String> {
        let schema = batches.first().ok_or("native output schema")?.schema();
        let mut values = Vec::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                let fields = batch
                    .columns()
                    .iter()
                    .map(|column| Self::literal(column.as_ref(), row))
                    .collect::<TestResult<Vec<_>>>()?;
                values.push(format!("({})", fields.join(", ")));
            }
        }
        let names = schema
            .fields()
            .iter()
            .map(|field| {
                datafusion::sql::sqlparser::ast::Ident::with_quote('"', field.name()).to_string()
            })
            .collect::<Vec<_>>();
        Ok(if values.is_empty() {
            let fields = schema
                .fields()
                .iter()
                .zip(&names)
                .map(|(field, name)| {
                    format!(
                        "arrow_cast(NULL, {}) AS {name}",
                        Value::SingleQuotedString(field.data_type().to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("SELECT {fields} WHERE FALSE")
        } else {
            format!(
                "SELECT * FROM (VALUES {}) AS rows({})",
                values.join(", "),
                names.join(", ")
            )
        })
    }

    pub(in crate::graph) fn literal(array: &dyn Array, row: usize) -> TestResult<String> {
        let kind = Value::SingleQuotedString(array.data_type().to_string());
        if array.is_null(row) {
            return Ok(format!("arrow_cast(NULL, {kind})"));
        }
        let value = ScalarValue::try_from_array(array, row)?;
        let expression = match value {
            ScalarValue::Binary(Some(bytes))
            | ScalarValue::LargeBinary(Some(bytes))
            | ScalarValue::BinaryView(Some(bytes))
            | ScalarValue::FixedSizeBinary(_, Some(bytes)) => {
                Value::HexStringLiteral(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
                    .to_string()
            }
            ScalarValue::Struct(array) => {
                let mut fields = Vec::new();
                for (field, column) in array.fields().iter().zip(array.columns()) {
                    fields.push(Value::SingleQuotedString(field.name().clone()).to_string());
                    fields.push(Self::literal(column.as_ref(), 0)?);
                }
                return Ok(format!("named_struct({})", fields.join(", ")));
            }
            ScalarValue::List(array) => {
                let values = array.value(0);
                let fields = (0..values.len())
                    .map(|row| Self::literal(values.as_ref(), row))
                    .collect::<TestResult<Vec<_>>>()?;
                format!("make_array({})", fields.join(", "))
            }
            ScalarValue::LargeList(array) => {
                let values = array.value(0);
                let fields = (0..values.len())
                    .map(|row| Self::literal(values.as_ref(), row))
                    .collect::<TestResult<Vec<_>>>()?;
                format!("make_array({})", fields.join(", "))
            }
            ScalarValue::FixedSizeList(array) => {
                let values = array.value(0);
                let fields = (0..values.len())
                    .map(|row| Self::literal(values.as_ref(), row))
                    .collect::<TestResult<Vec<_>>>()?;
                format!("make_array({})", fields.join(", "))
            }
            value => expr_to_sql(&lit(value))?.to_string(),
        };
        Ok(format!("arrow_cast({expression}, {kind})"))
    }
}

#[test]
fn native_input_coordinates() -> TestResult {
    let input = super::fixture::credential_input()?.normalized()?;
    for detector in super::detectors() {
        let evaluation = super::evaluation(&input, detector)?;
        let expected = detector.evaluate(&evaluation)?;
        let records = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
        let mut delivered = records.clone();
        delivered.reverse();
        let mut facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
        for fact in &mut facts {
            let id = &records[fact.record as usize].id;
            fact.record = delivered
                .iter()
                .position(|record| &record.id == id)
                .ok_or("fixture record absent")? as u32;
        }
        facts.reverse();
        let mut units = algorithm::Unit::decode(&evaluation.input("units")?.data)?;
        units.reverse();
        let mut actual = evaluation.clone();
        for data in [
            algorithm::Observation::encode(&delivered)?,
            algorithm::Fact::encode(&facts)?,
            algorithm::Unit::encode(&units)?,
        ] {
            let input = actual
                .inputs
                .iter_mut()
                .find(|input| input.data.name == data.name)
                .ok_or("fixture input absent")?;
            input.data = data;
        }
        assert_eq!(Fixture::inputs(&actual)?, Fixture::inputs(&evaluation)?);
        assert_eq!(
            Fixture::semantics(&actual, &detector.evaluate(&actual)?)?,
            Fixture::semantics(&evaluation, &expected)?
        );
        for kind in ["records", "facts", "units"] {
            let mut duplicate = actual.clone();
            let data = match kind {
                "records" => {
                    let mut rows = delivered.clone();
                    rows.push(rows[0].clone());
                    algorithm::Observation::encode(&rows)?
                }
                "facts" => {
                    let mut rows = facts.clone();
                    rows.push(rows[0].clone());
                    algorithm::Fact::encode(&rows)?
                }
                _ => {
                    let mut rows = units.clone();
                    rows.push(rows[0].clone());
                    algorithm::Unit::encode(&rows)?
                }
            };
            duplicate
                .inputs
                .iter_mut()
                .find(|input| input.data.name == kind)
                .ok_or("fixture input absent")?
                .data = data;
            assert!(Fixture::inputs(&duplicate).is_err(), "duplicate {kind}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn sql_preserves_invalid_metadata() -> TestResult {
    let detector = algorithm::Detector::Process;
    let input = super::selected(detector)?.normalized()?;
    let evaluation = super::evaluation(&input, detector)?;
    let expected = detector.evaluate(&evaluation)?;
    for fault in 0..4 {
        let mut output = expected.clone();
        let reason = output.reasons.first_mut().ok_or("fixture reason absent")?;
        let mut details = algorithm::ReasonDetails::decode(&sdk::Dataset {
            name: algorithm::ReasonDetails::port().name,
            batches: vec![reason.details.clone()],
        })?;
        match fault {
            0 => details[0].reason = "INTENTIONAL_MISMATCH".into(),
            1 => details[0].confirmed = !details[0].confirmed,
            2 => details[0].limits.push("INTENTIONAL_MISMATCH".into()),
            _ => {
                reason.code = detector.descriptor().exports[0]
                    .reasons
                    .iter()
                    .find(|candidate| candidate.code != reason.code)
                    .ok_or("alternate reason absent")?
                    .code
                    .clone();
            }
        }
        reason.details = algorithm::ReasonDetails::encode(&details)?
            .batches
            .remove(0);
        let fixture = Fixture::new(detector, Target::Sql, &evaluation, &output, None)?;
        let (call, returned) = fixture.run(&evaluation).await?;
        let result = returned
            .calls
            .get(&call.id())
            .ok_or("fixture call absent")?;
        assert!(
            Graph::new(&input)?.apply(&call, result).is_err(),
            "repaired metadata fault {fault}"
        );
        drop(returned);
        drop(call);
        fixture.released()?;
    }
    Ok(())
}
