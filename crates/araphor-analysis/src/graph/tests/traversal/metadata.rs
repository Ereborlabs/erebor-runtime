use super::*;

use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1};
use araphor_query::datafusion::arrow::array::{BooleanArray, StringArray, UInt64Array};
use araphor_query::datafusion::arrow::compute::concat_batches;
use araphor_query::definition::{DefinitionOutput, Invocation};

const GRAPH_PORTS: [&str; 3] = ["graph_subjects", "relationships", "graph_manifest"];

impl TraversalFixture {
    fn metadata_engine(&self) -> TestResult<Arc<Engine>> {
        let schemas = AnalysisStore::table_schemas();
        let mut inputs = Vec::new();
        for (name, fields) in [
            (
                "graph_subjects",
                "graph_result_id, subject_id, graph_sensitivity, traversal_depth",
            ),
            (
                "relationships",
                "graph_result_id, from_subject_id, to_subject_id, graph_sensitivity",
            ),
            (
                "graph_manifest",
                "graph_result_id, graph_sensitivity, previous_result_id, subject_count, relationship_count, max_hops, hop_boundary",
            ),
            ("events", "source_cursor"),
        ] {
            let fields = fields
                .split(", ")
                .map(|field| schemas[name].field_with_name(field).cloned())
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let columns = fields
                .iter()
                .map(|field| field.name().as_str())
                .collect::<Vec<_>>()
                .join(", ");
            inputs.push(sdk::InputPort {
                port: sdk::Port::new(name, sdk::Schema::new(fields)),
                source: sdk::InputSource::Query(format!("SELECT {columns} FROM {name}")),
            });
        }
        inputs.push(sdk::InputPort {
            port: sdk::Port::new(
                "local_rows",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
            ),
            source: sdk::InputSource::Query("SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into()),
        });
        let mut outputs = inputs
            .iter()
            .map(|input| input.port.clone())
            .collect::<Vec<_>>();
        outputs.push(sdk::Port::new(
            "metadata",
            sdk::Schema::new(
                ["dataset", "revision", "coverage"]
                    .into_iter()
                    .map(|name| sdk::Field::new(name, sdk::DataType::Utf8, false))
                    .collect::<Vec<_>>(),
            ),
        ));
        let mut model = sdk::Model::new("echo-inputs", Vec::new(), outputs);
        model.inputs = inputs;
        model.input_mode = sdk::InputMode::Resolved;
        let artifact = PackageArtifactV1 {
            descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["echo-inputs".into()],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            }],
            fixtures: Vec::new(),
        };
        self.store.install_package_image(
            source().tenant_id,
            &araphor_data::PackageBundle::try_from(PackageBundleV1 {
                schema_version: 1,
                root: artifact.reference(),
                artifacts: vec![artifact],
            })?,
            || Ok(()),
        )?;
        Ok(Engine::new(
            Arc::clone(&self.store),
            Limits {
                input_capacity: Some(64 * 1024 * 1024),
                ..Default::default()
            },
        )?)
    }

    fn metadata_selection(&self, request: GraphTraversalV1) -> TestResult<AnalysisSelectionV1> {
        let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
        selection.select_graphs(Selection::All, Some(request))?;
        Ok(selection)
    }

    async fn metadata(
        &self,
        engine: &Arc<Engine>,
        selection: AnalysisSelectionV1,
    ) -> TestResult<DefinitionOutput> {
        let control = AnalysisReadControl::default();
        let session = engine.session(selection, &control, 100)?;
        let prepared = session
            .prepare_definition(&Definition {
                name: "graph-input-metadata".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: r#"SELECT * FROM "runtime-fixture"."1"."echo-inputs"('metadata')"#
                            .into(),
                    },
                },
            })
            .await?;
        let output = session
            .execute_definition(&prepared, Invocation::default())
            .await?;
        assert_eq!(output.calls.len(), 1);
        assert_eq!(
            output.snapshot.page.extraction.meta.commit_revision,
            self.store.meta()?.commit_revision
        );
        Ok(output)
    }

    fn metadata_replace(
        &self,
        window: usize,
        mut snapshot: GraphSnapshotV1,
        id: &str,
    ) -> TestResult {
        snapshot.graph.revision.clone_from(&snapshot.input_manifest);
        for finding in &mut snapshot.findings {
            finding.revision.clone_from(&snapshot.input_manifest);
        }
        self.replace(window, snapshot, id)
    }
}

fn input_data<'a>(output: &'a DefinitionOutput, name: &str) -> TestResult<&'a sdk::Input> {
    output
        .calls
        .values()
        .next()
        .ok_or("the echo call is absent")?
        .evaluation()
        .inputs
        .iter()
        .find(|input| input.data.name == name)
        .ok_or_else(|| format!("the {name} input is absent").into())
}

fn input_batch(output: &DefinitionOutput, name: &str) -> TestResult<RecordBatch> {
    let data = &input_data(output, name)?.data;
    let schema = data
        .batches
        .first()
        .ok_or("the input schema is absent")?
        .schema();
    Ok(concat_batches(&schema, &data.batches)?)
}

fn expect_metadata(
    output: &DefinitionOutput,
    state: sdk::CoverageState,
    reasons: &[&str],
) -> TestResult {
    let call = output
        .calls
        .values()
        .next()
        .ok_or("the echo call is absent")?;
    let evaluation = call.evaluation();
    assert_eq!(evaluation.export, "echo-inputs");
    assert_eq!(evaluation.inputs.len(), 5);
    let metadata = call
        .output()
        .datasets
        .iter()
        .find(|data| data.name == "metadata")
        .ok_or("the echoed metadata is absent")?;
    let schema = metadata
        .batches
        .first()
        .ok_or("the metadata schema is absent")?
        .schema();
    let metadata = concat_batches(&schema, &metadata.batches)?;
    assert_eq!(metadata.num_rows(), evaluation.inputs.len());
    let strings = |column| -> TestResult<&StringArray> {
        metadata
            .column(column)
            .as_any()
            .downcast_ref()
            .ok_or_else(|| "the metadata column is invalid".into())
    };
    let (names, revisions, coverage) = (strings(0)?, strings(1)?, strings(2)?);
    let expected = sdk::Coverage {
        state,
        limits: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
    };
    for input in &evaluation.inputs {
        let name = input.data.name.as_str();
        assert!(!input.revision.owner.is_empty() && !input.revision.id.is_empty());
        assert!(input.revision.window.is_none());
        if GRAPH_PORTS.contains(&name) {
            assert_eq!(input.coverage, expected, "{name}");
        } else {
            assert_eq!(input.coverage.state, sdk::CoverageState::Unknown, "{name}");
            assert!(
                input
                    .coverage
                    .limits
                    .iter()
                    .all(|reason| !reason.contains("GRAPH")),
                "{name}"
            );
        }
        let row = (0..metadata.num_rows())
            .find(|row| names.value(*row) == name)
            .ok_or("the input metadata row is absent")?;
        assert_eq!(
            serde_json::from_str::<sdk::Revision>(revisions.value(row))?,
            input.revision
        );
        assert_eq!(
            serde_json::from_str::<sdk::Coverage>(coverage.value(row))?,
            input.coverage
        );
        let echoed = call
            .output()
            .datasets
            .iter()
            .find(|data| data.name == name)
            .ok_or("the echoed input is absent")?;
        let schema = input
            .data
            .batches
            .first()
            .ok_or("the input schema is absent")?
            .schema();
        assert!(echoed.batches.iter().all(|batch| batch.schema() == schema));
        assert_eq!(
            concat_batches(&schema, &echoed.batches)?,
            concat_batches(&schema, &input.data.batches)?,
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn graph_metadata_roundtrip() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let engine = fixture.metadata_engine()?;
    let selection = fixture.metadata_selection(TraversalFixture::request(8))?;
    let original = GraphSnapshotV1::try_from(fixture.requests[0].body.as_slice())?;
    let baseline = fixture.metadata(&engine, selection.clone()).await?;
    expect_metadata(&baseline, sdk::CoverageState::Complete, &[])?;
    assert!(input_batch(&baseline, "graph_subjects")?.num_rows() > 0);
    assert!(input_batch(&baseline, "relationships")?.num_rows() > 0);
    let mut full = selection.clone();
    full.select_graphs(Selection::All, None)?;
    let output = fixture.metadata(&engine, full).await?;
    expect_metadata(&output, sdk::CoverageState::Complete, &[])?;
    assert!(output.snapshot.page.extraction.graph_traversal().is_none());
    for request in &fixture.requests {
        assert_eq!(
            output
                .snapshot
                .page
                .extraction
                .graph_coverage(&request.result_id),
            Some(&sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            })
        );
    }
    drop(output);
    let stable = fixture.metadata(&engine, selection.clone()).await?;
    for name in [
        "graph_subjects",
        "relationships",
        "graph_manifest",
        "events",
        "local_rows",
    ] {
        assert_eq!(
            input_data(&baseline, name)?.revision,
            input_data(&stable, name)?.revision,
            "{name}"
        );
    }
    drop(stable);
    let subjects = input_data(&baseline, "graph_subjects")?
        .data
        .batches
        .iter()
        .find(|batch| batch.num_rows() > 0)
        .ok_or("the subject batch is absent")?;
    let held = subjects
        .column_by_name("subject_id")
        .ok_or("the subject column is absent")?
        .to_data()
        .buffers()[1]
        .clone();
    drop(baseline);
    assert!(engine.memory().input_reserved() > 0);
    drop(held);
    assert_eq!(engine.memory().input_reserved(), 0);

    let mut unknown = original.clone();
    unknown.input_manifest.coverage.clear();
    fixture.metadata_replace(0, unknown, "graph:metadata:unknown")?;
    let output = fixture.metadata(&engine, selection.clone()).await?;
    expect_metadata(&output, sdk::CoverageState::Unknown, &[])?;
    let previous = input_data(&output, "graph_subjects")?.revision.clone();
    drop(output);
    let mut gapped = original.clone();
    gapped.input_manifest.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    gapped.input_manifest.coverage[0].gap_reasons = vec![
        "Z_GRAPH_GAP".into(),
        "A_GRAPH_GAP".into(),
        "A_GRAPH_GAP".into(),
    ];
    let mut unknown = GraphSnapshotV1::try_from(fixture.requests[1].body.as_slice())?;
    unknown.input_manifest.coverage.clear();
    fixture.metadata_replace(1, unknown, "graph:metadata:other-unknown")?;
    fixture.metadata_replace(0, gapped, "graph:metadata:gapped")?;
    let output = fixture.metadata(&engine, selection.clone()).await?;
    expect_metadata(
        &output,
        sdk::CoverageState::Gapped,
        &["A_GRAPH_GAP", "Z_GRAPH_GAP"],
    )?;
    assert_ne!(input_data(&output, "graph_subjects")?.revision, previous);
    drop(output);

    let mut missing = original.clone();
    missing.missing_ranges = vec![(99, 99)];
    missing
        .input_manifest
        .missing_ranges
        .clone_from(&missing.missing_ranges);
    fixture.metadata_replace(0, missing, "graph:metadata:missing")?;
    let output = fixture.metadata(&engine, selection.clone()).await?;
    expect_metadata(&output, sdk::CoverageState::Gapped, &["GRAPH_INPUT_GAPS"])?;
    drop(output);
    let boundary = fixture.metadata_selection(TraversalFixture::request(0))?;
    let output = fixture.metadata(&engine, boundary.clone()).await?;
    expect_metadata(
        &output,
        sdk::CoverageState::Gapped,
        &["GRAPH_HOP_BOUNDARY", "GRAPH_INPUT_GAPS"],
    )?;
    assert!(
        output
            .snapshot
            .page
            .extraction
            .graph_traversal()
            .ok_or("the traversal receipt is absent")?
            .hop_boundary
    );
    drop(output);
    fixture.metadata_replace(0, original, "graph:metadata:healthy")?;
    let restored = GraphSnapshotV1::try_from(fixture.requests[1].body.as_slice())?;
    fixture.metadata_replace(1, restored, "graph:metadata:other-healthy")?;
    let output = fixture.metadata(&engine, boundary).await?;
    expect_metadata(
        &output,
        sdk::CoverageState::Unknown,
        &["GRAPH_HOP_BOUNDARY"],
    )?;
    let manifest = input_batch(&output, "graph_manifest")?;
    let hops = manifest
        .column_by_name("max_hops")
        .ok_or("the hop count is absent")?
        .as_any()
        .downcast_ref::<UInt32Array>()
        .ok_or("the hop count is invalid")?;
    let boundary = manifest
        .column_by_name("hop_boundary")
        .ok_or("the hop boundary is absent")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or("the hop boundary is invalid")?;
    assert!(hops.values().iter().all(|hops| *hops == 0));
    assert!((0..boundary.len()).all(|row| boundary.value(row)));
    Ok(())
}

#[tokio::test]
async fn graph_metadata_empty_scope() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let engine = fixture.metadata_engine()?;
    let mut snapshot = GraphSnapshotV1::try_from(fixture.requests[0].body.as_slice())?;
    let mut selection = fixture.metadata_selection(TraversalFixture::request(8))?;
    selection.select_graphs(
        Selection::Exact(vec![fixture.requests[0].result_id.clone()]),
        Some(TraversalFixture::request(8)),
    )?;
    let output = fixture.metadata(&engine, selection.clone()).await?;
    expect_metadata(&output, sdk::CoverageState::Complete, &[])?;
    for name in GRAPH_PORTS {
        let batch = input_batch(&output, name)?;
        let sensitivity = batch
            .column_by_name("graph_sensitivity")
            .ok_or("the graph sensitivity is absent")?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("the graph sensitivity is invalid")?;
        assert!(batch.num_rows() > 0);
        assert!((0..sensitivity.len()).all(|row| sensitivity.value(row) == "tenant"));
    }
    drop(output);
    let mut denied = selection.clone();
    denied.sources = Selection::Exact(Vec::new());
    let error = fixture
        .metadata(&engine, denied)
        .await
        .err()
        .ok_or("the ungranted graph source was admitted")?;
    assert!(matches!(
        TraversalFixture::data_error(error.as_ref()),
        Some(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    let mut unselected = selection.clone();
    unselected.binding_ids = vec![[99; 16]];
    let output = fixture.metadata(&engine, unselected).await?;
    expect_metadata(
        &output,
        sdk::CoverageState::Unknown,
        &["NO_SELECTED_GRAPH_VERSION"],
    )?;
    assert!(output
        .snapshot
        .page
        .extraction
        .graph_traversal()
        .ok_or("the traversal receipt is absent")?
        .result_ids
        .is_empty());
    for name in GRAPH_PORTS {
        assert_eq!(input_batch(&output, name)?.num_rows(), 0);
    }
    drop(output);

    snapshot.graph.subjects.clear();
    snapshot.graph.edges.clear();
    snapshot.findings.clear();
    fixture.metadata_replace(0, snapshot, "graph:metadata:empty")?;
    selection.select_graphs(
        Selection::Exact(vec!["graph:metadata:empty".into()]),
        Some(TraversalFixture::request(8)),
    )?;
    let (captured, rows) = fixture
        .selected(
            TraversalFixture::request(8),
            selection.clone(),
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
        .await?;
    assert_eq!(rows.iter().map(RecordBatch::num_rows).sum::<usize>(), 0);
    assert_eq!(
        captured
            .page
            .extraction
            .graph_coverage("graph:metadata:empty"),
        Some(&sdk::Coverage {
            state: sdk::CoverageState::Complete,
            limits: Vec::new(),
        })
    );
    drop((captured, rows));
    let output = fixture.metadata(&engine, selection).await?;
    expect_metadata(&output, sdk::CoverageState::Complete, &[])?;
    assert_eq!(input_batch(&output, "graph_subjects")?.num_rows(), 0);
    assert_eq!(input_batch(&output, "relationships")?.num_rows(), 0);
    let manifest = input_batch(&output, "graph_manifest")?;
    assert_eq!(manifest.num_rows(), 1);
    for field in ["subject_count", "relationship_count"] {
        let counts = manifest
            .column_by_name(field)
            .ok_or("the graph count is absent")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("the graph count is invalid")?;
        assert_eq!(counts.value(0), 0);
    }
    let previous = manifest
        .column_by_name("previous_result_id")
        .ok_or("the previous result is absent")?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("the previous result is invalid")?;
    assert_eq!(previous.value(0), fixture.requests[0].result_id);
    Ok(())
}
