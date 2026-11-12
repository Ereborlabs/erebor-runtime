use super::*;
use crate::analysis::graph_rows::{tests::fixture::CommitFixture, GraphRows};

fn fixture() -> TestResult<(CommitFixture, Fixture)> {
    let graph = CommitFixture::new()?;
    let source = graph.snapshot.scope.identity.clone();
    let mut fixture = Fixture::admit_scope(
        &graph.store,
        false,
        AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]),
    )?;
    let mut spec = fixture.instance.spec.clone();
    spec.id = "graph-prefix".into();
    spec.destination = ManagedDestination::Graph {
        source,
        calls: BTreeSet::from([10, 11, 13]),
        operation: ManagedGraphOperation::Evaluate,
        events_sql: "SELECT * FROM events".into(),
        control_sql: "SELECT * FROM graph_state".into(),
    };
    let descriptor = araphor_analysis_builtins::graph::Detector::Process.descriptor();
    let export = descriptor.exports[0].name.clone();
    let artifact = PackageArtifactV1 {
        descriptor,
        implementations: vec![PackageImplementationV1::Sql {
            export: export.clone(),
            program: SqlModelV1::default(),
        }],
        fixtures: Vec::new(),
    };
    let image = crate::PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    })?;
    graph
        .store
        .install_package_image(spec.tenant, &image, || Ok(()))?;
    let pin = ImagePin {
        image: image.bundle().root.clone(),
        digest: image.digest().into(),
    };
    let mut call = spec.manifest.calls[&10].clone();
    call.image = pin.clone();
    call.package = image.bundle().root.clone();
    call.export = export;
    call.arguments.clear();
    call.target = "sql".into();
    call.artifact = None;
    call.dependencies.clear();
    spec.manifest.calls.insert(13, call);
    let mut images = spec.definition.images.clone();
    images.push(pin);
    spec.definition = ResolvedDefinition::new(
        spec.definition.definition.clone(),
        spec.definition.sql.clone(),
        images,
    )?;
    spec.manifest.definition =
        graph
            .store
            .admit_definition(spec.tenant, &spec.definition, || Ok(()))?;
    fixture.instance = graph
        .store
        .admit_managed(&spec, &fixture.instance.grant, || Ok(()))?;
    fixture.instance = graph.store.set_managed_running(
        spec.tenant,
        &spec.id,
        fixture.instance.lifecycle,
        true,
        || Ok(()),
    )?;
    Ok((graph, fixture))
}

#[test]
fn graph_reopen_rejects_corruption() -> TestResult {
    for fault in 0..3 {
        let (graph, fixture) = fixture()?;
        let captured = read(&graph, &mode(&fixture, true))?;
        let attempt = graph
            .store
            .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
        let receipt = publish(&graph, &fixture, &captured, &attempt)?;
        let result = receipt.graph.as_ref().ok_or("Graph result absent")?;
        graph.store.verify_state()?;
        {
            let mut writer = graph.store.writer()?;
            let writer = writer.get_mut()?;
            if fault == 0 {
                let header = GraphRows::read_header(
                    writer,
                    fixture.instance.spec.tenant,
                    &result.result_id,
                )?
                .ok_or("Graph header absent")?;
                let mut snapshot = GraphRows::read(writer, &result.result_id, &header)?;
                let package = snapshot
                    .packages
                    .iter_mut()
                    .find(|package| {
                        package.package_id
                            == araphor_analysis_builtins::graph::Detector::Process.id()
                    })
                    .ok_or("Graph package absent")?;
                package.state = if package.state
                    == araphor_analysis_builtins::graph::GraphPackageStateV1::Waiting
                {
                    araphor_analysis_builtins::graph::GraphPackageStateV1::NativeEffect
                } else {
                    araphor_analysis_builtins::graph::GraphPackageStateV1::Waiting
                };
                let body = GraphRows::encode(&snapshot)?;
                assert_eq!(
                    writer.execute(
                        "UPDATE analysis_results SET body=? WHERE result_id=?",
                        params![body, result.result_id],
                    )?,
                    1
                );
            } else {
                assert_eq!(writer.execute("UPDATE graph_producer_versions SET captured_revision=captured_revision-1
                WHERE result_id=(SELECT metadata_result_id FROM graph_versions WHERE result_id=?) AND captured_revision>1",
                params![result.result_id])?,1);
                if fault == 2 {
                    assert_eq!(writer.execute("UPDATE graph_producer_versions SET captured_revision=captured_revision-1
                    WHERE result_id=? AND captured_revision>1",params![receipt.results[&13].result_id])?,1);
                }
            }
        }
        let error = graph
            .store
            .verify_state()
            .err()
            .ok_or("corrupt Graph state accepted")?;
        assert!(
            format!("{error:?}").contains(match fault {
                0 => "published Graph package state differs",
                1 => "graph metadata summary",
                _ => "captured",
            }),
            "fault {fault}: {error:?}"
        );
        let root = graph._directory.path().join("analysis");
        let CommitFixture {
            store,
            _graph,
            _directory,
            ..
        } = graph;
        drop(_graph);
        drop(store);
        assert!(AnalysisStore::open(&root).is_err());
    }
    Ok(())
}

fn read(graph: &CommitFixture, mode: &ManagedRead) -> TestResult<ManagedCapture> {
    let cursor = crate::AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    Ok(graph
        .store
        .read_managed_tables_filtered(
            &mode.instance.grant.selection,
            mode,
            AnalysisTableRead {
                requests: &AnalysisTableRequests::from([(
                    "events".into(),
                    Some(BTreeSet::from([cursor])),
                )]),
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state)
}

fn mode(fixture: &Fixture, follow: bool) -> ManagedRead {
    ManagedRead {
        source: None,
        execution: None,
        instance: fixture.instance.clone(),
        expected: None,
        rebuild: false,
        follow,
        completed: follow.then_some(0),
    }
}

fn input(graph: &CommitFixture) -> ManagedRequest {
    let mut input = request("graph-prefix");
    input.witness_expiry = graph.snapshot.witness_deadline_utc_ns;
    input.frontier = Some(ManagedFrontier {
        cursor: vec![1],
        next_change: None,
        pending: false,
    });
    input
}

fn empty_dataset(port: &sdk::Port) -> sdk::Dataset {
    sdk::Dataset {
        name: port.name.clone(),
        batches: vec![sdk::RecordBatch::new_empty(Arc::new(port.schema.clone()))],
    }
}

fn graph_evaluation(request: &ManagedRequest) -> TestResult<sdk::Evaluation> {
    let descriptor = araphor_analysis_builtins::graph::Detector::Process.descriptor();
    let model = &descriptor.exports[0];
    let changes = model.change_inputs.as_ref().ok_or("Graph changes absent")?;
    let inputs = model
        .inputs
        .iter()
        .map(|input| {
            Ok(sdk::Input {
                data: if input.port.name == changes.reset {
                    changes.reset_input(true)?
                } else {
                    empty_dataset(&input.port)
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "graph-cut".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(sdk::Evaluation {
        export: "detect".into(),
        inputs,
        parameters: None,
        checkpoint: None,
        previous_outputs: Vec::new(),
        context: sdk::EvaluationContext {
            id: request.id.clone(),
            time_utc_ns: request.time_utc_ns as i64,
            seed: request.seed,
        },
    })
}

fn graph_output(evaluation: &sdk::Evaluation) -> TestResult<sdk::Output> {
    Ok(araphor_analysis_builtins::graph::Detector::Process.evaluate(evaluation)?)
}

fn publish(
    graph: &CommitFixture,
    fixture: &Fixture,
    captured: &ManagedCapture,
    attempt: &ManagedAttempt,
) -> TestResult<ManagedReceipt> {
    let mut evaluations = vec![
        fixture.evaluation(attempt.request(), 10, Some(captured))?,
        fixture.evaluation(attempt.request(), 11, Some(captured))?,
    ];
    let mut outputs = vec![fixture.output(2)?, fixture.output(3)?];
    let mut calls = vec![10, 11];
    if fixture.instance.spec.manifest.calls.contains_key(&13) {
        evaluations.push(graph_evaluation(attempt.request())?);
        outputs.push(graph_output(
            evaluations.last().ok_or("Graph evaluation absent")?,
        )?);
        calls.push(13);
    }
    let changes = evaluations
        .last()
        .filter(|_| calls.last() == Some(&13))
        .map(|_| -> TestResult<ManagedChanges> { Ok(ManagedChanges { base: None }) })
        .transpose()?;
    let returns = evaluations
        .iter()
        .zip(&outputs)
        .zip(calls)
        .map(|((evaluation, output), call)| ManagedReturn {
            graph: None,
            retained: None,
            call,
            evaluation,
            output,
            changes: if call == 13 { changes.as_ref() } else { None },
        })
        .collect::<Vec<_>>();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    for record in &graph.snapshot.input_manifest.evidence {
        let page = graph
            .store
            .read_page(&record.stream, record.durable_cursor)?;
        let observed = page
            .records
            .into_iter()
            .find(|observed| observed.cursor == record.durable_cursor)
            .ok_or("Graph fixture journal record absent")?;
        assert!(observed.position.commit_revision <= attempt.captured_revision());
    }
    let (receipt, result) = graph.store.commit_managed_graph(
        graph.store.prepare_managed(&ManagedCommit {
            control: &crate::AnalysisReadControl::default(),
            budget: &crate::analysis::managed::tests::TestBudget,
            completed: true,
            attempt,
            now_utc_ns: 10,
            returns: &returns,
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema,
        })?,
        || Ok(()),
    )?;
    assert_eq!(
        result.ok_or("Graph receipt absent")?.commit_revision,
        receipt.commit_revision
    );
    Ok(receipt)
}
