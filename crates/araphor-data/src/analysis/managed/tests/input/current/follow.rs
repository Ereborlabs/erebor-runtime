use super::*;
use crate::analysis::graph_rows::{tests::fixture::CommitFixture, CanonicalGraph, GraphRows};
use crate::PackageErrorCodeV1 as Code;

fn fixture() -> TestResult<(CommitFixture, Fixture)> {
    fixture_with_unused_call(false)
}

fn fixture_with_unused_call(unused_call: bool) -> TestResult<(CommitFixture, Fixture)> {
    fixture_with_calls(unused_call, true)
}

fn fixture_with_calls(
    unused_call: bool,
    graph_producer: bool,
) -> TestResult<(CommitFixture, Fixture)> {
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
        calls: if graph_producer {
            BTreeSet::from([10, 11, 13])
        } else {
            BTreeSet::from([10, 11])
        },
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
    if graph_producer {
        spec.manifest.calls.insert(13, call.clone());
    }
    if unused_call {
        spec.manifest.calls.insert(12, call);
    }
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
fn graph_reopen_uses_selected_call_subset() -> TestResult {
    let (graph, fixture) = fixture_with_unused_call(true)?;
    let captured = read(&graph, &mode(&fixture, true))?;
    let attempt = graph
        .store
        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
    let receipt = publish(&graph, &fixture, &captured, &attempt)?;
    assert_eq!(receipt.results.len(), 3);
    assert!(receipt.results.contains_key(&13));
    assert!(!receipt.results.contains_key(&12));
    let root = graph._directory.path().join("analysis");
    let CommitFixture {
        store,
        _graph,
        _directory,
        ..
    } = graph;
    drop(_graph);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let saved = reopened
        .managed_attempt(
            fixture.instance.spec.tenant,
            &fixture.instance.spec.id,
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("reopened managed Graph attempt")?;
    assert_eq!(saved.receipt(), Some(&receipt));
    Ok(())
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

#[test]
fn graph_publication_requires_a_graph_producer() -> TestResult {
    let (graph, fixture) = fixture_with_calls(false, false)?;
    let captured = read(&graph, &mode(&fixture, true))?;
    let attempt = graph
        .store
        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
    let before = fixture.commit_state(&graph.store)?;
    let error = publish(&graph, &fixture, &captured, &attempt)
        .err()
        .ok_or("Graph publication without a producer succeeded")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::GraphInvalid {
            field: "graph producer is absent",
            ..
        })
    ));
    assert_eq!(fixture.commit_state(&graph.store)?, before);
    assert!(graph
        .store
        .processor_result(&graph.snapshot.scope)?
        .is_none());
    assert!(graph
        .store
        .managed_attempt(
            fixture.instance.spec.tenant,
            &fixture.instance.spec.id,
            &attempt.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("registered managed attempt absent")?
        .receipt()
        .is_none());
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

fn append(graph: &CommitFixture, same_source: bool) -> TestResult {
    let mut source = graph.snapshot.scope.identity.clone();
    let cursor = if same_source {
        2
    } else {
        source.source_id = [93; 16];
        1
    };
    let frame = Vec::<u8>::try_from(&crate::EvidenceRecord {
        observed_boottime_ns: 2,
        ..Default::default()
    })?;
    graph.store.accept_validated_batch(
        source,
        crate::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 2,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    Ok(())
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

#[test]
fn graph_follow_retains_prefix() -> TestResult {
    for same_source in [false, true] {
        for before_admission in [false, true] {
            let (graph, fixture) = fixture()?;
            let captured = read(&graph, &mode(&fixture, true))?;
            assert!(captured.follows_graph());
            if before_admission {
                append(&graph, same_source)?;
            }
            let attempt =
                graph
                    .store
                    .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
            if !before_admission {
                append(&graph, same_source)?;
            }
            let receipt = publish(&graph, &fixture, &captured, &attempt)?;
            assert!(receipt.commit_revision > captured.revision());
            assert_eq!(
                fixture.current(&graph.store)?.progress,
                receipt.commit_revision
            );
            assert_eq!(receipt.results.len(), 3);
            assert_eq!(
                receipt.graph,
                Some(crate::analysis::PackageResultRefV1 {
                    result_id: graph.request.result_id.clone(),
                    commit_revision: receipt.commit_revision,
                })
            );
            assert!(matches!(
                graph
                    .store
                    .managed_result(
                        &fixture.current(&graph.store)?,
                        &receipt.selected.result_id,
                        10,
                        &AnalysisReadControl::default(),
                    )?
                    .kind,
                crate::InstanceResultKindV1::Selected
            ));
            let result = graph.store.managed_result(
                &fixture.current(&graph.store)?,
                &receipt.results[&10].result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert!(!result.current);
            assert_eq!(result.result, receipt.results[&10]);
            assert_eq!(result.receipt, receipt);
            assert_eq!(
                fixture
                    .checkpoint(&graph.store, &receipt.results[&10])?
                    .datasets[0]
                    .batches,
                fixture
                    .output(2)?
                    .checkpoint
                    .ok_or("fixture checkpoint")?
                    .datasets[0]
                    .batches
            );
            assert_eq!(
                receipt.frontier.as_ref(),
                attempt.request().frontier.as_ref()
            );
            let health = graph
                .store
                .processor_health(&graph.snapshot.scope)?
                .ok_or("Graph health absent")?;
            assert_eq!(health.consumed_cursor, 1);
            assert_eq!(health.accepted_cursor, if same_source { 2 } else { 1 });
            let saved = graph
                .store
                .managed_attempt(
                    [1; 16],
                    &fixture.instance.spec.id,
                    &attempt.request().id,
                    &AnalysisReadControl::default(),
                )?
                .ok_or("saved attempt absent")?;
            assert!(saved.follows_graph());
        }
    }
    Ok(())
}

#[test]
fn finite_graph_rejects_changes() -> TestResult {
    for same_source in [false, true] {
        for before_admission in [false, true] {
            let (graph, fixture) = fixture()?;
            assert!(fixture.instance.running);
            let captured = read(&graph, &mode(&fixture, false))?;
            assert!(!captured.follows_graph());
            if before_admission {
                append(&graph, same_source)?;
                let before = fixture.commit_state(&graph.store)?;
                assert!(matches!(
                    graph
                        .store
                        .register_managed_attempt(&captured, &input(&graph), || Ok(())),
                    Err(crate::Error::AnalysisSourceChanged { .. })
                ));
                assert_eq!(fixture.commit_state(&graph.store)?, before);
            } else {
                let attempt =
                    graph
                        .store
                        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
                append(&graph, same_source)?;
                let before = fixture.commit_state(&graph.store)?;
                let error = publish(&graph, &fixture, &captured, &attempt)
                    .err()
                    .ok_or("finite stale publication succeeded")?;
                assert!(matches!(
                    error.downcast_ref::<crate::Error>(),
                    Some(crate::Error::AnalysisSourceChanged { .. })
                ));
                assert_eq!(fixture.commit_state(&graph.store)?, before);
            }
            assert!(graph
                .store
                .processor_result(&graph.snapshot.scope)?
                .is_none());
        }
    }
    Ok(())
}

#[test]
fn graph_follow_requires_mode() -> TestResult {
    let (graph, fixture) = fixture()?;
    let valid = mode(&fixture, true);
    let mut invalid = [valid.clone(), valid.clone(), valid.clone()];
    invalid[0].completed = None;
    invalid[1].expected = Some(valid.instance.clone());
    invalid[2].rebuild = true;
    for invalid in invalid {
        let before = fixture.commit_state(&graph.store)?;
        let error = read(&graph, &invalid)
            .err()
            .ok_or("invalid Follow capture succeeded")?;
        assert!(matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::Package {
                code: Code::Invalid,
                field: "managed Graph follow mode",
                ..
            })
        ));
        assert_eq!(fixture.commit_state(&graph.store)?, before);
    }
    let mut captured = read(&graph, &valid)?;
    let mut legacy = serde_json::to_value(&captured.contract)?;
    legacy
        .as_object_mut()
        .ok_or("capture object absent")?
        .remove("follow");
    captured.contract = serde_json::from_value(legacy)?;
    assert!(!captured.follows_graph());
    append(&graph, false)?;
    assert!(matches!(
        graph
            .store
            .register_managed_attempt(&captured, &input(&graph), || Ok(())),
        Err(crate::Error::AnalysisSourceChanged { .. })
    ));
    let stopped = graph.store.set_managed_running(
        fixture.instance.spec.tenant,
        &fixture.instance.spec.id,
        fixture.instance.lifecycle,
        false,
        || Ok(()),
    )?;
    let before = fixture.commit_state(&graph.store)?;
    let error = read(
        &graph,
        &ManagedRead {
            execution: None,
            instance: stopped,
            ..valid
        },
    )
    .err()
    .ok_or("inactive Follow capture succeeded")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::Package {
            code: Code::Invalid,
            field: "managed Graph follow mode",
            ..
        })
    ));
    assert_eq!(fixture.commit_state(&graph.store)?, before);
    Ok(())
}

#[test]
fn graph_follow_rejects_future() -> TestResult {
    let (graph, fixture) = fixture()?;
    let mut captured = read(&graph, &mode(&fixture, true))?;
    let original = captured.contract.sources.clone();
    captured
        .contract
        .sources
        .first_mut()
        .ok_or("source guard absent")?
        .1 = captured.revision() + 1;
    let before = fixture.commit_state(&graph.store)?;
    assert!(matches!(
        graph
            .store
            .register_managed_attempt(&captured, &input(&graph), || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.commit_state(&graph.store)?, before);
    captured.contract.sources = original;
    let _attempt = graph
        .store
        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
    Ok(())
}
