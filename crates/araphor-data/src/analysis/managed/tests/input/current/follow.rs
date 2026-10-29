use super::*;
use crate::analysis::graph_rows::{tests::fixture::CommitFixture, CanonicalGraph, GraphRows};

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
        calls: BTreeSet::from([10, 11]),
        operation: ManagedGraphOperation::Evaluate,
        events_sql: "SELECT * FROM events".into(),
    };
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

fn read(graph: &CommitFixture, mode: &ManagedRead) -> TestResult<ManagedCapture> {
    let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    Ok(graph
        .store
        .read_managed_tables(
            &mode.instance.grant.selection,
            mode,
            AnalysisTableRead {
                requests: &AnalysisTableRequests::from([(
                    "events".into(),
                    Some(BTreeSet::from([cursor])),
                )]),
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?
        .state)
}

fn mode(fixture: &Fixture, follow: bool) -> ManagedRead {
    ManagedRead {
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

fn publish(
    graph: &CommitFixture,
    fixture: &Fixture,
    captured: &ManagedCapture,
    attempt: &ManagedAttempt,
    source_revision: Option<u64>,
) -> TestResult<ManagedReceipt> {
    let evaluations = [
        fixture.evaluation(attempt.request(), 10, Some(captured))?,
        fixture.evaluation(attempt.request(), 11, Some(captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let returns = evaluations
        .iter()
        .zip(&outputs)
        .enumerate()
        .map(|(index, (evaluation, output))| ManagedReturn {
            call: 10 + index as u64,
            evaluation,
            output,
            retained: None,
        })
        .collect::<Vec<_>>();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: outputs[0].datasets[0].batches.clone(),
    };
    let mut sources = captured.contract.sources.clone();
    if let Some(revision) = source_revision {
        sources.first_mut().ok_or("source guard absent")?.1 = revision;
    }
    let mut request = graph.request.clone();
    request.body.clear();
    let (receipt, result) = graph.store.commit_managed_graph(
        &ManagedCommit {
            completed: true,
            attempt,
            now_utc_ns: 10,
            returns: &returns,
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema,
        },
        Some(crate::analysis::graph::GraphCommit {
            request,
            graph: CanonicalGraph::new(graph.snapshot.clone())?,
            contexts: Vec::new(),
            proofs: Vec::new(),
            sources,
            advance: true,
        }),
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
            let receipt = publish(&graph, &fixture, &captured, &attempt, None)?;
            assert!(receipt.commit_revision > captured.revision());
            assert_eq!(
                fixture.current(&graph.store)?.progress,
                receipt.commit_revision
            );
            assert_eq!(receipt.results.len(), 2);
            assert_eq!(
                receipt.graph,
                Some(crate::analysis::PackageResultRefV1 {
                    result_id: graph.request.result_id.clone(),
                    commit_revision: receipt.commit_revision,
                })
            );
            assert!(matches!(
                graph.store.managed_query_output(
                    &fixture.instance.grant.selection,
                    &fixture.instance.spec.id,
                    Some(&receipt.selected.result_id),
                    10,
                    &AnalysisReadControl::default(),
                )?,
                ManagedOutput::Selected { .. }
            ));
            let ManagedOutput::Call { result, data } = graph.store.managed_query_output(
                &fixture.instance.grant.selection,
                &fixture.instance.spec.id,
                Some(&receipt.results[&10].result_id),
                10,
                &AnalysisReadControl::default(),
            )?
            else {
                return Err("retained call output absent".into());
            };
            assert!(!result.current);
            assert_eq!(
                sdk::wire::Output::encode_model(&data, &fixture.model)?,
                sdk::wire::Output::encode_model(&fixture.output(2)?, &fixture.model)?
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
fn graph_empty_step_has_no_publication() -> TestResult {
    let (graph, fixture) = fixture()?;
    let captured = read(&graph, &mode(&fixture, true))?;
    let attempt = graph
        .store
        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: Vec::new(),
    };
    let (receipt, graph_result) = graph.store.commit_managed_graph(
        &ManagedCommit {
            completed: true,
            attempt: &attempt,
            now_utc_ns: 10,
            returns: &[],
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema,
        },
        None,
        || Ok(()),
    )?;
    assert!(receipt.results.is_empty());
    assert!(receipt.graph.is_none());
    assert!(graph_result.is_none());
    assert!(matches!(
        graph.store.managed_query_output(
            &fixture.instance.grant.selection,
            &fixture.instance.spec.id,
            Some(&receipt.selected.result_id),
            10,
            &AnalysisReadControl::default(),
        )?,
        ManagedOutput::Selected { .. }
    ));
    let writer = graph.store.writer()?;
    let (mut step, _, revision) = AnalysisStore::managed_step_from(
        writer.get()?,
        fixture.instance.spec.tenant,
        &receipt.selected.result_id,
    )?;
    step.rows = 1;
    assert!(AnalysisStore::validate_selected_header(
        writer.get()?,
        fixture.instance.spec.tenant,
        &receipt.selected.result_id,
        &step,
        revision,
    )
    .is_err());
    Ok(())
}

#[test]
fn graph_selected_rejects_wrong_publication_binding() -> TestResult {
    for fault in [
        "missing_edge",
        "wrong_edge",
        "wrong_receipt",
        "damaged_header",
        "header_source",
    ] {
        let (mut graph, fixture) = fixture()?;
        let captured = read(&graph, &mode(&fixture, true))?;
        let attempt = graph
            .store
            .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
        let receipt = publish(&graph, &fixture, &captured, &attempt, None)?;
        let original = receipt.graph.as_ref().ok_or("Graph publication")?;
        let mut request = graph.request.clone();
        request.body.clear();
        request.result_id = format!("graph:later-{fault}");
        request.expected_cursor = graph.snapshot.last_cursor;
        request.consumed_cursor = graph.snapshot.last_cursor;
        request.created_utc_ns += 1;
        let mut snapshot = graph.snapshot.clone();
        snapshot.previous_result_id = Some(original.result_id.clone());
        snapshot.packages[0].coverage_predicate.push_str("-later");
        let later = graph.store.commit_graph_snapshot(
            request.clone(),
            CanonicalGraph::new(snapshot)?,
            &[],
            &[],
            &[],
            false,
            || Ok(()),
        )?;
        let later = crate::analysis::PackageResultRefV1 {
            result_id: request.result_id,
            commit_revision: later.commit_revision,
        };
        if fault == "wrong_receipt" {
            let writer = graph.store.writer()?;
            let reader = writer.get()?;
            let mut other_source = graph.snapshot.scope.identity.clone();
            other_source.source_id = [93; 16];
            assert!(AnalysisStore::check_graph_publication(
                reader,
                graph.snapshot.scope.identity.tenant_id,
                &other_source,
                original,
                receipt.commit_revision,
            )
            .is_err());
            assert!(AnalysisStore::check_graph_publication(
                reader,
                [9; 16],
                &graph.snapshot.scope.identity,
                original,
                receipt.commit_revision,
            )
            .is_err());
            assert!(AnalysisStore::check_graph_publication(
                reader,
                graph.snapshot.scope.identity.tenant_id,
                &graph.snapshot.scope.identity,
                &receipt.results[&10],
                receipt.commit_revision,
            )
            .is_err());
            let mut wrong_revision = original.clone();
            wrong_revision.commit_revision += 1;
            assert!(AnalysisStore::check_graph_publication(
                reader,
                graph.snapshot.scope.identity.tenant_id,
                &graph.snapshot.scope.identity,
                &wrong_revision,
                wrong_revision.commit_revision,
            )
            .is_err());
        }
        assert!(matches!(
            graph.store.managed_query_output(
                &fixture.instance.grant.selection,
                &fixture.instance.spec.id,
                Some(&receipt.selected.result_id),
                10,
                &AnalysisReadControl::default(),
            )?,
            ManagedOutput::Selected { .. }
        ));
        {
            let mut writer = graph.store.writer()?;
            let writer = writer.get_mut()?;
            if fault == "missing_edge" {
                writer.execute(
                    "DELETE FROM managed_edges WHERE result_id = ? AND dependency_id = ?",
                    params![receipt.selected.result_id, original.result_id],
                )?;
            } else if fault == "wrong_edge" {
                let metadata: Vec<u8> = writer.query_row(
                    "SELECT request_meta FROM analysis_results WHERE result_id = ?",
                    params![receipt.selected.result_id],
                    |row| row.get(0),
                )?;
                let mut step: model::Step = serde_json::from_slice(&metadata)?;
                *step
                    .dependencies
                    .iter_mut()
                    .find(|reference| reference.result_id == original.result_id)
                    .ok_or("selected Graph dependency")? = later.clone();
                step.dependencies
                    .sort_by(|left, right| left.result_id.cmp(&right.result_id));
                writer.execute(
                    "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
                    params![serde_json::to_vec(&step)?, receipt.selected.result_id],
                )?;
                writer.execute(
                    "UPDATE managed_edges SET dependency_id = ?, commit_revision = ?
                     WHERE result_id = ? AND dependency_id = ?",
                    params![
                        later.result_id,
                        later.commit_revision,
                        receipt.selected.result_id,
                        original.result_id
                    ],
                )?;
            } else if fault == "wrong_receipt" {
                let metadata: Vec<u8> = writer.query_row(
                    "SELECT contract FROM managed_attempts
                     WHERE instance_id = ? AND attempt_id = ?",
                    params![fixture.instance.spec.id, attempt.request().id],
                    |row| row.get(0),
                )?;
                let mut saved: model::Attempt = serde_json::from_slice(&metadata)?;
                saved.receipt.as_mut().ok_or("saved Graph receipt")?.graph = Some(later);
                writer.execute(
                    "UPDATE managed_attempts SET contract = ?
                     WHERE instance_id = ? AND attempt_id = ?",
                    params![
                        serde_json::to_vec(&saved)?,
                        fixture.instance.spec.id,
                        attempt.request().id
                    ],
                )?;
            } else if fault == "damaged_header" {
                writer.execute(
                    "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?",
                    params![original.result_id],
                )?;
            } else {
                let mut wrong = graph.snapshot.clone();
                wrong.scope.identity.source_id = [93; 16];
                wrong.input_manifest.evidence.clear();
                wrong.input_positions.clear();
                wrong.graph.subjects.clear();
                wrong.graph.edges.clear();
                wrong.graph.branches.clear();
                wrong.findings.clear();
                let body = GraphRows::encode(&wrong)?;
                writer.execute(
                    "UPDATE analysis_results SET body = ? WHERE result_id = ?",
                    params![body, original.result_id],
                )?;
            }
        }
        assert!(graph
            .store
            .managed_query_output(
                &fixture.instance.grant.selection,
                &fixture.instance.spec.id,
                Some(&receipt.selected.result_id),
                10,
                &AnalysisReadControl::default(),
            )
            .is_err());
        let directory = std::mem::replace(&mut graph._directory, tempfile::tempdir()?);
        drop(graph);
        assert!(
            AnalysisStore::open(directory.path().join("analysis")).is_err(),
            "{fault}"
        );
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
                let error = publish(&graph, &fixture, &captured, &attempt, None)
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
    let attempt = graph
        .store
        .register_managed_attempt(&captured, &input(&graph), || Ok(()))?;
    let before = fixture.commit_state(&graph.store)?;
    let error = publish(
        &graph,
        &fixture,
        &captured,
        &attempt,
        Some(before.meta.commit_revision + 1),
    )
    .err()
    .ok_or("future Graph publication succeeded")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.commit_state(&graph.store)?, before);
    Ok(())
}
