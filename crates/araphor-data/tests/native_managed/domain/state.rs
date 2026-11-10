use super::*;
use araphor_analysis_types::{GraphPackageStateV1, GraphStateMember};

#[test]
fn snapshot_keeps_package_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = fixture_source(&store, true)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    let states = [
        GraphStateMember {
            record: None,
            position: None,
            fact: None,
            state: GraphPackageStateV1::Declared("0".into()),
        },
        GraphStateMember {
            record: Some(observation.id.clone()),
            position: Some(observation.position),
            fact: None,
            state: GraphPackageStateV1::Declared("1".into()),
        },
    ];
    commit_named_expiry(
        &store,
        &model,
        &observation,
        0,
        None,
        "domain",
        Some((&states, false)),
    )?;
    let snapshot = store.graph_snapshot(&source)?.ok_or("snapshot")?;
    assert_eq!(snapshot.graph.subjects.len(), 2);
    assert_eq!(snapshot.graph.edges.len(), 1);
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.graph.facts.len(), 1);
    assert_eq!(snapshot.input_positions.len(), 1);
    let package = &snapshot.packages[0];
    assert_eq!(package.state, GraphPackageStateV1::Declared("1".into()));
    assert_eq!(package.accepted_cursor_watermark, 1);
    assert_eq!(
        package.observed_boottime_watermark_ns,
        observation.observed_boottime_ns
    );
    let reference = store.processor_result(&scope)?.ok_or("result")?;
    assert_eq!(
        store.graph_result([1; 16], &reference.result_id)?,
        Some(snapshot.clone())
    );
    check_traversal(&store, &source, &reference.result_id, &snapshot)?;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.graph_snapshot(&source)?, Some(snapshot.clone()));
    check_traversal(&store, &source, &reference.result_id, &snapshot)?;
    Ok(())
}

fn check_traversal(
    store: &NativeStore,
    source: &EvidenceIntakeIdentityV1,
    result: &str,
    snapshot: &araphor_data::GraphSnapshotV1,
) -> TestResult {
    use araphor_data::{GraphTraversalDirectionV1 as Direction, GraphTraversalV1, Selection};
    use sdk::arrow_array::UInt32Array;
    let requests = ["graph_subjects", "relationships"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect();
    let read = |selection: &AnalysisSelectionV1, limits| {
        store.read_tables(
            selection,
            AnalysisTableRead {
                requests: &requests,
                mode: AnalysisReadModeV1::Complete,
                now: 1000,
                event_ranges: None,
            },
            limits,
            &AnalysisReadControl::default(),
        )
    };
    let edge = &snapshot.graph.edges[0];
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source.clone()]);
    selection.select_graphs(Selection::Exact(vec![result.into()]), None)?;
    let ordinary = read(&selection, AnalysisExtractLimits::default())?;
    let mut request = GraphTraversalV1 {
        seeds: vec![snapshot.graph.subjects[edge.key.to as usize].clone()],
        direction: Direction::Incoming,
        max_hops: 0,
        ..Default::default()
    };
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request.clone()))?;
    let zero = read(&selection, AnalysisExtractLimits::default())?;
    let receipt = zero
        .extraction
        .graph_traversal()
        .ok_or("traversal receipt")?;
    assert_eq!(
        (
            receipt.unique_subject_count,
            receipt.versioned_subject_count,
            receipt.relationship_count
        ),
        (1, 1, 0)
    );
    assert!(receipt.hop_boundary);
    let ids = zero.tables["graph_subjects"]
        .iter()
        .flat_map(|batch| {
            batch
                .column_by_name("subject_id")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt32Array>()
                .unwrap()
                .values()
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert!(edge.key.to > 0);
    assert_eq!(ids, [edge.key.to]);
    request.seeds = vec![snapshot.graph.subjects[edge.key.from as usize].clone()];
    request.direction = Direction::Outgoing;
    request.max_hops = 1;
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request.clone()))?;
    let walked = read(&selection, AnalysisExtractLimits::default())?;
    let receipt = walked
        .extraction
        .graph_traversal()
        .ok_or("traversal receipt")?;
    assert_eq!(
        (
            receipt.unique_subject_count,
            receipt.versioned_subject_count,
            receipt.relationship_count
        ),
        (2, 2, 1)
    );
    assert!(!receipt.hop_boundary);
    for name in ["relationships", "graph_subjects"] {
        let left = ordinary.tables[name]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>();
        let right = walked.tables[name]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>();
        assert_eq!(left, right);
    }
    request.seeds = vec![snapshot.graph.subjects[edge.key.to as usize].clone()];
    request.direction = Direction::Incoming;
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request.clone()))?;
    assert_eq!(
        read(&selection, AnalysisExtractLimits::default())?
            .extraction
            .graph_traversal()
            .ok_or("receipt")?
            .relationship_count,
        1
    );
    request.edge_types = vec![GraphEdgeTypeV1::NativeParent];
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request.clone()))?;
    let filtered = read(&selection, AnalysisExtractLimits::default())?;
    let receipt = filtered.extraction.graph_traversal().ok_or("receipt")?;
    assert_eq!(
        (
            receipt.unique_subject_count,
            receipt.relationship_count,
            receipt.hop_boundary
        ),
        (1, 0, false)
    );
    request.edge_types.clear();
    request.max_subjects = 1;
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request.clone()))?;
    assert!(read(&selection, AnalysisExtractLimits::default()).is_err());
    request.max_subjects = usize::MAX;
    request.result_ids = vec!["outside-selection".into()];
    selection.select_graphs(Selection::Exact(vec![result.into()]), Some(request))?;
    assert!(matches!(
        read(&selection, AnalysisExtractLimits::default()),
        Err(Error::AnalysisReadDenied { .. })
    ));
    Ok(())
}

#[test]
fn state_owner_is_canonical() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("data"))?;
    let (_, model, _, observation) = fixture(&store)?;
    let state = GraphStateMember {
        record: Some(observation.id.clone()),
        position: Some(observation.position),
        fact: None,
        state: GraphPackageStateV1::Declared("1".into()),
    };
    let before = store.view()?.revision();
    assert!(commit_named_expiry(
        &store,
        &model,
        &observation,
        0,
        None,
        "domain",
        Some((&[state], true))
    )
    .is_err());
    assert!(store
        .managed_history(
            &AnalysisSelectionV1::tenant([1; 16]),
            "domain",
            &AnalysisReadControl::default()
        )?
        .is_empty());
    assert!(store.view()?.revision() > before);
    Ok(())
}

#[test]
fn traversal_spans_retained_versions() -> TestResult {
    use araphor_data::{GraphTraversalV1, Selection};
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = fixture_binding(&store, true, Some([6; 16]))?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    let state = GraphStateMember {
        record: None,
        position: None,
        fact: None,
        state: GraphPackageStateV1::Declared("retained".into()),
    };
    commit_named_expiry(
        &store,
        &model,
        &observation,
        0,
        None,
        "domain",
        Some((&[state], false)),
    )?;
    let first = store.processor_result(&scope)?.ok_or("first result")?;
    let first_graph = store
        .graph_result([1; 16], &first.result_id)?
        .ok_or("first Graph")?;
    let held = store.view()?;
    let original = algorithm::RelationshipIdentity::from_keys(
        &first_graph.graph.edges[0].key,
        &first_graph.graph.subjects,
        &first_graph.input_manifest.evidence,
    )?;
    let target = GraphSubjectKeyV1::native(&source, GraphSubjectKindV1::Process, vec![8; 16]);
    let added = algorithm::SubjectChange {
        anchor: algorithm::Anchor {
            record: observation.id.clone(),
            fact: None,
        },
        key: target.clone(),
    };
    let mut edge = algorithm::RelationshipChange {
        anchor: added.anchor.clone(),
        key: original.clone(),
        proof_quality: observation.proof_quality,
        required_coverage_interval_ids: vec![[4; 16]],
        first_boottime_ns: 10,
        last_boottime_ns: 10,
    };
    let removed = command(
        &model,
        DomainRelations::RELATIONSHIPS,
        b"owner",
        &[DomainRelations::key(&original)?],
        Some([
            DomainRelations::key(&original.from)?,
            DomainRelations::key(&original.to)?,
            DomainRelations::key(&original.edge_type)?,
        ]),
        algorithm::RelationshipChange::encode(&[edge.clone()])?,
        true,
    )?;
    edge.key.from = original.from.clone();
    edge.key.to = target;
    edge.key.edge_type = GraphEdgeTypeV1::TaskInProcess;
    let commands = vec![
        (DomainRelations::RELATIONSHIPS.into(), removed),
        (
            DomainRelations::SUBJECTS.into(),
            command(
                &model,
                DomainRelations::SUBJECTS,
                b"owner",
                &[DomainRelations::key(&added.key)?],
                None,
                algorithm::SubjectChange::encode(&[added])?,
                false,
            )?,
        ),
        (
            DomainRelations::RELATIONSHIPS.into(),
            command(
                &model,
                DomainRelations::RELATIONSHIPS,
                b"owner",
                &[DomainRelations::key(&edge.key)?],
                Some([
                    DomainRelations::key(&edge.key.from)?,
                    DomainRelations::key(&edge.key.to)?,
                    DomainRelations::key(&edge.key.edge_type)?,
                ]),
                algorithm::RelationshipChange::encode(&[edge])?,
                false,
            )?,
        ),
    ];
    commit_commands(
        &store,
        &model,
        &observation,
        1,
        None,
        "domain",
        None,
        &commands,
        None,
    )?;
    let second = store.processor_result(&scope)?.ok_or("second result")?;
    let requests = ["graph_subjects", "relationships"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect();
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source.clone()]);
    let ids = vec![second.result_id.clone(), first.result_id.clone()];
    let mut request = GraphTraversalV1 {
        seeds: vec![original.to],
        direction: araphor_data::GraphTraversalDirectionV1::Both,
        result_ids: ids.clone(),
        max_hops: 2,
        ..Default::default()
    };
    selection.select_graphs(Selection::Exact(ids.clone()), Some(request.clone()))?;
    let read = |store: &NativeStore, selection: &AnalysisSelectionV1| {
        store.read_tables(
            selection,
            AnalysisTableRead {
                requests: &requests,
                mode: AnalysisReadModeV1::Complete,
                now: 1000,
                event_ranges: None,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
    };
    let page = read(&store, &selection)?;
    let receipt = page.extraction.graph_traversal().ok_or("receipt")?;
    assert_eq!(receipt.result_ids, ids);
    assert_eq!(
        (
            receipt.unique_subject_count,
            receipt.versioned_subject_count,
            receipt.relationship_count
        ),
        (3, 5, 2)
    );
    assert!(!receipt.hop_boundary);
    request.max_subjects = 4;
    let mut limited = selection.clone();
    limited.select_graphs(Selection::Exact(ids.clone()), Some(request))?;
    assert!(read(&store, &limited).is_err());
    assert_eq!(
        store.graph_result([1; 16], &first.result_id)?,
        Some(first_graph.clone())
    );
    assert!(store
        .read_tables_at(
            &held,
            &selection,
            AnalysisTableRead {
                requests: &requests,
                mode: AnalysisReadModeV1::Complete,
                now: 1000,
                event_ranges: None
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None
        )
        .is_err());
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(held);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        read(&store, &selection)?.extraction.graph_traversal(),
        Some(receipt)
    );
    assert_eq!(
        store.graph_result([1; 16], &first.result_id)?,
        Some(first_graph)
    );
    Ok(())
}

#[test]
fn projections_keep_optional_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("data"))?;
    let (_, model, source, observation) = fixture_source(&store, true)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    commit(&store, &model, &observation, 0)?;
    let reference = store.processor_result(&scope)?.ok_or("Source result")?;
    let requests = ["graph_subjects", "relationships", "findings"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect();
    let selection = AnalysisSelectionV1::new([1; 16], vec![source]);
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &requests,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    for (name, expected) in [("graph_subjects", 2), ("relationships", 1), ("findings", 1)] {
        assert_eq!(
            page.tables[name]
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>(),
            expected
        );
    }
    assert!(store.graph_result([1; 16], &reference.result_id).is_err());
    let schema = &araphor_data::AnalysisStore::table_schemas()["graph_manifest"];
    let complete = [(
        "graph_manifest".into(),
        Some([schema.index_of("snapshot")?].into()),
    )]
    .into();
    assert!(store
        .read_tables(
            &selection,
            AnalysisTableRead {
                requests: &complete,
                mode: AnalysisReadModeV1::Complete,
                now: 1000,
                event_ranges: None
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_err());
    Ok(())
}
