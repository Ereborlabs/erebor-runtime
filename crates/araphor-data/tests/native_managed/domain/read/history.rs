use super::*;
use araphor_data::{GraphTraversalV1, ProcessorClassV1, ProcessorScopeV1};

fn manifest_ids(page: &AnalysisPositionPageV1) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut ids = Vec::new();
    for batch in page.tables.get("graph_manifest").into_iter().flatten() {
        let values = batch
            .column_by_name("graph_result_id")
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or("Graph result ID")?;
        ids.extend((0..batch.num_rows()).map(|index| values.value(index).to_owned()));
    }
    ids.sort();
    Ok(ids)
}

#[test]
fn analysis_exact_graph_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("data"))?;
    let (_, model, source, observation) = fixture_source(&store, true)?;
    let scope = ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    let states = [araphor_analysis_types::GraphStateMember {
        record: None,
        position: None,
        fact: None,
        state: araphor_analysis_types::GraphPackageStateV1::Declared("retained".into()),
    }];
    commit_named_expiry(
        &store,
        &model,
        &observation,
        0,
        None,
        "domain",
        Some((&states, false)),
    )?;
    let first = store.processor_result(&scope)?.ok_or("first result")?;
    let snapshot = store
        .graph_result([1; 16], &first.result_id)?
        .ok_or("first Graph")?;
    assert_eq!(snapshot.graph.edges.len(), 1);
    let original = algorithm::RelationshipIdentity::from_keys(
        &snapshot.graph.edges[0].key,
        &snapshot.graph.subjects,
        &snapshot.input_manifest.evidence,
    )?;
    let edge = algorithm::RelationshipChange {
        anchor: algorithm::Anchor {
            record: observation.id.clone(),
            fact: None,
        },
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
        algorithm::RelationshipChange::encode(&[edge])?,
        true,
    )?;
    commit_commands(
        &store,
        &model,
        &observation,
        1,
        None,
        "domain",
        None,
        &[(DomainRelations::RELATIONSHIPS.into(), removed)],
        None,
    )?;
    let second = store.processor_result(&scope)?.ok_or("second result")?;
    assert_ne!(first.result_id, second.result_id);
    assert!(store
        .graph_result([1; 16], &second.result_id)?
        .ok_or("second Graph")?
        .graph
        .edges
        .is_empty());
    assert_eq!(
        store
            .graph_result([1; 16], &first.result_id)?
            .ok_or("historical Graph")?,
        snapshot
    );
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let schema = &araphor_data::AnalysisStore::table_schemas()["graph_manifest"];
    let requests = AnalysisTableRequests::from([(
        "graph_manifest".into(),
        Some(
            ["graph_result_id", "subject_count", "relationship_count"]
                .into_iter()
                .map(|name| schema.index_of(name))
                .collect::<Result<_, _>>()?,
        ),
    )]);
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
            &control,
        )
    };
    let ids = vec![first.result_id.clone(), second.result_id.clone()];
    let mut expected = ids.clone();
    expected.sort();
    let mut exact = AnalysisSelectionV1::new([1; 16], vec![source]);
    exact.select_graphs(Selection::Exact(ids.clone()), None)?;
    let before = store.meta()?;
    let page = read(&exact, AnalysisExtractLimits::default())?;
    assert_eq!(manifest_ids(&page)?, expected);
    let mut all = exact.clone();
    all.select_graphs(Selection::All, None)?;
    let page = read(&all, AnalysisExtractLimits::default())?;
    assert_eq!(manifest_ids(&page)?, [second.result_id.clone()]);
    assert_eq!(value(&page, "graph_manifest", "relationship_count")?, 0);
    let traversal = GraphTraversalV1 {
        seeds: vec![original.from],
        result_ids: vec![first.result_id.clone()],
        ..Default::default()
    };
    let mut requested = all.clone();
    requested.select_graphs(Selection::All, Some(traversal.clone()))?;
    let page = read(&requested, AnalysisExtractLimits::default())?;
    assert_eq!(
        page.extraction
            .graph_traversal()
            .ok_or("traversal receipt")?
            .result_ids,
        traversal.result_ids
    );
    assert!(page.extraction.input_bytes >= requested.allocation_bytes());
    for limits in [
        AnalysisExtractLimits {
            keys: Some(1),
            ..Default::default()
        },
        AnalysisExtractLimits {
            input_bytes: requested.allocation_bytes(),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            read(&requested, limits),
            Err(Error::AnalysisInputTooLarge {
                resource: "selected input keys",
                ..
            })
        ));
    }
    let mut permitted = exact.clone();
    permitted.select_graphs(Selection::Exact(ids), Some(traversal.clone()))?;
    let page = read(&permitted, AnalysisExtractLimits::default())?;
    assert_eq!(
        page.extraction
            .graph_traversal()
            .ok_or("permitted receipt")?
            .result_ids,
        traversal.result_ids
    );
    let bounded = read(
        &permitted,
        AnalysisExtractLimits {
            keys: Some(2),
            ..Default::default()
        },
    )?;
    assert_eq!(
        bounded
            .extraction
            .graph_traversal()
            .ok_or("bounded receipt")?
            .result_ids,
        traversal.result_ids
    );
    for graphs in [vec![second.result_id], Vec::new()] {
        let mut denied = exact.clone();
        denied.select_graphs(Selection::Exact(graphs), Some(traversal.clone()))?;
        assert!(matches!(
            read(&denied, AnalysisExtractLimits::default()),
            Err(Error::AnalysisReadDenied { .. })
        ));
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}
