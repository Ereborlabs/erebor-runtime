use super::*;

#[tokio::test]
async fn native_traversal_binding_membership() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let seed = TraversalFixture::subject(1);
    let first = GraphSnapshotV1::try_from(fixture.requests[0].body.as_slice())?;
    assert!(first
        .findings
        .iter()
        .all(|finding| finding.subject_id != seed));
    assert!(first.graph.edges.iter().any(
        |edge| (edge.key.from == seed || edge.key.to == seed) && !edge.key.evidence.is_empty()
    ));
    let mut other = GraphSnapshotV1::try_from(fixture.requests[1].body.as_slice())?;
    assert!(other
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.from != seed && edge.key.to != seed));
    other.graph.subjects.push(seed.clone());
    other.graph.subjects.sort();
    fixture.replace(1, other, "graph:traversal:isolated")?;
    let mut request = TraversalFixture::request(0);
    request.seeds = vec![seed.clone()];
    let unscoped = fixture.query(request.clone(), SUBJECT_SQL).await?;
    assert_eq!(
        unscoped
            .graph_traversal
            .as_ref()
            .ok_or("unscoped receipt")?
            .versioned_subject_count,
        2
    );
    let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
    selection.binding_ids.push([10; 16]);
    for edge_types in [vec![], vec![GraphEdgeTypeV1::NativeEffect]] {
        request.edge_types = edge_types;
        let result = fixture
            .selected(
                request.clone(),
                selection.clone(),
                QueryLimits::default(),
                Arc::new(AnalysisReadControl::default()),
                SUBJECT_SQL,
            )
            .await?;
        assert_eq!(
            TraversalFixture::depths(&result)?,
            BTreeMap::from([(seed.clone(), 0)])
        );
        let receipt = result.graph_traversal.as_ref().ok_or("binding receipt")?;
        assert_eq!(receipt.unique_subject_count, 1);
        assert_eq!(receipt.versioned_subject_count, 1);
        assert_eq!(receipt.relationship_count, 0);
    }
    Ok(())
}
