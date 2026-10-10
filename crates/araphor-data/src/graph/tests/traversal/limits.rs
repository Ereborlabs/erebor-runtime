use super::*;

#[tokio::test]
async fn native_traversal_fanout_caps() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let mut snapshot = GraphSnapshotV1::try_from(fixture.requests[0].body.as_slice())?;
    let template = snapshot
        .graph
        .edges
        .iter()
        .find(|edge| edge.key.from == TraversalFixture::subject(0))
        .ok_or("fanout edge")?
        .clone();
    for index in 100..160 {
        let subject = TraversalFixture::subject(index);
        snapshot.graph.subjects.push(subject.clone());
        let mut edge = template.clone();
        edge.key.to = subject;
        snapshot.graph.edges.push(edge);
    }
    snapshot.graph.subjects.sort();
    snapshot
        .graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    fixture.replace(0, snapshot, "graph:traversal:fanout")?;
    let mut request = TraversalFixture::request(1);
    request.max_subjects = 16;
    assert!(matches!(
        fixture
            .query(request.clone(), "SELECT COUNT(*) FROM graph_subjects")
            .await,
        Err(Error::AnalysisInputTooLarge { .. })
    ));
    request.max_subjects = 63;
    request.max_relationships = 62;
    let result = fixture
        .query(request, "SELECT COUNT(*) FROM graph_subjects")
        .await?;
    assert_eq!(result.rows, vec![vec![Value::BigInt(63)]]);
    let receipt = result.graph_traversal.as_ref().ok_or("fanout receipt")?;
    assert_eq!(receipt.unique_subject_count, 63);
    assert_eq!(receipt.versioned_subject_count, 63);
    assert_eq!(receipt.relationship_count, 62);
    assert!(receipt.hop_boundary);
    Ok(())
}

#[tokio::test]
async fn native_traversal_input_caps() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    for (subjects, edges) in [(7, 9), (9, 9), (10, 8)] {
        let mut request = TraversalFixture::request(8);
        request.max_subjects = subjects;
        request.max_relationships = edges;
        assert!(matches!(
            fixture
                .query(request, "SELECT COUNT(*) FROM relationships")
                .await,
            Err(Error::AnalysisInputTooLarge { .. })
        ));
    }
    let mut exact = TraversalFixture::request(8);
    exact.max_subjects = 10;
    exact.max_relationships = 9;
    let complete = fixture
        .query(exact, "SELECT COUNT(*) FROM relationships")
        .await?;
    assert_eq!(complete.rows, vec![vec![Value::BigInt(9)]]);
    for limits in [
        QueryLimits {
            scan_bytes: 1,
            ..Default::default()
        },
        QueryLimits {
            input_bytes: 1_024,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            fixture
                .selected(
                    TraversalFixture::request(8),
                    AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
                    limits,
                    Arc::new(AnalysisReadControl::default()),
                    "SELECT COUNT(*) FROM relationships"
                )
                .await,
            Err(Error::AnalysisInputTooLarge { .. })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn native_traversal_cancel_and_deadline() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let cancelled = Arc::new(AnalysisReadControl::default());
    cancelled.cancel()?;
    assert!(matches!(
        fixture
            .selected(
                TraversalFixture::request(8),
                AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
                QueryLimits::default(),
                cancelled,
                SUBJECT_SQL
            )
            .await,
        Err(Error::AnalysisReadCancelled { .. })
    ));
    let expired = Arc::new(AnalysisReadControl::with_timeout(
        std::time::Duration::from_nanos(1),
    )?);
    assert!(matches!(
        fixture
            .selected(
                TraversalFixture::request(8),
                AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
                QueryLimits::default(),
                expired,
                SUBJECT_SQL
            )
            .await,
        Err(Error::AnalysisReadDeadline { .. })
    ));
    assert_eq!(
        fixture
            .query(TraversalFixture::request(8), SUBJECT_SQL)
            .await?
            .rows
            .len(),
        8
    );
    fixture.native.store.checkpoint()?;
    Ok(())
}
