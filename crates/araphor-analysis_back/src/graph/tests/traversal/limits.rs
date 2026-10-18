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
    let error = fixture
        .query(request.clone(), "SELECT COUNT(*) FROM graph_subjects")
        .await
        .err()
        .ok_or("traversal subject cap")?;
    assert!(matches!(
        TraversalFixture::data_error(&error),
        Some(araphor_data::Error::AnalysisInputTooLarge { .. })
    ));
    request.max_subjects = 63;
    request.max_relationships = 62;
    let result = fixture
        .query(request, "SELECT COUNT(*) FROM graph_subjects")
        .await?;
    assert_eq!(TraversalFixture::count(&result.1)?, 63);
    let receipt = result
        .0
        .page
        .extraction
        .graph_traversal()
        .ok_or("fanout receipt")?;
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
        let error = fixture
            .query(request, "SELECT COUNT(*) FROM relationships")
            .await
            .err()
            .ok_or("traversal graph cap")?;
        assert!(matches!(
            TraversalFixture::data_error(&error),
            Some(araphor_data::Error::AnalysisInputTooLarge { .. })
        ));
    }
    let mut exact = TraversalFixture::request(8);
    exact.max_subjects = 10;
    exact.max_relationships = 9;
    let complete = fixture
        .query(exact, "SELECT COUNT(*) FROM relationships")
        .await?;
    assert_eq!(TraversalFixture::count(&complete.1)?, 9);
    for limits in [
        Limits {
            scan_bytes: 1,
            ..Default::default()
        },
        Limits {
            input_bytes: 1_024,
            ..Default::default()
        },
    ] {
        let error = fixture
            .selected(
                TraversalFixture::request(8),
                AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
                limits,
                Arc::new(AnalysisReadControl::default()),
                "SELECT COUNT(*) FROM relationships",
            )
            .await
            .err()
            .ok_or("traversal input cap")?;
        assert!(matches!(
            TraversalFixture::data_error(&error),
            Some(araphor_data::Error::AnalysisInputTooLarge { .. })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn native_traversal_cancel_and_deadline() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let cancelled = Arc::new(AnalysisReadControl::default());
    cancelled.cancel()?;
    let error = fixture
        .selected(
            TraversalFixture::request(8),
            AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
            Limits::default(),
            cancelled,
            SUBJECT_SQL,
        )
        .await
        .err()
        .ok_or("cancelled traversal")?;
    assert!(matches!(
        TraversalFixture::data_error(&error),
        Some(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    let expired = Arc::new(AnalysisReadControl::with_timeout(
        std::time::Duration::from_nanos(1),
    )?);
    let error = fixture
        .selected(
            TraversalFixture::request(8),
            AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
            Limits::default(),
            expired,
            SUBJECT_SQL,
        )
        .await
        .err()
        .ok_or("expired traversal")?;
    assert!(matches!(
        TraversalFixture::data_error(&error),
        Some(araphor_data::Error::AnalysisReadDeadline { .. })
    ));
    assert_eq!(
        fixture
            .query(TraversalFixture::request(8), SUBJECT_SQL)
            .await?
            .1
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        8
    );
    fixture.native.store.checkpoint()?;
    Ok(())
}
