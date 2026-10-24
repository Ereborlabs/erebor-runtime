use super::*;

#[tokio::test]
async fn traversal_replacement_history() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let original = &fixture.requests[0];
    let mut snapshot = GraphSnapshotV1::try_from(original.body.as_slice())?;
    snapshot.graph.edges.clear();
    fixture.replace(0, snapshot, "graph:traversal:replacement")?;
    let current = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    assert_eq!(
        TraversalFixture::depths(&current.1)?,
        BTreeMap::from([(TraversalFixture::subject(0), 0)])
    );
    let mut historical = TraversalFixture::request(8);
    historical.result_ids = fixture
        .requests
        .iter()
        .map(|request| request.result_id.clone())
        .collect();
    let mut expected = historical.result_ids.clone();
    expected.sort();
    let retained = fixture.query(historical, SUBJECT_SQL).await?;
    let mut selected = retained
        .0
        .page
        .extraction
        .graph_traversal()
        .ok_or("historical traversal receipt")?
        .result_ids
        .clone();
    selected.sort();
    assert_eq!(selected, expected);
    assert_eq!(
        retained.1.iter().map(RecordBatch::num_rows).sum::<usize>(),
        8
    );
    assert_eq!(
        fixture
            .store
            .read_result(source().tenant_id, &original.result_id)?,
        Some(original.body.clone())
    );
    let mut denied = TraversalFixture::request(8);
    denied.result_ids = vec![original.result_id.clone()];
    let error = fixture
        .selected(
            denied,
            AnalysisSelectionV1::new(source().tenant_id, Vec::new()),
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
        .await
        .err()
        .ok_or("graph result without source permission")?;
    assert!(matches!(
        TraversalFixture::data_error(error.as_ref()),
        Some(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    let mut absent = TraversalFixture::request(8);
    absent.result_ids = vec!["graph:traversal:absent".into()];
    let error = fixture
        .query(absent, SUBJECT_SQL)
        .await
        .err()
        .ok_or("absent graph result")?;
    assert!(matches!(
        TraversalFixture::data_error(error.as_ref()),
        Some(araphor_data::Error::AnalysisReadDenied { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn traversal_reopen_and_restore() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let before = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    let expected = TraversalFixture::depths(&before.1)?;
    let receipt = before.0.page.extraction.graph_traversal().cloned();
    drop(before);
    let TraversalFixture {
        directory,
        store,
        requests,
        _graph: graph_lease,
    } = fixture;
    drop(graph_lease);
    drop(store);
    let root = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open(&root)?);
    let graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source().tenant_id)])?;
    store.register_graph(&source())?;
    let fixture = TraversalFixture {
        directory,
        store,
        requests,
        _graph: graph,
    };
    let reopened = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    assert_eq!(TraversalFixture::depths(&reopened.1)?, expected);
    assert_eq!(
        reopened.0.page.extraction.graph_traversal(),
        receipt.as_ref()
    );
    drop(reopened);
    let backup = root.join("backups/traversal");
    fixture.store.backup(&backup)?;
    let restored = Arc::new(AnalysisStore::restore(
        &backup,
        &fixture.directory.path().join("restored"),
    )?);
    let saved = fixture.store.package_revisions(source().tenant_id)?;
    assert_eq!(saved.len(), 4);
    assert_eq!(restored.package_revisions(source().tenant_id)?, saved);
    let _graph = restored.lease_graph(vec![AnalysisSelectionV1::tenant(source().tenant_id)])?;
    restored.register_graph(&source())?;
    let result = TraversalFixture::read(
        restored,
        TraversalFixture::request(8),
        AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
        Limits::default(),
        Arc::new(AnalysisReadControl::default()),
        SUBJECT_SQL,
    )
    .await?;
    assert_eq!(TraversalFixture::depths(&result.1)?, expected);
    assert_eq!(result.0.page.extraction.graph_traversal(), receipt.as_ref());
    Ok(())
}
