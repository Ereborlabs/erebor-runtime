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
    let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
    selection.select_graphs(Selection::Exact(historical.result_ids.clone()), None)?;
    let retained = fixture
        .selected(
            historical,
            selection,
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
        .await?;
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
    let mut absent = TraversalFixture::request(8);
    absent.result_ids = vec!["graph:traversal:absent".into()];
    let mut selection = AnalysisSelectionV1::new(source().tenant_id, vec![source()]);
    selection.select_graphs(Selection::Exact(absent.result_ids.clone()), None)?;
    let error = fixture
        .selected(
            absent,
            selection,
            Limits::default(),
            Arc::new(AnalysisReadControl::default()),
            SUBJECT_SQL,
        )
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
    } = fixture;
    drop(store);
    let root = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open(&root)?);
    store.enable_graph_owner()?;
    store.register_graph(&source())?;
    let fixture = TraversalFixture {
        directory,
        store,
        requests,
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
    restored.enable_graph_owner()?;
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
