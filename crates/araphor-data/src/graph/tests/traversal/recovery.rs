use super::*;

#[tokio::test]
async fn native_traversal_replacement_history() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let original = &fixture.requests[0];
    let mut snapshot = GraphSnapshotV1::try_from(original.body.as_slice())?;
    snapshot.graph.edges.clear();
    fixture.replace(0, snapshot, "graph:traversal:replacement")?;
    let current = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    assert_eq!(
        TraversalFixture::depths(&current)?,
        BTreeMap::from([(TraversalFixture::subject(0), 0)])
    );
    let mut historical = TraversalFixture::request(8);
    historical.result_ids = fixture
        .requests
        .iter()
        .map(|request| request.result_id.clone())
        .collect();
    let retained = fixture.query(historical, SUBJECT_SQL).await?;
    assert_eq!(retained.rows.len(), 8);
    assert_eq!(
        fixture
            .native
            .store
            .read_result(source().tenant_id, &original.result_id)?,
        Some(original.body.clone())
    );
    let mut absent = TraversalFixture::request(8);
    absent.result_ids = vec!["graph:traversal:absent".into()];
    assert!(matches!(
        fixture.query(absent, SUBJECT_SQL).await,
        Err(Error::QueryDenied { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn native_traversal_reopen_and_restore() -> TestResult {
    let fixture = TraversalFixture::new(false)?;
    let before = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    let expected = TraversalFixture::depths(&before)?;
    let receipt = before.graph_traversal.clone();
    drop(before);
    let TraversalFixture { native, requests } = fixture;
    let native_storage::CommitFixture {
        directory,
        owner,
        store,
        snapshot,
        request,
    } = native;
    drop(owner);
    drop(store);
    let root = directory.path().join("analysis");
    let store = Arc::new(AnalysisStore::open(&root)?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    let fixture = TraversalFixture {
        native: native_storage::CommitFixture {
            directory,
            owner,
            store,
            snapshot,
            request,
        },
        requests,
    };
    let reopened = fixture
        .query(TraversalFixture::request(8), SUBJECT_SQL)
        .await?;
    assert_eq!(TraversalFixture::depths(&reopened)?, expected);
    assert_eq!(reopened.graph_traversal, receipt);
    drop(reopened);
    let backup = root.join("backups/traversal");
    fixture.native.store.backup(&backup)?;
    let restored = Arc::new(AnalysisStore::restore(
        &backup,
        &fixture.native.directory.path().join("restored"),
    )?);
    let _owner = GraphAndFindingOwner::new(restored.clone(), Arc::new(Inputs::default()))?;
    let plan = QueryPlan::client_graph(
        QueryGrant {
            principal: "traversal-test".into(),
            revision: 1,
            selection: AnalysisSelectionV1::new(source().tenant_id, vec![source()]),
        },
        QuerySql::admit(SUBJECT_SQL, vec![], false)?,
        TraversalFixture::request(8),
    )?;
    let result = Arc::new(QueryOwner::new(restored, QueryLimits::default())?)
        .query_client(
            plan,
            Arc::new(Authority::new(source().tenant_id)),
            100,
            Arc::new(AnalysisReadControl::default()),
        )
        .await?;
    assert_eq!(TraversalFixture::depths(&result)?, expected);
    assert_eq!(result.graph_traversal, receipt);
    Ok(())
}
