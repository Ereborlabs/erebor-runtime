use super::*;
use sha2::Sha256;

#[test]
fn branch_values_keep_history_order_and_duplicates() -> TestResult {
    let fixture = CommitFixture::new()?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let branch = crate::GraphBranchV1::from_value(&fixture.snapshot.findings[0]);
    let mut changed = branch.clone();
    changed.state = crate::GraphBranchStateV1::CoverageUnknown;
    changed.missing_fields.push("changed".into());
    let root = tempfile::tempdir()?;
    let path = root.path().join("branches.duckdb");
    let writer = Connection::open(&path)?;
    writer.execute_batch(&GraphRows::schema())?;
    let versions = [
        (
            "first",
            1,
            1,
            vec![branch.clone(), branch.clone(), changed.clone()],
        ),
        (
            "same",
            1,
            2,
            vec![branch.clone(), branch.clone(), changed.clone()],
        ),
        (
            "reordered",
            1,
            3,
            vec![changed.clone(), branch.clone(), branch.clone()],
        ),
        ("empty", 1, 4, vec![]),
        ("reentered", 1, 5, vec![branch.clone()]),
        ("independent", 2, 6, vec![branch.clone()]),
    ];
    for (id, lineage, revision, branches) in &versions {
        NativeRows::bind(&writer, id, *lineage, *revision)?;
        NativeRows::branches(&writer, tenant, *lineage, *revision, branches)?;
        assert_eq!(
            NativeRows::read_branches(&writer, id, tenant, branches.len(), None)?,
            *branches,
            "{id}"
        );
    }
    let values: u64 = writer.query_row(
        "SELECT count(*)::UBIGINT FROM graph_branch_values",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(values, 2);
    drop(writer);
    let mut writer = Connection::open(&path)?;
    for (id, _, _, branches) in &versions {
        assert_eq!(
            NativeRows::read_branches(&writer, id, tenant, branches.len(), None)?,
            *branches,
            "reopened {id}"
        );
    }
    {
        let transaction = writer.transaction()?;
        NativeRows::bind(&transaction, "rolled-back", 1, 7)?;
        NativeRows::branches(&transaction, tenant, 1, 7, &[])?;
    }
    assert_eq!(
        writer.query_row::<u64, _, _>(
            "SELECT count(*)::UBIGINT FROM graph_versions",
            [],
            |row| row.get(0)
        )?,
        versions.len() as u64
    );
    {
        let transaction = writer.transaction()?;
        transaction.execute(
            "INSERT INTO graph_producer_members VALUES (1,6,from_hex('0000'),1,NULL,NULL,NULL,0,4,NULL)",
            [],
        )?;
        assert!(NativeRows::read_branches(&transaction, "empty", tenant, 0, None).is_err());
    }
    {
        let transaction = writer.transaction()?;
        transaction.execute("DELETE FROM graph_branch_values WHERE branch_id = 1", [])?;
        assert!(NativeRows::read_branches(&transaction, "first", tenant, 3, None).is_err());
    }
    {
        let transaction = writer.transaction()?;
        let mut body: Vec<u8> = transaction.query_row(
            "SELECT body FROM graph_branch_values WHERE branch_id = 1",
            [],
            |row| row.get(0),
        )?;
        body.push(0);
        let hash = Sha256::digest(&body);
        transaction.execute(
            "UPDATE graph_branch_values SET body = ?, value_hash = ? WHERE branch_id = 1",
            params![body, hash.as_slice()],
        )?;
        assert!(NativeRows::read_branches(&transaction, "first", tenant, 3, None).is_err());
    }
    Ok(())
}

#[test]
fn branch_headers_restore_exact_values() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut graph = fixture.snapshot.clone();
    let branch = crate::GraphBranchV1::from_value(&graph.findings[0]);
    graph.graph.branches = vec![branch.clone(), branch];
    let tenant = graph.scope.identity.tenant_id;
    let mut request = fixture.request.clone();
    request.body.clear();
    fixture.store.commit_graph_snapshot(
        request,
        CanonicalGraph::new(graph.clone())?,
        &[],
        &[],
        &[],
        true,
        || Ok(()),
    )?;
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(graph.clone())
    );
    fixture.store.read_snapshot(|reader| {
        let bytes: Vec<u8> = reader
            .query_row(
                "SELECT body FROM analysis_results WHERE result_id = ?",
                params![&fixture.request.result_id],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read branch test header",
            })?;
        let raw = GraphHeader::decode(&bytes)?;
        assert_eq!(raw.branch_count, 2);
        assert!(raw.snapshot.graph.branches.is_empty());
        assert_eq!(
            GraphRows::read_control(reader, &fixture.request.result_id, &raw, None)?,
            graph
        );
        let mut visited = 0;
        GraphRows::visit_headers(
            reader,
            tenant,
            std::slice::from_ref(&fixture.request.result_id),
            &AnalysisReadControl::default(),
            |_, header, _, _| {
                visited += 1;
                assert_eq!(header.snapshot.graph.branches, graph.graph.branches);
                assert!(header.branches_loaded);
                Ok(())
            },
        )?;
        assert_eq!(visited, 1);
        Ok(())
    })?;
    Ok(())
}
