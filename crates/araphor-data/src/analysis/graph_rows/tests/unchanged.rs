use super::*;

#[test]
fn unchanged_findings_reuse_values_and_membership() -> TestResult {
    let fixture = CommitFixture::new()?;
    let first = fixture.snapshot;
    let path = fixture._directory.path().join("unchanged.duckdb");
    let writer = Connection::open(&path)?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
            tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
            method_version UBIGINT, first_cursor UBIGINT, facts_revision UBIGINT,
            coverage_revision UBIGINT, commit_revision UBIGINT);
         CREATE TABLE source_receipts (stream_key BLOB PRIMARY KEY,
            identity_json VARCHAR, tenant_id BLOB)",
    )?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute(
        "INSERT INTO source_receipts VALUES (?, ?, ?)",
        params![
            first.scope.identity.key(),
            serde_json::to_string(&first.scope.identity)?,
            first.scope.identity.tenant_id.as_slice()
        ],
    )?;
    let insert_result = |writer: &Connection, id: &str, revision: u64, graph: &GraphSnapshotV1| {
        writer.execute(
            "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                graph.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(graph)?,
                graph.scope.identity.key(),
                graph.scope.method_version,
                graph.first_cursor,
                graph.context_notice_revision,
                fixture.request.coverage_revision,
                revision
            ],
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    insert_result(&writer, "first", 1, &first)?;
    GraphRows::insert(&first, &writer, "first")?;
    let finding: (u64, u64, Option<u64>) = writer.query_row(
        "SELECT value_id, valid_from, valid_to FROM graph_finding_membership",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let branches = {
        let mut statement = writer.prepare(
            "SELECT ordinal, branch_id, valid_from, valid_to
             FROM graph_branch_membership ORDER BY ordinal",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut next = first.clone();
    next.previous_result_id = Some("first".into());
    next.last_cursor = 2;
    let mut record = next.input_manifest.evidence[0].clone();
    record.durable_cursor = 2;
    next.input_manifest.evidence.push(record);
    let mut edge = next.graph.edges[0].clone();
    edge.key.evidence = vec![1];
    next.graph.edges.push(edge);
    next.graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    next.validate()?;
    insert_result(&writer, "next", 2, &next)?;
    let reference = PackageResultRefV1 {
        result_id: "first".into(),
        commit_revision: 1,
    };
    let wrong = PackageResultRefV1 {
        result_id: "wrong".into(),
        commit_revision: 1,
    };
    assert!(matches!(
        GraphRows::insert_with_reuse(&next, &writer, "next", Some(&wrong)),
        Err(crate::Error::GraphInvalid {
            field: "graph unchanged finding base",
            ..
        })
    ));
    GraphRows::insert_with_reuse(&next, &writer, "next", Some(&reference))?;
    let current_finding: (u64, u64, Option<u64>) = writer.query_row(
        "SELECT value_id, valid_from, valid_to FROM graph_finding_membership",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(current_finding, finding);
    assert_eq!(finding.1, 1);
    assert_eq!(finding.2, None);
    let current_branches = {
        let mut statement = writer.prepare(
            "SELECT ordinal, branch_id, valid_from, valid_to
             FROM graph_branch_membership ORDER BY ordinal",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    assert_eq!(current_branches, branches);
    let header = GraphRows::read_header(&writer, first.scope.identity.tenant_id, "next")?
        .ok_or("missing updated Graph")?;
    assert_eq!(GraphRows::read(&writer, "next", &header)?, next);
    let first_header = GraphRows::read_header(&writer, first.scope.identity.tenant_id, "first")?
        .ok_or("missing old Graph")?;
    assert_eq!(GraphRows::read(&writer, "first", &first_header)?, first);
    drop(writer);
    let reader = Connection::open(&path)?;
    let header = GraphRows::read_header(&reader, first.scope.identity.tenant_id, "next")?
        .ok_or("missing reopened Graph")?;
    assert_eq!(GraphRows::read(&reader, "next", &header)?, next);
    let first_header = GraphRows::read_header(&reader, first.scope.identity.tenant_id, "first")?
        .ok_or("missing reopened old Graph")?;
    assert_eq!(GraphRows::read(&reader, "first", &first_header)?, first);
    Ok(())
}
