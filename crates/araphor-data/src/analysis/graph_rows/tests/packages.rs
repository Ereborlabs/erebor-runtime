use super::CommitFixture;
use super::*;

#[test]
fn graph_appender_constraint_rollback() -> TestResult {
    let fixture = CommitFixture::new()?;
    assert!(!fixture.snapshot.graph.subjects.is_empty());
    assert!(!fixture.snapshot.graph.edges.is_empty());
    assert!(!fixture.snapshot.findings.is_empty());
    let original = araphor_graph::FindingRows::SCHEMA;
    let (table, _) = original
        .split_once("CREATE INDEX graph_finding_identity")
        .ok_or("finding value schema")?;
    let (_, view) = original
        .split_once("CREATE VIEW graph_findings")
        .ok_or("finding view schema")?;
    let view = format!("CREATE VIEW graph_findings{view}");
    let rejecting = table.replace(
        "value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32)\n);",
        "value_hash BLOB NOT NULL CHECK (octet_length(value_hash) = 32), CHECK (false)\n);",
    );
    assert_ne!(rejecting, table);
    fixture.store.fault_write(
        &format!("DROP VIEW graph_findings; DROP TABLE graph_finding_values; {rejecting} {view}"),
        &[],
    )?;
    let before = fixture.store.meta()?;
    let usage = fixture
        .store
        .witness_usage(fixture.request.scope.identity.tenant_id, 10)?;
    let mut request = fixture.request.clone();
    request.body.clear();
    let prepared = crate::analysis::graph_rows::CanonicalGraph::new(fixture.snapshot.clone())?;
    assert!(matches!(
        fixture
            .store
            .commit_graph_snapshot(request, prepared, &[], &[], &[], true, || Ok(())),
        Err(crate::Error::AnalysisDatabase { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(
        fixture
            .store
            .witness_usage(fixture.request.scope.identity.tenant_id, 10)?,
        usage
    );
    assert!(fixture
        .store
        .read_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id
        )?
        .is_none());
    let writer = fixture.store.writer_access()?;
    for table in [
        "graph_subjects",
        "graph_relationships",
        "graph_edge_values",
        "graph_edge_membership",
        "graph_findings",
        "graph_finding_values",
        "graph_finding_membership",
        "evidence_refs",
    ] {
        let count: u64 =
            writer
                .get()?
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
        assert_eq!(count, 0, "retained rows in {table}");
    }
    drop(writer);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.request.scope)?
            .ok_or("processor health")?
            .consumed_cursor,
        0
    );
    fixture.store.fault_write(
        &format!(
            "DROP VIEW graph_findings; DROP TABLE graph_finding_values;
                 {table} CREATE INDEX graph_finding_identity
                 ON graph_finding_values (value_hash); {view}"
        ),
        &[],
    )?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    assert_eq!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?,
        receipt
    );
    Ok(())
}

#[test]
fn graph_typed_commit_matches_bytes() -> TestResult {
    use crate::analysis::graph_rows::CanonicalGraph;
    let byte = CommitFixture::new()?;
    let typed = CommitFixture::new()?;
    assert_eq!(byte.snapshot, typed.snapshot);
    assert_eq!(byte.request, typed.request);
    let receipt = byte.store.commit_graph(&byte.request, true, || Ok(()))?;
    let mut metadata = typed.request.clone();
    metadata.body.clear();
    let actual = typed.store.commit_graph_snapshot(
        metadata.clone(),
        CanonicalGraph::new(typed.snapshot.clone())?,
        &[],
        &[],
        &[],
        true,
        || Ok(()),
    )?;
    assert_eq!(actual, receipt);
    assert_eq!(
        typed.store.commit_graph_snapshot(
            metadata.clone(),
            CanonicalGraph::new(typed.snapshot.clone())?,
            &[],
            &[],
            &[],
            true,
            || Ok(()),
        )?,
        receipt
    );
    for fixture in [&byte, &typed] {
        assert_eq!(
            fixture.store.graph_result(
                fixture.request.scope.identity.tenant_id,
                &fixture.request.result_id
            )?,
            Some(fixture.snapshot.clone())
        );
        assert_eq!(
            fixture
                .store
                .graph_snapshot(&fixture.request.scope.identity)?,
            Some(fixture.snapshot.clone())
        );
    }
    let left = byte.store.writer_access()?;
    let right = typed.store.writer_access()?;
    let retained = |connection: &duckdb::Connection| -> duckdb::Result<Vec<u8>> {
        connection.query_row(
            "SELECT body FROM analysis_results WHERE result_id = ?",
            duckdb::params![byte.request.result_id],
            |row| row.get(0),
        )
    };
    assert_eq!(retained(left.get()?)?, retained(right.get()?)?);
    for table in [
        "graph_subjects",
        "graph_relationships",
        "graph_edge_values",
        "graph_edge_membership",
        "graph_findings",
        "evidence_refs",
        "context_refs",
        "processor_progress",
    ] {
        let sql = format!("SELECT to_json(t)::VARCHAR FROM {table} t ORDER BY 1");
        let read = |connection: &duckdb::Connection| -> duckdb::Result<Vec<String>> {
            connection
                .prepare(&sql)?
                .query_map([], |row| row.get(0))?
                .collect()
        };
        assert_eq!(read(left.get()?)?, read(right.get()?)?, "retained {table}");
    }
    drop(left);
    drop(right);
    let mut changed = typed.snapshot.clone();
    changed.findings[0].limits.push("RETRY_CHANGED".into());
    changed.findings[0].limits.sort();
    assert!(matches!(
        typed.store.commit_graph_snapshot(
            metadata,
            CanonicalGraph::new(changed)?,
            &[],
            &[],
            &[],
            true,
            || Ok(())
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(typed.store.meta()?.commit_revision, receipt.commit_revision);
    Ok(())
}
