use super::*;
use crate::graph::tests::native_storage::CommitFixture;
use duckdb::params;

#[test]
fn graph_package_commit_refs() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let refs = fixture.add_packages()?;
    let reference = fixture.request.context_refs[0].clone();
    let context = fixture
        .store
        .context_version(&reference.key)?
        .ok_or("package context absent")?;
    let before = fixture.store.meta()?;
    let mut changed = fixture.request.clone();
    changed.context_refs[0].key.entity_key = b"other-result".to_vec();
    assert!(fixture.store.commit_graph(&changed, true).is_err());
    fixture.store.writer_access()?.get_mut()?.execute(
        "UPDATE context_versions SET body = ? WHERE owner_id = ? AND entity_key = ?",
        params![
            b"invalid".as_slice(),
            reference.key.owner_id,
            reference.key.entity_key
        ],
    )?;
    assert!(fixture.store.commit_graph(&fixture.request, true).is_err());
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture
        .store
        .read_result(reference.key.tenant_id, &fixture.request.result_id)?
        .is_none());
    fixture.store.writer_access()?.get_mut()?.execute(
        "UPDATE context_versions SET body = ? WHERE owner_id = ? AND entity_key = ?",
        params![
            context.body,
            reference.key.owner_id,
            reference.key.entity_key
        ],
    )?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    assert_eq!(
        fixture
            .owner
            .snapshot_result(reference.key.tenant_id, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    assert_eq!(
        fixture
            .owner
            .installed_refs(reference.key.tenant_id, &fixture.request.result_id)?,
        Some(refs)
    );
    let retained = fixture
        .store
        .processor_result(&fixture.request.scope)?
        .ok_or("committed graph absent")?;
    let (_, contexts) = fixture.store.package_evidence(
        reference.key.tenant_id,
        std::slice::from_ref(&fixture.request.result_id),
    )?;
    assert_eq!(contexts, vec![reference]);
    assert_eq!(retained.body, fixture.request.body);
    Ok(())
}

#[test]
fn graph_appender_constraint_rollback() -> TestResult {
    let fixture = CommitFixture::new()?;
    assert!(!fixture.snapshot.graph.subjects.is_empty());
    assert!(!fixture.snapshot.graph.edges.is_empty());
    assert!(!fixture.snapshot.findings.is_empty());
    let (_, finding) = GraphRows::SCHEMA
        .split_once("CREATE TABLE graph_findings")
        .ok_or("finding schema")?;
    let original = format!("CREATE TABLE graph_findings{finding}");
    let rejecting = original.replace(
        "PRIMARY KEY (result_id, ordinal)",
        "CHECK (false), PRIMARY KEY (result_id, ordinal)",
    );
    fixture
        .store
        .fault_write(&format!("DROP TABLE graph_findings; {rejecting}"), &[])?;
    let before = fixture.store.meta()?;
    let usage = fixture
        .store
        .witness_usage(fixture.request.scope.identity.tenant_id, 10)?;
    let mut request = fixture.request.clone();
    request.body.clear();
    let prepared = crate::analysis::graph_rows::CanonicalGraph::new(fixture.snapshot.clone())?;
    assert!(matches!(
        fixture.store.commit_graph_snapshot(request, prepared, true),
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
        "graph_findings",
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
    fixture
        .store
        .fault_write(&format!("DROP TABLE graph_findings; {original}"), &[])?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    Ok(())
}

#[test]
fn graph_typed_commit_matches_bytes() -> TestResult {
    use crate::analysis::graph_rows::CanonicalGraph;
    let byte = CommitFixture::new()?;
    let typed = CommitFixture::new()?;
    assert_eq!(byte.snapshot, typed.snapshot);
    assert_eq!(byte.request, typed.request);
    let receipt = byte.store.commit_graph(&byte.request, true)?;
    let mut metadata = typed.request.clone();
    metadata.body.clear();
    let actual = typed.store.commit_graph_snapshot(
        metadata.clone(),
        CanonicalGraph::new(typed.snapshot.clone())?,
        true,
    )?;
    assert_eq!(actual, receipt);
    assert_eq!(
        typed.store.commit_graph_snapshot(
            metadata.clone(),
            CanonicalGraph::new(typed.snapshot.clone())?,
            true,
        )?,
        receipt
    );
    for fixture in [&byte, &typed] {
        assert_eq!(
            fixture.store.read_result(
                fixture.request.scope.identity.tenant_id,
                &fixture.request.result_id
            )?,
            Some(fixture.request.body.clone())
        );
        assert_eq!(
            fixture.owner.snapshot(&fixture.request.scope.identity)?,
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
        "graph_findings",
        "tenant_usage",
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
        typed
            .store
            .commit_graph_snapshot(metadata, CanonicalGraph::new(changed)?, true),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(typed.store.meta()?.commit_revision, receipt.commit_revision);
    Ok(())
}
