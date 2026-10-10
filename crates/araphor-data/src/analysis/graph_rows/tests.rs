use super::*;

mod encoding;
mod schema;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

impl crate::analysis::AnalysisStore {
    fn fault_write(&self, query: &str, values: &[&dyn duckdb::ToSql]) -> TestResult {
        let mut writer = self.writer_access()?;
        let writer = writer.get_mut()?;
        writer.execute_batch(&format!(
            "SET memory_limit='{}B'",
            4 * crate::analysis::NATIVE_MEMORY_BYTES
        ))?;
        let mutation = writer
            .execute(query, values)
            .and_then(|_| writer.execute_batch("CHECKPOINT"));
        let restored = writer.execute_batch(&format!(
            "SET memory_limit='{}B'",
            crate::analysis::NATIVE_MEMORY_BYTES
        ));
        mutation?;
        restored?;
        Ok(())
    }
}

#[test]
fn native_rows_integrity() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let graph = &fixture.snapshot;
    assert!(!graph.graph.subjects.is_empty());
    assert!(!graph.graph.edges.is_empty());
    assert!(!graph.findings.is_empty());
    let rows = GraphRows::encode(graph)?;
    let metadata = GraphHeader::decode(rows.header())?;
    assert!(metadata.snapshot.findings.is_empty());
    assert!(metadata.snapshot.graph.subjects.is_empty());
    assert!(metadata.snapshot.graph.edges.is_empty());
    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
        tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
        method_version UBIGINT, first_cursor UBIGINT, graph_encoding BLOB)",
    )?;
    writer.execute_batch(GraphRows::SCHEMA)?;
    GraphRows::validate_tables(&writer)?;
    writer.execute(
        "INSERT INTO analysis_results VALUES ('version', ?, ?, ?, ?, ?, ?, ?)",
        params![
            graph.scope.identity.tenant_id.as_slice(),
            crate::GRAPH_PROCESSOR,
            rows.header(),
            graph.scope.identity.key().as_slice(),
            graph.scope.method_version,
            graph.first_cursor,
            rows.encoding()
        ],
    )?;
    rows.insert(&writer, "version")?;
    let header = GraphRows::read_header(&writer, graph.scope.identity.tenant_id, "version")?
        .ok_or("missing header")?;
    assert_eq!(GraphRows::read(&writer, "version", &header)?, *graph);
    assert_eq!(
        GraphRows::read_body(&writer, "version", &header, graph)?,
        serde_json::to_vec(graph)?
    );
    assert_eq!(
        serde_json::to_vec(&GraphRows::read(&writer, "version", &header)?)?,
        serde_json::to_vec(graph)?
    );
    let charged: i64 = writer.query_row(
        &format!("SELECT sum(bytes)::BIGINT FROM ({})", GraphRows::CHARGES),
        [],
        |row| row.get(0),
    )?;
    assert_eq!(charged, rows.bytes("version")?);
    assert!(GraphRows::read_header(&writer, [9; 16], "version")?.is_none());
    assert_eq!(
        GraphRows::read_finding(
            &writer,
            "version",
            &graph.findings[0].finding_id,
            &header,
            None
        )?,
        Some(graph.findings[0].clone())
    );
    for mutation in [
        "UPDATE analysis_results SET graph_encoding = NULL",
        "UPDATE analysis_results SET graph_encoding = 'invalid'::BLOB",
    ] {
        let transaction = writer.transaction()?;
        transaction.execute(mutation, [])?;
        assert_eq!(GraphRows::read(&transaction, "version", &header)?, *graph);
        assert!(GraphRows::read_body(&transaction, "version", &header, graph).is_err());
        transaction.rollback()?;
    }
    for mutation in [
        "DELETE FROM graph_subjects WHERE ordinal = 0",
        "UPDATE graph_relationships SET first_boottime_ns = last_boottime_ns + 1",
        "UPDATE graph_findings SET severity = 'INVALID'",
        "UPDATE graph_findings SET ordinal = ordinal + 1",
        "UPDATE graph_subjects SET identity = repeat('x', 16777217)::BLOB WHERE ordinal = 0",
    ] {
        let transaction = writer.transaction()?;
        transaction.execute(mutation, [])?;
        assert!(
            GraphRows::read(&transaction, "version", &header).is_err(),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn native_finding_tenant() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let mut writer = fixture.store.writer_access()?;
    let transaction = writer.get_mut()?.transaction()?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let result = &fixture.request.result_id;
    let header = GraphRows::read_header(&transaction, tenant, result)?.ok_or("missing header")?;
    transaction.execute(
        "UPDATE graph_findings SET tenant_id = ? WHERE result_id = ?",
        params![[9_u8; 16].as_slice(), result],
    )?;
    assert!(matches!(
        GraphRows::read_finding(
            &transaction,
            result,
            &fixture.snapshot.findings[0].finding_id,
            &header,
            None
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph finding tenant",
            ..
        })
    ));
    assert!(GraphRows::read_findings(&transaction, result, &header, None).is_err());
    transaction.commit()?;
    drop(writer);
    assert!(matches!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX, usize::MAX),
        Err(crate::Error::GraphInvalid {
            field: "graph finding tenant",
            ..
        })
    ));
    Ok(())
}

#[test]
fn native_selected_byte_bounds() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let original: Vec<u8> = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT effects FROM graph_findings WHERE result_id = ? AND ordinal = 0",
            params![&fixture.request.result_id],
            |row| row.get(0),
        )?
    };
    for length in [
        GraphRows::MAX_CANONICAL_BYTES - 1,
        GraphRows::MAX_CANONICAL_BYTES + 4 * 1024 * 1024,
    ] {
        fixture.store.fault_write(
            "UPDATE graph_findings SET effects = repeat('x'::BLOB, ?) WHERE result_id = ?",
            params![length as i64, &fixture.request.result_id],
        )?;
        let selected = fixture.store.graph_findings(
            fixture.snapshot.scope.identity.tenant_id,
            None,
            None,
            usize::MAX,
            usize::MAX,
        );
        assert!(
            matches!(
                &selected,
                Err(crate::Error::GraphInvalid {
                    field: "graph storage byte bound",
                    ..
                })
            ),
            "{length}: {selected:?}"
        );
    }
    fixture.store.fault_write(
        "UPDATE graph_findings SET effects = ? WHERE result_id = ?",
        params![original, &fixture.request.result_id],
    )?;
    fixture.store.fault_write(
        "UPDATE analysis_results SET stream_key = repeat('x'::BLOB, ?) WHERE result_id = ?",
        params![
            (crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES + 1) as i64,
            &fixture.request.result_id
        ],
    )?;
    assert!(matches!(
        fixture
            .store
            .read_snapshot(|snapshot| GraphRows::read_header(
                snapshot,
                fixture.snapshot.scope.identity.tenant_id,
                &fixture.request.result_id
            )),
        Err(crate::Error::GraphInvalid {
            field: "graph header index",
            ..
        })
    ));
    assert!(matches!(
        fixture.store.graph_findings(
            fixture.snapshot.scope.identity.tenant_id,
            None,
            None,
            usize::MAX,
            usize::MAX,
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph header index",
            ..
        })
    ));
    fixture.store.fault_write(
        "UPDATE analysis_results SET stream_key = ? WHERE result_id = ?",
        params![
            fixture.snapshot.scope.identity.key(),
            &fixture.request.result_id
        ],
    )?;
    assert_eq!(
        fixture
            .owner
            .current_findings(fixture.snapshot.scope.identity.tenant_id)?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn native_retry_byte_bounds() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    let result = &fixture.request.result_id;
    let original: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT tenant_id, request_meta, body FROM analysis_results WHERE result_id = ?",
            params![result],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?
    };
    for (column, length, header) in [
        ("request_meta", super::super::MAX_RESULT_BYTES + 1, false),
        ("body", GraphHeader::MAX_BYTES + 1, true),
        ("tenant_id", 1024, false),
    ] {
        fixture.store.fault_write(
            &format!(
                "UPDATE analysis_results SET {column} = repeat('x'::BLOB, ?) WHERE result_id = ?"
            ),
            params![length as i64, result],
        )?;
        let error = fixture
            .store
            .commit_graph(&fixture.request, true)
            .err()
            .ok_or("the corrupted retry was accepted")?;
        if header {
            assert!(matches!(
                error,
                crate::Error::GraphInvalid {
                    field: "graph header bytes",
                    ..
                }
            ));
        } else {
            assert!(
                matches!(error, crate::Error::AnalysisState { reason, .. } if reason == "the retained analysis result exceeds its byte bound")
            );
        }
        fixture.store.fault_write(
            "UPDATE analysis_results SET tenant_id = ?, request_meta = ?, body = ? WHERE result_id = ?",
            params![original.0, original.1, original.2, result],
        )?;
        assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
        assert_eq!(
            fixture.store.meta()?.commit_revision,
            receipt.commit_revision
        );
    }
    Ok(())
}
