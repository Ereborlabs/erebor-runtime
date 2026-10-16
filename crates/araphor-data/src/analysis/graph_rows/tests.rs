use super::*;

mod bounds;
mod encoding;
pub(in crate::analysis) mod fixture;
mod headers;
mod packages;
mod schema;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
use fixture::CommitFixture;

#[test]
fn native_rows_integrity() -> TestResult {
    let fixture = CommitFixture::new()?;
    let graph = &fixture.snapshot;
    assert!(!graph.graph.subjects.is_empty());
    assert!(!graph.graph.edges.is_empty());
    assert!(!graph.findings.is_empty());
    let encoded_header = GraphRows::encode(graph)?;
    let metadata = GraphHeader::decode(&encoded_header)?;
    assert!(metadata.snapshot.findings.is_empty());
    assert!(metadata.snapshot.graph.subjects.is_empty());
    assert!(metadata.snapshot.graph.edges.is_empty());
    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
        tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
        method_version UBIGINT, first_cursor UBIGINT)",
    )?;
    writer.execute_batch(GraphRows::SCHEMA)?;
    GraphRows::validate_tables(&writer)?;
    writer.execute(
        "INSERT INTO analysis_results VALUES ('version', ?, ?, ?, ?, ?, ?)",
        params![
            graph.scope.identity.tenant_id.as_slice(),
            crate::GRAPH_PROCESSOR,
            &encoded_header,
            graph.scope.identity.key().as_slice(),
            graph.scope.method_version,
            graph.first_cursor
        ],
    )?;
    let inserted_bytes = GraphRows::insert(graph, &writer, "version")?;
    let header = GraphRows::read_header(&writer, graph.scope.identity.tenant_id, "version")?
        .ok_or("missing header")?;
    assert_eq!(GraphRows::read(&writer, "version", &header)?, *graph);
    assert_eq!(header.body(graph)?, serde_json::to_vec(graph)?);
    assert_eq!(
        serde_json::to_vec(&GraphRows::read(&writer, "version", &header)?)?,
        serde_json::to_vec(graph)?
    );
    let charged: i64 = writer.query_row(
        &format!("SELECT sum(bytes)::BIGINT FROM ({})", GraphRows::CHARGES),
        [],
        |row| row.get(0),
    )?;
    assert_eq!(charged, inserted_bytes);
    assert_eq!(GraphRows::stored_bytes(&writer, "absent")?, 0);
    {
        let transaction = writer.transaction()?;
        let other = "versión";
        transaction.execute(
            "INSERT INTO analysis_results SELECT ?, tenant_id, processor_id, body,
            stream_key, method_version, first_cursor FROM analysis_results WHERE result_id = ?",
            params![other, "version"],
        )?;
        let other_bytes = GraphRows::insert(graph, &transaction, other)?;
        let count =
            (graph.graph.subjects.len() + graph.graph.edges.len() + graph.findings.len()) as i64;
        assert_eq!(
            other_bytes,
            inserted_bytes + (other.len() as i64 - "version".len() as i64) * count
        );
        assert_eq!(
            GraphRows::stored_bytes(&transaction, "version")?,
            inserted_bytes as u64
        );
        assert_eq!(
            GraphRows::stored_bytes(&transaction, other)?,
            other_bytes as u64
        );
        let total: i64 = transaction.query_row(
            &format!("SELECT sum(bytes)::BIGINT FROM ({})", GraphRows::CHARGES),
            [],
            |row| row.get(0),
        )?;
        assert_eq!(total, inserted_bytes + other_bytes);
        transaction.rollback()?;
    }
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
        "DELETE FROM graph_subjects WHERE ordinal = 0",
        "UPDATE graph_relationships SET first_boottime_ns = last_boottime_ns + 1",
        "UPDATE graph_findings SET severity = 'INVALID'",
        "UPDATE graph_findings SET ordinal = ordinal + 1",
        "UPDATE graph_subjects SET identity = repeat('x', 16777217)::BLOB WHERE ordinal = 0",
        "UPDATE graph_subjects SET tenant_id = 'short'::BLOB WHERE ordinal = 0",
        "UPDATE graph_subjects SET authority = '{'::BLOB WHERE ordinal = 0",
        "UPDATE graph_relationships SET evidence = '{'::BLOB WHERE ordinal = 0",
        "UPDATE graph_findings SET tenant_id = 'short'::BLOB WHERE ordinal = 0",
        "UPDATE graph_findings SET effects = '{'::BLOB WHERE ordinal = 0",
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
fn native_borrowed_columns() -> TestResult {
    let writer = Connection::open_in_memory()?;
    let json = |sql: &str| {
        writer.query_row(sql, [], |row| {
            Ok(GraphRows::json_column::<Vec<String>>(row, 0))
        })
    };
    assert_eq!(json("SELECT '[\"value\"]'::BLOB")??, vec!["value"]);
    for sql in ["SELECT 1 AS value", "SELECT NULL::BLOB AS value"] {
        assert!(matches!(
            json(sql)?,
            Err(crate::Error::AnalysisDatabase {
                source: duckdb::Error::InvalidColumnType(0, name, _),
                ..
            }) if name == "value"
        ));
    }
    assert!(matches!(
        json("SELECT '{'::BLOB")?,
        Err(crate::Error::GraphEncoding { .. })
    ));
    let label = writer.query_row("SELECT 1 AS value", [], |row| {
        Ok(GraphRows::label_column::<crate::GraphEdgeTypeV1>(row, 0))
    })?;
    assert!(matches!(
        label,
        Err(crate::Error::AnalysisDatabase {
            source: duckdb::Error::InvalidColumnType(0, name, _),
            ..
        }) if name == "value"
    ));
    let label = writer.query_row("SELECT 'INVALID'", [], |row| {
        Ok(GraphRows::label_column::<crate::GraphEdgeTypeV1>(row, 0))
    })?;
    assert!(matches!(label, Err(crate::Error::GraphEncoding { .. })));
    let ordinal = writer.query_row("SELECT -1::BIGINT", [], |row| {
        Ok(GraphRows::column::<u32>(row, 0))
    })?;
    assert!(matches!(
        ordinal,
        Err(crate::Error::AnalysisDatabase {
            source: duckdb::Error::IntegralValueOutOfRange(0, -1),
            ..
        })
    ));
    Ok(())
}

#[test]
fn native_row_read_cancel() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let writer = fixture.store.writer_access()?;
    let writer = writer.get()?;
    let result = &fixture.request.result_id;
    let header = GraphRows::read_header(writer, fixture.snapshot.scope.identity.tenant_id, result)?
        .ok_or("missing header")?;
    let control = AnalysisReadControl::default();
    control.cancel()?;
    for read in [
        GraphRows::read_subjects(writer, result, Some(&control)).map(|_| ()),
        GraphRows::read_edges(writer, result, Some(&control)).map(|_| ()),
        GraphRows::read_findings(writer, result, &header, Some(&control)).map(|_| ()),
        GraphRows::read_finding(
            writer,
            result,
            &fixture.snapshot.findings[0].finding_id,
            &header,
            Some(&control),
        )
        .map(|_| ()),
        GraphRows::selected_subjects(
            writer,
            result,
            &fixture.snapshot.graph.subjects,
            &control,
            false,
        )
        .map(|_| ()),
        GraphRows::selected_edges(writer, result, &[0], &control).map(|_| ()),
    ] {
        assert!(matches!(
            read,
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
    }
    Ok(())
}

#[test]
fn native_finding_tenant() -> TestResult {
    let fixture = CommitFixture::new()?;
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
    let fixture = CommitFixture::new()?;
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
            .store
            .graph_findings(
                fixture.snapshot.scope.identity.tenant_id,
                None,
                None,
                usize::MAX,
                usize::MAX
            )?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn native_retry_byte_bounds() -> TestResult {
    let fixture = CommitFixture::new()?;
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
