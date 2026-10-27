use super::*;

mod atomic;

mod bounds;
mod defaults;
mod encoding;
pub(in crate::analysis) mod fixture;
mod guards;
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
        method_version UBIGINT, first_cursor UBIGINT, facts_revision UBIGINT,
        coverage_revision UBIGINT)",
    )?;
    writer.execute_batch(GraphRows::SCHEMA)?;
    GraphRows::validate_tables(&writer)?;
    writer.execute(
        "INSERT INTO analysis_results VALUES ('version', ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            graph.scope.identity.tenant_id.as_slice(),
            crate::GRAPH_PROCESSOR,
            &encoded_header,
            graph.scope.identity.key().as_slice(),
            graph.scope.method_version,
            graph.first_cursor,
            graph.context_notice_revision,
            fixture.request.coverage_revision
        ],
    )?;
    GraphRows::insert(graph, &writer, "version")?;
    let inserted_bytes = GraphRows::stored_bytes(&writer, "version")? as i64;
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
            stream_key, method_version, first_cursor, facts_revision, coverage_revision
            FROM analysis_results WHERE result_id = ?",
            params![other, "version"],
        )?;
        GraphRows::insert(graph, &transaction, other)?;
        let other_bytes = GraphRows::stored_bytes(&transaction, other)? as i64;
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
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
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
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
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
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let original: Vec<u8> = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT effects FROM graph_findings WHERE result_id = ? AND ordinal = 0",
            params![&fixture.request.result_id],
            |row| row.get(0),
        )?
    };
    for length in [
        fixture.request.body.len() * 2,
        fixture.request.body.len() * 3,
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
fn native_retry_rejects_corruption() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
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
        ("request_meta", 1024, false),
        ("body", 1024, true),
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
            .commit_graph(&fixture.request, true, || Ok(()))
            .err()
            .ok_or("the corrupted retry was accepted")?;
        if header {
            assert!(matches!(
                error,
                crate::Error::GraphInvalid {
                    field: "graph header format",
                    ..
                }
            ));
        } else if column == "request_meta" {
            assert!(matches!(error, crate::Error::AnalysisConflict { .. }));
        } else {
            assert!(matches!(error, crate::Error::AnalysisState { .. }));
        }
        fixture.store.fault_write(
            "UPDATE analysis_results SET tenant_id = ?, request_meta = ?, body = ? WHERE result_id = ?",
            params![original.0, original.1, original.2, result],
        )?;
        assert_eq!(
            fixture
                .store
                .commit_graph(&fixture.request, true, || Ok(()))?,
            receipt
        );
        assert_eq!(
            fixture.store.meta()?.commit_revision,
            receipt.commit_revision
        );
    }
    Ok(())
}

#[test]
fn native_membership_validation() -> TestResult {
    use crate::GraphValidate as _;

    let fixture = CommitFixture::new()?;
    let mut sorted = fixture.snapshot.clone();
    let record = sorted.input_manifest.evidence[0].clone();
    let mut records = [0, 1, 2]
        .map(|cpu_id| {
            let mut record = record.clone();
            record.cpu_id = cpu_id;
            record
        })
        .to_vec();
    records.sort();
    sorted.input_manifest.evidence = records.clone();
    sorted.graph.revision = sorted.input_manifest.clone();
    sorted.input_positions = vec![(
        records[1].clone(),
        crate::StorePositionV1 {
            commit_revision: 1,
            ordinal: 0,
        },
    )];
    for finding in &mut sorted.findings {
        finding.revision = sorted.input_manifest.clone();
        finding.evidence = records.clone();
        let effect = finding.effects.first().ok_or("fixture effect")?.clone();
        finding.effects = records
            .iter()
            .map(|record| {
                let mut effect = effect.clone();
                effect.evidence = record.clone();
                effect
            })
            .collect();
    }
    for edge in &mut sorted.graph.edges {
        edge.key.evidence = records.clone();
    }
    sorted.validate()?;

    let rejected = |result: crate::Result<()>, expected: &'static str| {
        assert!(
            matches!(&result, Err(crate::Error::GraphInvalid { field, .. }) if *field == expected),
            "expected GraphInvalid/{expected}, got {result:?}"
        );
    };
    let mut absent = records[0].clone();
    absent.cpu_id = 3;

    let mut missing_position = sorted.clone();
    missing_position.input_positions[0].0 = absent.clone();
    rejected(missing_position.validate(), "graph snapshot");

    let mut missing_finding = sorted.findings[0].clone();
    missing_finding.evidence = vec![absent.clone()];
    for effect in &mut missing_finding.effects {
        effect.evidence = absent.clone();
    }
    rejected(missing_finding.validate(), "finding revision");

    let mut missing_effect = sorted.findings[0].clone();
    missing_effect.effects[0].evidence = absent.clone();
    rejected(missing_effect.validate(), "finding revision");

    for from in [true, false] {
        let mut missing_endpoint = sorted.clone();
        let mut edge = missing_endpoint.graph.edges[0].clone();
        let endpoint = if from {
            &mut edge.key.from
        } else {
            &mut edge.key.to
        };
        endpoint.identity[0] ^= 128;
        endpoint.validate()?;
        missing_endpoint.graph.edges = vec![edge];
        rejected(missing_endpoint.validate(), "graph edge proof");
    }

    let mut missing_edge_evidence = sorted.clone();
    let mut edge = missing_edge_evidence.graph.edges[0].clone();
    edge.key.evidence = vec![absent];
    missing_edge_evidence.graph.edges = vec![edge];
    rejected(missing_edge_evidence.validate(), "graph edge proof");

    let mut unsorted_manifest = sorted.clone();
    unsorted_manifest.input_manifest.evidence.reverse();
    unsorted_manifest.graph.revision = unsorted_manifest.input_manifest.clone();
    for finding in &mut unsorted_manifest.findings {
        finding.revision = unsorted_manifest.input_manifest.clone();
    }
    unsorted_manifest.input_positions[0].1.commit_revision = 0;
    rejected(unsorted_manifest.validate(), "revision manifest");

    let mut unsorted_finding = sorted.findings[0].clone();
    unsorted_finding.evidence.reverse();
    unsorted_finding.effects.clear();
    rejected(unsorted_finding.validate(), "finding revision");

    let mut invalid_revision = unsorted_finding;
    invalid_revision.revision.evidence.reverse();
    rejected(invalid_revision.validate(), "revision manifest");

    let mut unsorted_subjects = sorted;
    unsorted_subjects.graph.subjects.reverse();
    unsorted_subjects.graph.edges.truncate(1);
    let endpoint = &mut unsorted_subjects.graph.edges[0].key.from;
    endpoint.identity[0] ^= 128;
    endpoint.validate()?;
    rejected(unsorted_subjects.validate(), "graph snapshot");
    Ok(())
}
