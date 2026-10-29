use super::*;

#[test]
fn native_header_batch_integrity() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let ids = vec![fixture.request.result_id.clone()];
    let mut calls = 0;
    fixture.store.read_snapshot(|reader| {
        let length: u64 = reader
            .query_row(
                "SELECT octet_length(body) FROM analysis_results WHERE result_id = ?",
                params![&ids[0]],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read native header test length",
            })?;
        GraphRows::visit_headers(
            reader,
            tenant,
            &ids,
            &AnalysisReadControl::default(),
            |id, header, revision, bytes| {
                calls += 1;
                assert_eq!(id, fixture.request.result_id);
                assert_eq!(revision, receipt.commit_revision);
                assert_eq!(header.snapshot.scope, fixture.snapshot.scope);
                assert_eq!(header.subject_count, fixture.snapshot.graph.subjects.len());
                assert_eq!(header.edge_count, fixture.snapshot.graph.edges.len());
                assert_eq!(header.finding_count, fixture.snapshot.findings.len());
                assert!(!bytes.is_empty());
                assert_eq!(bytes.len() as u64, length);
                let saved = GraphHeader::decode(&bytes)?;
                assert_eq!(saved.snapshot.scope, header.snapshot.scope);
                assert_eq!(
                    saved.evidence_count,
                    header.snapshot.input_manifest.evidence.len()
                );
                assert_eq!(saved.position_count, header.snapshot.input_positions.len());
                assert_eq!(saved.subject_count, header.subject_count);
                assert_eq!(saved.edge_count, header.edge_count);
                assert_eq!(saved.finding_count, header.finding_count);
                assert!(header.snapshot.graph.subjects.is_empty());
                assert!(header.snapshot.graph.edges.is_empty());
                assert!(header.snapshot.findings.is_empty());
                Ok(())
            },
        )
    })?;
    assert_eq!(calls, 1);
    let rejected = |ids: &[String]| {
        let mut calls = 0;
        let result = fixture.store.read_snapshot(|reader| {
            GraphRows::visit_headers(
                reader,
                tenant,
                ids,
                &AnalysisReadControl::default(),
                |_, _, _, _| {
                    calls += 1;
                    Ok(())
                },
            )
        });
        assert_eq!(calls, 0);
        result
    };
    assert!(matches!(
        rejected(&[ids[0].clone(), "graph:absent".into()]),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    let mutations = [
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?".to_owned(),
        "DELETE FROM graph_subject_membership WHERE lineage_id =
            (SELECT lineage_id FROM graph_versions WHERE result_id = ?)"
            .to_owned(),
    ];
    let mut writer = fixture.store.writer_access()?;
    for mutation in mutations {
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(&mutation, params![&ids[0]])?;
        let mut calls = 0;
        let result = GraphRows::visit_headers(
            &transaction,
            tenant,
            &ids,
            &AnalysisReadControl::default(),
            |_, _, _, _| {
                calls += 1;
                Ok(())
            },
        );
        assert!(matches!(result, Err(crate::Error::GraphInvalid { .. })));
        assert_eq!(calls, 0);
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn native_header_shape_rejects_missing_values_and_duplicate_subjects() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let result = &fixture.request.result_id;
    let mut writer = fixture.store.writer_access()?;
    for (table, key) in [
        ("graph_subject_values", "subject_id"),
        ("graph_edge_values", "edge_id"),
        ("graph_finding_values", "value_id"),
    ] {
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(
            &format!("DELETE FROM {table} WHERE {key} = (SELECT min({key}) FROM {table})"),
            [],
        )?;
        assert!(matches!(
            GraphRows::read_header(&transaction, tenant, result),
            Err(crate::Error::GraphInvalid { .. })
        ));
        transaction.rollback()?;
    }
    let transaction = writer.get_mut()?.transaction()?;
    let (lineage, first, last): (u64, u64, u64) = transaction.query_row(
        "SELECT m.lineage_id, min(m.subject_id), max(m.subject_id)
         FROM graph_subject_membership m
         JOIN graph_versions v ON v.lineage_id = m.lineage_id
         WHERE v.result_id = ? GROUP BY m.lineage_id",
        params![result],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_ne!(first, last);
    transaction.execute(
        "DELETE FROM graph_subject_membership WHERE lineage_id = ? AND subject_id = ?",
        params![lineage, last],
    )?;
    transaction.execute(
        "INSERT INTO graph_subject_membership VALUES (?, ?, 0, NULL)",
        params![lineage, first],
    )?;
    assert!(matches!(
        GraphRows::stored_shape(&transaction, result),
        Err(crate::Error::GraphInvalid {
            field: "duplicate graph subject membership",
            ..
        })
    ));
    transaction.rollback()?;
    Ok(())
}
