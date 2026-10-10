use super::*;

#[test]
fn native_header_batch_bounds() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
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
            usize::MAX,
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
                assert_eq!(saved.snapshot, header.snapshot);
                assert_eq!(saved.subject_count, header.subject_count);
                assert_eq!(saved.edge_count, header.edge_count);
                assert_eq!(saved.finding_count, header.finding_count);
                assert_eq!(saved.snapshot_bytes, header.snapshot_bytes);
                assert!(header.snapshot.graph.subjects.is_empty());
                assert!(header.snapshot.graph.edges.is_empty());
                assert!(header.snapshot.findings.is_empty());
                Ok(())
            },
        )
    })?;
    assert_eq!(calls, 1);
    let rejected = |ids: &[String], bytes| {
        let mut calls = 0;
        let result = fixture.store.read_snapshot(|reader| {
            GraphRows::visit_headers(
                reader,
                tenant,
                ids,
                bytes,
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
        rejected(&[ids[0].clone(), "graph:absent".into()], usize::MAX),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        rejected(&ids, 1),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let maximum = serde_json::to_vec(&fixture.snapshot)?.len()
        + (fixture.snapshot.graph.subjects.len()
            + fixture.snapshot.graph.edges.len()
            + fixture.snapshot.findings.len())
            * (256 + ids[0].len());
    let mutations = [
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?".to_owned(),
        format!(
            "UPDATE graph_subjects SET identity = repeat('x'::BLOB, {})
            WHERE result_id = ? AND ordinal = 0",
            maximum + 1
        ),
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
            usize::MAX,
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
