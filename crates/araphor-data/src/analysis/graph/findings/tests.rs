use super::*;

#[test]
fn native_header_once() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    fixture.snapshot.packages[0].coverage_predicate = "x".repeat(1024 * 1024);
    fixture.add_findings(2)?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    assert_eq!(fixture.owner.current_findings(tenant)?.len(), 3);
    let query = format!(
        "SELECT count(*)::UBIGINT, count(graph_header)::UBIGINT,
            sum(octet_length(graph_header))::UBIGINT FROM ({})",
        AnalysisStore::finding_preflight(1)
    );
    let counts: (u64, u64, u64) = fixture.store.read_snapshot(|snapshot| {
        snapshot
            .query_row(
                &query,
                params![
                    fixture.request.result_id,
                    GraphRows::MAX_CANONICAL_BYTES as u64,
                    GraphHeader::MAX_BYTES as u64,
                    crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check first selected graph header",
            })
    })?;
    assert_eq!((counts.0, counts.1), (1, 1));
    assert!(counts.2 > 1024 * 1024);
    Ok(())
}

#[test]
fn native_finding_batches() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    fixture.add_findings(257)?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let expected = fixture
        .snapshot
        .findings
        .iter()
        .cloned()
        .map(|finding| (fixture.request.result_id.clone(), finding))
        .collect::<Vec<_>>();
    assert_eq!(fixture.owner.current_findings(tenant)?, expected);
    let bytes = serde_json::to_vec(&expected[..257])?.len();
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX, bytes)?,
        expected[..257]
    );
    assert_eq!(
        fixture.store.graph_findings(
            tenant,
            Some(&expected[255].1.finding_id),
            None,
            usize::MAX,
            usize::MAX
        )?,
        expected[256..]
    );
    Ok(())
}

#[test]
fn native_finding_fallback() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    fixture.add_findings(2)?;
    fixture.store.commit_graph(&fixture.request, true)?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let expected = fixture.owner.current_findings(tenant)?;
    let bytes = serde_json::to_vec(&expected[..2])?.len();
    for (after, points, bytes, wanted) in [
        (None, usize::MAX, bytes, &expected[..2]),
        (None, 1, bytes, &expected[..2]),
        (
            Some(expected[0].1.finding_id.as_str()),
            1,
            usize::MAX,
            &expected[1..],
        ),
    ] {
        let actual = fixture.store.read_snapshot(|snapshot| {
            let mut selection = fixture.store.preflight_findings(
                snapshot,
                tenant,
                params![
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    after,
                    after,
                    None::<String>,
                    None::<String>,
                    i64::MAX
                ],
            )?;
            for key in selection.keys.iter_mut().take(points) {
                key.bytes = GraphRows::MAX_CANONICAL_BYTES as u64;
            }
            if points == 1 {
                selection.headers = FindingHeaders::default();
            }
            fixture
                .store
                .collect_findings(snapshot, selection, tenant, bytes)
        })?;
        assert_eq!(actual, wanted);
    }
    Ok(())
}
