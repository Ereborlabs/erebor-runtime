use super::*;
use crate::analysis::graph_rows::tests::fixture::CommitFixture;

#[test]
fn native_header_read_budget() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = CommitFixture::new()?;
    let encoded_header = GraphRows::encode(&fixture.snapshot)?;
    let mut headers = FindingHeaders::default();
    for id in ["first", "second"] {
        let mut header = GraphHeader::decode(&encoded_header)?;
        header.snapshot_bytes = MAX_READ_BYTES / 4 + 1;
        headers.insert(id.into(), header);
    }
    assert!(headers.get("first").is_some());
    assert!(headers.get("second").is_some());
    Ok(())
}

#[test]
fn native_header_once() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.packages[0].coverage_predicate = "x".repeat(1024 * 1024);
    fixture.add_findings(2)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX, usize::MAX)?
            .len(),
        3
    );
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
                    MAX_READ_BYTES as u64,
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
    let mut fixture = CommitFixture::new()?;
    fixture.add_findings(257)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    fixture.store.read_snapshot(|snapshot| {
        let selection = fixture.store.preflight_findings(
            snapshot,
            tenant,
            params![
                tenant.as_slice(),
                GRAPH_PROCESSOR,
                GRAPH_SCHEMA_VERSION,
                None::<String>,
                None::<String>,
                None::<String>,
                None::<String>,
                i64::MAX
            ],
        )?;
        assert_eq!(FindingKey::batch_end(&selection.keys, 0), 256);
        let stored: u64 = snapshot
            .query_row(
                &format!("SELECT sum(bytes)::UBIGINT FROM ({})", GraphRows::CHARGES),
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "check selected finding row charge",
            })?;
        assert!(selection.keys.iter().all(|key| key.bytes < stored));
        Ok(())
    })?;
    let expected = fixture
        .snapshot
        .findings
        .iter()
        .cloned()
        .map(|finding| (fixture.request.result_id.clone(), finding))
        .collect::<Vec<_>>();
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX, usize::MAX)?,
        expected
    );
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
fn finding_shared_header_batch() {
    let keys = ["first", "first", "second"].map(|result| FindingKey {
        result: result.into(),
        finding: "finding".into(),
        bytes: MAX_READ_BYTES as u64 / 8,
        header_bytes: MAX_READ_BYTES as u64 / 2,
    });
    assert_eq!(FindingKey::batch_end(&keys, 0), 2);
    assert_eq!(FindingKey::batch_end(&keys, 1), 2);
    assert_eq!(FindingKey::batch_end(&keys, 2), 3);
}

#[test]
fn native_finding_fallback() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CommitFixture::new()?;
    fixture.add_findings(2)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let expected = fixture
        .store
        .graph_findings(tenant, None, None, usize::MAX, usize::MAX)?;
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
                key.bytes = MAX_READ_BYTES as u64;
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

#[test]
fn graph_reads_reject_scope() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = CommitFixture::limits(crate::StorageLimitsV1 {
        reader_admissions: Some(16),
        ..Default::default()
    })?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let result = fixture.request.result_id.as_str();
    let finding = fixture
        .snapshot
        .findings
        .first()
        .ok_or("fixture finding")?
        .finding_id
        .as_str();
    fixture
        .store
        .read_slots
        .as_ref()
        .ok_or("configured reader admissions")?
        .close();
    assert!(matches!(
        fixture
            .store
            .graph_findings(tenant, None, None, 0, usize::MAX),
        Err(crate::Error::GraphInvalid {
            field: "finding page limit",
            ..
        })
    ));
    for tenant in [[0; 16], tenant] {
        let invalid = if tenant == [0; 16] { "valid" } else { "" };
        assert!(matches!(
            fixture
                .store
                .graph_findings(tenant, Some(invalid), None, 1, usize::MAX),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture
                .store
                .graph_findings(tenant, None, Some(invalid), 1, usize::MAX),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_finding(tenant, result, invalid),
            Err(crate::Error::GraphInvalid {
                field: "finding reference",
                ..
            })
        ));
        assert!(matches!(
            fixture
                .store
                .graph_revision_finding(tenant, invalid, &fixture.snapshot.input_manifest),
            Err(crate::Error::GraphInvalid {
                field: "finding reference",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_result(tenant, invalid),
            Err(crate::Error::GraphInvalid {
                field: "graph result reference",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_source(tenant, invalid),
            Err(crate::Error::GraphInvalid {
                field: "graph result reference",
                ..
            })
        ));
    }
    for invalid in ["\0", "finding\nsecret", "finding\rsecret", "finding\u{7f}"] {
        assert!(matches!(
            fixture
                .store
                .graph_findings(tenant, Some(invalid), None, 1, usize::MAX),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture
                .store
                .graph_findings(tenant, None, Some(invalid), 1, usize::MAX),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_finding(tenant, result, invalid),
            Err(crate::Error::GraphInvalid {
                field: "finding reference",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_finding(tenant, invalid, finding),
            Err(crate::Error::GraphInvalid {
                field: "finding reference",
                ..
            })
        ));
        assert!(matches!(
            fixture
                .store
                .graph_revision_finding(tenant, invalid, &fixture.snapshot.input_manifest),
            Err(crate::Error::GraphInvalid {
                field: "finding reference",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_result(tenant, invalid),
            Err(crate::Error::GraphInvalid {
                field: "graph result reference",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_source(tenant, invalid),
            Err(crate::Error::GraphInvalid {
                field: "graph result reference",
                ..
            })
        ));
    }
    assert!(matches!(
        fixture
            .store
            .graph_findings(tenant, None, None, 1, usize::MAX),
        Err(crate::Error::AnalysisBusy {
            resource: "reader",
            ..
        })
    ));
    Ok(())
}

#[test]
fn graph_revision_keeps_guards() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = CommitFixture::limits(crate::StorageLimitsV1 {
        reader_admissions: Some(16),
        ..Default::default()
    })?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let finding = &fixture
        .snapshot
        .findings
        .first()
        .ok_or("fixture finding")?
        .finding_id;
    let revision = &fixture.snapshot.input_manifest;
    let mut invalid = Vec::new();
    let mut changed = revision.clone();
    changed.evidence[0].stream.tenant_id = [9; 16];
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.evidence[0].durable_cursor = 0;
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.evidence.push(changed.evidence[0].clone());
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.coverage[0].source.tenant_id = [9; 16];
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.coverage[0].interval_id = [0; 16];
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.coverage.push(changed.coverage[0].clone());
    invalid.push(changed);
    let key = crate::AnalysisContextKeyV1 {
        tenant_id: tenant,
        owner_id: "graph-read".into(),
        entity_key: vec![1],
        lifetime_key: vec![1],
        owner_revision: 1,
    };
    let mut changed = revision.clone();
    let mut foreign = key.clone();
    foreign.tenant_id = [9; 16];
    changed.context.push(foreign);
    invalid.push(changed);
    let mut changed = revision.clone();
    changed.context = vec![key.clone(), key];
    invalid.push(changed);
    for range in [(0, 1), (2, 1)] {
        let mut changed = revision.clone();
        changed.missing_ranges.push(range);
        invalid.push(changed);
    }
    fixture
        .store
        .read_slots
        .as_ref()
        .ok_or("configured reader admissions")?
        .close();
    for revision in invalid {
        assert!(matches!(
            fixture
                .store
                .graph_revision_finding(tenant, finding, &revision),
            Err(crate::Error::GraphInvalid {
                field: "revision manifest",
                ..
            })
        ));
    }
    assert!(matches!(
        fixture
            .store
            .graph_revision_finding(tenant, finding, revision),
        Err(crate::Error::AnalysisBusy {
            resource: "reader",
            ..
        })
    ));
    let mut unlimited = revision.clone();
    unlimited.evidence = (1..=257)
        .map(|cursor| {
            let mut id = revision.evidence[0].clone();
            id.durable_cursor = cursor;
            id
        })
        .collect();
    unlimited.coverage = (1_u128..=4097)
        .map(|index| {
            let mut key = revision.coverage[0].clone();
            key.interval_id = index.to_be_bytes();
            key
        })
        .collect();
    unlimited.context = (1_u64..=257)
        .map(|index| crate::AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: "graph-read".into(),
            entity_key: index.to_be_bytes().to_vec(),
            lifetime_key: vec![1],
            owner_revision: 1,
        })
        .collect();
    unlimited.missing_ranges = (1..=257).map(|cursor| (cursor, cursor)).collect();
    unlimited.validate(tenant)?;
    assert!(matches!(
        fixture
            .store
            .graph_revision_finding(tenant, finding, &unlimited),
        Err(crate::Error::AnalysisBusy {
            resource: "reader",
            ..
        })
    ));
    Ok(())
}

#[test]
fn graph_reads_keep_history() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = CommitFixture::new()?;
    let original = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let finding = fixture.snapshot.findings.first().ok_or("fixture finding")?;
    let mut next = fixture.request.clone();
    next.expected_cursor = next.consumed_cursor;
    next.result_id = "graph:updated-window".into();
    next.created_utc_ns += 1;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some(fixture.request.result_id.clone());
    let updated = snapshot.findings.first_mut().ok_or("fixture finding")?;
    updated.required_action = Some("inspect-updated-effect".into());
    let updated = updated.clone();
    next.body = serde_json::to_vec(&snapshot)?;
    let receipt = fixture.store.commit_graph(&next, false, || Ok(()))?;
    assert!(receipt.commit_revision > original.commit_revision);
    assert_eq!(
        fixture.store.graph_result(tenant, &next.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_finding(tenant, &fixture.request.result_id, &finding.finding_id)?,
        Some(finding.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_revision_finding(tenant, &finding.finding_id, &finding.revision)?,
        Some(finding.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX, usize::MAX)?,
        vec![(next.result_id.clone(), updated)]
    );
    assert_eq!(
        fixture
            .store
            .graph_source(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.scope.identity.clone())
    );
    let foreign = [9; 16];
    assert!(fixture
        .store
        .graph_result(foreign, &fixture.request.result_id)?
        .is_none());
    assert!(fixture
        .store
        .graph_source(foreign, &fixture.request.result_id)?
        .is_none());
    assert!(fixture
        .store
        .graph_finding(foreign, &fixture.request.result_id, &finding.finding_id)?
        .is_none());
    assert!(fixture
        .store
        .graph_findings(foreign, None, None, usize::MAX, usize::MAX)?
        .is_empty());
    assert!(matches!(
        fixture
            .store
            .graph_revision_finding(foreign, &finding.finding_id, &finding.revision),
        Err(crate::Error::GraphInvalid {
            field: "revision manifest",
            ..
        })
    ));
    let unknown = "x".repeat(4097);
    assert!(fixture
        .store
        .graph_findings(tenant, Some(&unknown), None, usize::MAX, usize::MAX)?
        .is_empty());
    assert!(fixture
        .store
        .graph_findings(tenant, None, Some(&unknown), usize::MAX, usize::MAX)?
        .is_empty());
    assert!(fixture
        .store
        .graph_finding(tenant, &fixture.request.result_id, &unknown)?
        .is_none());
    assert!(fixture
        .store
        .graph_finding(tenant, &unknown, &finding.finding_id)?
        .is_none());
    assert!(fixture.store.graph_result(tenant, &unknown)?.is_none());
    assert!(fixture.store.graph_source(tenant, &unknown)?.is_none());
    assert!(fixture
        .store
        .graph_revision_finding(tenant, &unknown, &finding.revision)?
        .is_none());
    Ok(())
}

#[test]
fn graph_pages_keep_budget() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CommitFixture::new()?;
    fixture.add_findings(1)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let current = fixture
        .store
        .graph_findings(tenant, None, None, 2, usize::MAX)?;
    assert_eq!(current.len(), 2);
    let first_bytes = serde_json::to_vec(&current[..1])?.len();
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, 2, first_bytes)?,
        current[..1]
    );
    let next_bytes = serde_json::to_vec(&current[1..])?.len();
    assert_eq!(
        fixture.store.graph_findings(
            tenant,
            Some(&current[0].1.finding_id),
            None,
            2,
            next_bytes
        )?,
        current[1..]
    );
    assert!(matches!(
        fixture
            .store
            .graph_findings(tenant, None, None, 2, first_bytes - 1),
        Err(crate::Error::GraphEncoding { .. })
    ));
    Ok(())
}
