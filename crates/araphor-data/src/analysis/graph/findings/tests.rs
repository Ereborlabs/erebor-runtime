use super::*;
use crate::analysis::graph_rows::tests::fixture::CommitFixture;

#[test]
fn native_header_once() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.packages[0].coverage_predicate = "x".repeat(1024 * 1024);
    fixture.add_findings(2)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let findings = fixture
        .store
        .graph_findings(tenant, None, None, usize::MAX)?;
    assert_eq!(findings.len(), 3);
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot)
    );
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
            .graph_findings(tenant, None, None, usize::MAX)?,
        expected
    );
    assert_eq!(
        fixture.store.graph_findings(tenant, None, None, 257)?,
        expected[..257]
    );
    assert_eq!(
        fixture.store.graph_findings(
            tenant,
            Some(&expected[255].1.finding_id),
            None,
            usize::MAX
        )?,
        expected[256..]
    );
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
        fixture.store.graph_findings(tenant, None, None, 0),
        Err(crate::Error::GraphInvalid {
            field: "finding page limit",
            ..
        })
    ));
    for tenant in [[0; 16], tenant] {
        let invalid = if tenant == [0; 16] { "valid" } else { "" };
        assert!(matches!(
            fixture.store.graph_findings(tenant, Some(invalid), None, 1),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_findings(tenant, None, Some(invalid), 1),
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
            fixture.store.graph_findings(tenant, Some(invalid), None, 1),
            Err(crate::Error::GraphInvalid {
                field: "finding page scope",
                ..
            })
        ));
        assert!(matches!(
            fixture.store.graph_findings(tenant, None, Some(invalid), 1),
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
        fixture.store.graph_findings(tenant, None, None, 1),
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
        Some((finding.clone(), fixture.snapshot.input_manifest.clone()))
    );
    assert_eq!(
        fixture.store.graph_revision_finding(
            tenant,
            &finding.finding_id,
            &fixture.snapshot.input_manifest
        )?,
        Some(finding.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX)?,
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
        .graph_findings(foreign, None, None, usize::MAX)?
        .is_empty());
    assert!(matches!(
        fixture.store.graph_revision_finding(
            foreign,
            &finding.finding_id,
            &fixture.snapshot.input_manifest
        ),
        Err(crate::Error::GraphInvalid {
            field: "revision manifest",
            ..
        })
    ));
    let unknown = "x".repeat(4097);
    assert!(fixture
        .store
        .graph_findings(tenant, Some(&unknown), None, usize::MAX)?
        .is_empty());
    assert!(fixture
        .store
        .graph_findings(tenant, None, Some(&unknown), usize::MAX)?
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
        .graph_revision_finding(tenant, &unknown, &fixture.snapshot.input_manifest)?
        .is_none());
    Ok(())
}

#[test]
fn graph_pages_follow_limit() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CommitFixture::new()?;
    fixture.add_findings(1)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let current = fixture.store.graph_findings(tenant, None, None, 2)?;
    assert_eq!(current.len(), 2);
    assert_eq!(
        fixture.store.graph_findings(tenant, None, None, 1)?,
        current[..1]
    );
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, Some(&current[0].1.finding_id), None, 2)?,
        current[1..]
    );
    Ok(())
}

#[test]
fn notification_finding_checks_current() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let fixture = CommitFixture::new()?;
    let first = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let finding = fixture
        .snapshot
        .findings
        .first()
        .ok_or("fixture finding")?
        .clone();
    let original = crate::NotificationFindingRefV1 {
        result_id: fixture.request.result_id.clone(),
        finding_id: finding.finding_id.clone(),
    };
    assert_eq!(
        fixture.store.notification_finding(tenant, &original)?,
        (finding.clone(), fixture.snapshot.input_manifest.clone())
    );
    assert!(matches!(
        fixture.store.notification_finding([0; 16], &original),
        Err(crate::Error::Notification {
            code: crate::NotificationErrorCodeV1::Invalid,
            field: "finding reference",
            ..
        })
    ));
    for invalid in ["", "finding\ninvalid", "finding\rinvalid", "\0", "\u{7f}"] {
        for reference in [
            crate::NotificationFindingRefV1 {
                finding_id: invalid.into(),
                ..original.clone()
            },
            crate::NotificationFindingRefV1 {
                result_id: invalid.into(),
                ..original.clone()
            },
        ] {
            assert!(matches!(
                fixture.store.notification_finding(tenant, &reference),
                Err(crate::Error::Notification {
                    code: crate::NotificationErrorCodeV1::Invalid,
                    field: "finding reference",
                    ..
                })
            ));
        }
    }
    assert!(matches!(
        fixture.store.notification_finding([9; 16], &original),
        Err(crate::Error::Notification {
            code: crate::NotificationErrorCodeV1::Denied,
            field: "current finding scope",
            ..
        })
    ));
    let missing = crate::NotificationFindingRefV1 {
        finding_id: "absent-finding".into(),
        ..original.clone()
    };
    assert!(matches!(
        fixture.store.notification_finding(tenant, &missing),
        Err(crate::Error::Notification {
            code: crate::NotificationErrorCodeV1::Denied,
            field: "current finding scope",
            ..
        })
    ));
    let unknown_result = crate::NotificationFindingRefV1 {
        result_id: "graph:missing".into(),
        ..original.clone()
    };
    assert!(matches!(
        fixture.store.notification_finding(tenant, &unknown_result),
        Err(crate::Error::Notification {
            code: crate::NotificationErrorCodeV1::Conflict,
            field: "current finding reference",
            ..
        })
    ));

    let mut next = fixture.request.clone();
    next.expected_cursor = next.consumed_cursor;
    next.result_id = "graph:notification-current".into();
    next.created_utc_ns += 1;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some(original.result_id.clone());
    let updated = snapshot.findings.first_mut().ok_or("fixture finding")?;
    updated.required_action = Some("inspect-current-effect".into());
    let updated = updated.clone();
    snapshot.validate()?;
    next.body = serde_json::to_vec(&snapshot)?;
    let second = fixture.store.commit_graph(&next, false, || Ok(()))?;
    assert!(second.commit_revision > first.commit_revision);
    let current = crate::NotificationFindingRefV1 {
        result_id: next.result_id.clone(),
        finding_id: finding.finding_id.clone(),
    };
    assert_eq!(
        fixture.store.notification_finding(tenant, &current)?,
        (updated, fixture.snapshot.input_manifest.clone())
    );
    assert!(matches!(
        fixture.store.notification_finding(tenant, &original),
        Err(crate::Error::Notification {
            code: crate::NotificationErrorCodeV1::Conflict,
            field: "current finding reference",
            ..
        })
    ));
    assert_eq!(
        fixture
            .store
            .graph_finding(tenant, &original.result_id, &original.finding_id)?,
        Some((finding.clone(), fixture.snapshot.input_manifest.clone()))
    );

    let header: Vec<u8> = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT body FROM analysis_results WHERE result_id = ?",
            params![&current.result_id],
            |row| row.get(0),
        )?
    };
    fixture.store.fault_write(
        "UPDATE analysis_results SET body = 'invalid'::BLOB WHERE result_id = ?",
        params![&current.result_id],
    )?;
    let corrupt_current = fixture.store.notification_finding(tenant, &current);
    let corrupt_stale = fixture.store.notification_finding(tenant, &original);
    fixture.store.fault_write(
        "UPDATE analysis_results SET body = ? WHERE result_id = ?",
        params![&header, &current.result_id],
    )?;
    assert!(
        matches!(
            &corrupt_current,
            Err(crate::Error::GraphInvalid {
                field: "graph header format",
                ..
            })
        ),
        "matching corrupt reference returned {corrupt_current:?}"
    );
    assert!(
        matches!(
            &corrupt_stale,
            Err(crate::Error::Notification {
                code: crate::NotificationErrorCodeV1::Conflict,
                field: "current finding reference",
                ..
            })
        ),
        "stale reference returned {corrupt_stale:?}"
    );

    let mut empty = next.clone();
    empty.result_id = "graph:notification-empty".into();
    empty.created_utc_ns += 1;
    snapshot.previous_result_id = Some(current.result_id.clone());
    snapshot.findings.clear();
    snapshot.validate()?;
    empty.body = serde_json::to_vec(&snapshot)?;
    let third = fixture.store.commit_graph(&empty, false, || Ok(()))?;
    assert!(third.commit_revision > second.commit_revision);
    assert_eq!(
        fixture.store.graph_result(tenant, &empty.result_id)?,
        Some(snapshot)
    );
    for reference in [&original, &current] {
        assert!(matches!(
            fixture.store.notification_finding(tenant, reference),
            Err(crate::Error::Notification {
                code: crate::NotificationErrorCodeV1::Denied,
                field: "current finding scope",
                ..
            })
        ));
    }
    assert_eq!(
        fixture
            .store
            .graph_finding(tenant, &original.result_id, &original.finding_id)?,
        Some((finding, fixture.snapshot.input_manifest.clone()))
    );
    Ok(())
}
