use super::*;

#[test]
fn graph_authority_rolls_back() -> TestResult {
    for typed in [false, true] {
        let fixture = CommitFixture::new()?;
        let before = fixture.store.meta()?;
        let usage = fixture
            .store
            .witness_usage(fixture.snapshot.scope.identity.tenant_id, 10)?;
        let notices = fixture.store.subscribe_revision();
        let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
        let cancelled = std::sync::Arc::clone(&control);
        fixture
            .store
            .set_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit, move || {
                cancelled.cancel()
            })?;
        let result = if typed {
            let mut metadata = fixture.request.clone();
            metadata.body.clear();
            fixture.store.commit_graph_snapshot(
                metadata,
                CanonicalGraph::new(fixture.snapshot.clone())?,
                &[],
                &[],
                &[],
                true,
                || control.check(),
            )
        } else {
            fixture
                .store
                .commit_graph(&fixture.request, true, || control.check())
        };
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(fixture.store.meta()?, before);
        assert!(!notices.has_changed()?);
        assert_eq!(
            fixture
                .store
                .witness_usage(fixture.snapshot.scope.identity.tenant_id, 10)?,
            usage
        );
        assert!(fixture
            .store
            .read_result(
                fixture.snapshot.scope.identity.tenant_id,
                &fixture.request.result_id
            )?
            .is_none());
        assert!(fixture
            .store
            .graph_snapshot(&fixture.snapshot.scope.identity)?
            .is_none());
        assert_eq!(
            fixture
                .store
                .processor_health(&fixture.request.scope)?
                .ok_or("processor health")?
                .consumed_cursor,
            0
        );
        let writer = fixture.store.writer_access()?;
        for table in [
            "analysis_results",
            "graph_sources",
            "graph_evidence",
            "graph_producer_scopes",
            "graph_producer_versions",
            "graph_producer_members",
            "graph_result_producers",
            "graph_versions",
            "graph_subject_values",
            "graph_edge_values",
            "graph_edge_properties",
            "graph_progress_values",
            "graph_position_values",
            "graph_branch_values",
            "graph_fact_values",
            "graph_finding_values",
            "evidence_refs",
            "context_refs",
        ] {
            let count: u64 =
                writer
                    .get()?
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            assert_eq!(count, 0, "{table}");
        }
        drop(writer);
        let receipt = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?;
        assert_eq!(
            fixture
                .store
                .graph_snapshot(&fixture.snapshot.scope.identity)?,
            Some(fixture.snapshot.clone())
        );
        assert_eq!(receipt.consumed_cursor, 1);
    }
    Ok(())
}

#[test]
fn graph_retry_checks_authority() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let before = fixture.store.meta()?;
    let result = fixture.store.commit_graph(&fixture.request, true, || {
        Err(crate::PackageErrorCodeV1::Denied.error("graph publication authority"))
    });
    assert!(matches!(
        result,
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            field: "graph publication authority",
            ..
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?,
        receipt
    );
    let mut changed_expected = fixture.request.clone();
    changed_expected.expected_cursor = changed_expected.consumed_cursor;
    let mut changed_coverage = fixture.request.clone();
    changed_coverage.coverage_revision += 1;
    let mut changed_time = fixture.request.clone();
    changed_time.created_utc_ns += 1;
    for changed in [changed_expected, changed_coverage, changed_time] {
        assert!(matches!(
            fixture.store.commit_graph(&changed, true, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(fixture.store.meta()?, before);
    }
    Ok(())
}

#[test]
fn graph_window_head_is_exact() -> TestResult {
    let fixture = CommitFixture::new()?;
    let original = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some(fixture.request.result_id.clone());
    snapshot
        .findings
        .first_mut()
        .ok_or("fixture finding")?
        .required_action = Some("inspect-updated-effect".into());
    let mut first = fixture.request.clone();
    first.result_id = "graph:head-first".into();
    first.expected_cursor = first.consumed_cursor;
    first.body = serde_json::to_vec(&snapshot)?;
    let second = fixture.store.commit_graph(&first, false, || Ok(()))?;
    assert!(second.commit_revision > original.commit_revision);
    assert_eq!(
        fixture
            .store
            .graph_result(fixture.snapshot.scope.identity.tenant_id, &first.result_id)?,
        Some(snapshot.clone())
    );
    let before = fixture.store.meta()?;
    let mut stale = first.clone();
    stale.result_id = "graph:head-stale".into();
    for previous in [
        None,
        Some("graph:foreign".into()),
        Some(fixture.request.result_id.clone()),
    ] {
        snapshot.previous_result_id = previous;
        stale.body = serde_json::to_vec(&snapshot)?;
        assert!(matches!(
            fixture.store.commit_graph(&stale, false, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(fixture.store.meta()?, before);
    }
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture
        .store
        .read_result(fixture.snapshot.scope.identity.tenant_id, &stale.result_id)?
        .is_none());
    assert!(matches!(
        fixture.store.mark_graph_notice(
            &first.scope,
            &fixture.request.result_id,
            original.commit_revision,
            7,
            1,
            || Ok(())
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture
            .store
            .graph_notice(&first.scope, &first.result_id, second.commit_revision)?,
        Some((snapshot.context_notice_revision, first.coverage_revision))
    );
    assert_eq!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?,
        original
    );
    snapshot.previous_result_id = Some(first.result_id.clone());
    snapshot
        .findings
        .first_mut()
        .ok_or("fixture finding")?
        .required_action = Some("inspect-followup-effect".into());
    stale.body = serde_json::to_vec(&snapshot)?;
    let third = fixture.store.commit_graph(&stale, false, || Ok(()))?;
    assert!(third.commit_revision > second.commit_revision);
    assert_eq!(
        fixture
            .store
            .graph_result(fixture.snapshot.scope.identity.tenant_id, &stale.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        fixture
            .store
            .graph_snapshot(&fixture.snapshot.scope.identity)?,
        Some(fixture.snapshot.clone())
    );
    Ok(())
}

#[test]
fn graph_notice_checks_authority() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let scope = &fixture.request.scope;
    let id = &fixture.request.result_id;
    let notice = fixture
        .store
        .graph_notice(scope, id, receipt.commit_revision)?;
    let before = fixture.store.meta()?;
    let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
    let cancelled = std::sync::Arc::clone(&control);
    fixture
        .store
        .set_commit_hook(crate::AnalysisCommitStage::BeforeResultCommit, move || {
            cancelled.cancel()
        })?;
    assert!(matches!(
        fixture
            .store
            .mark_graph_notice(scope, id, receipt.commit_revision, 7, 1, || control.check()),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(
        fixture
            .store
            .graph_notice(scope, id, receipt.commit_revision)?,
        notice
    );
    assert_eq!(
        fixture
            .store
            .graph_snapshot(&fixture.snapshot.scope.identity)?,
        Some(fixture.snapshot.clone())
    );
    fixture
        .store
        .mark_graph_notice(scope, id, receipt.commit_revision, 7, 1, || Ok(()))?;
    assert_eq!(
        fixture
            .store
            .graph_notice(scope, id, receipt.commit_revision)?,
        Some((7, 1))
    );
    assert_eq!(
        fixture
            .store
            .graph_result(fixture.snapshot.scope.identity.tenant_id, id)?,
        Some(fixture.snapshot.clone())
    );
    Ok(())
}

#[test]
fn generic_graph_requires_guard() -> TestResult {
    let fixture = CommitFixture::new()?;
    let before = fixture.store.meta()?;
    let error = fixture
        .store
        .commit_result(&fixture.request)
        .err()
        .ok_or("unguarded graph commit")?;
    assert!(
        error.to_string().contains("guarded graph commit"),
        "{error:?}"
    );
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture
        .store
        .read_result(
            fixture.snapshot.scope.identity.tenant_id,
            &fixture.request.result_id
        )?
        .is_none());
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    Ok(())
}
