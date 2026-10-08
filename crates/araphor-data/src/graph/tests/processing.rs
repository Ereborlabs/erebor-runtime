use super::*;

#[test]
fn control_graph_expiry_process() -> TestResult {
    for retain in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            RetentionLimitsV1 {
                raw_max_age_ns: 1,
                raw_max_bytes: 100_000,
            },
            Default::default(),
        )?);
        let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
        accept(
            &store,
            &[record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?],
        )?;
        coverage(&store, 1, 1, "HEALTHY")?;
        assert_eq!(owner.process(10)?, 1);
        let original = owner.current_findings(source().tenant_id)?.remove(0);
        assert_eq!(original.1.state, FindingStateV1::Confirmed);
        let snapshot = owner.snapshot(&source())?.ok_or("snapshot")?;
        let now = snapshot.witness_deadline_utc_ns + 1;
        if retain {
            assert_eq!(
                EvidenceRetentionOwner::new(&store)
                    .retain(&source(), now)?
                    .removed_records,
                1
            );
        }
        assert_eq!(owner.process(now)?, 0);
        assert_eq!(owner.process(now)?, 1);
        let current = owner.current_findings(source().tenant_id)?.remove(0);
        assert_eq!(current.1.state, FindingStateV1::CoverageInsufficient);
        assert!(current.1.limits.contains(&"RETAINED_INPUT_EXPIRED".into()));
        assert_eq!(
            owner
                .snapshot_result(source().tenant_id, &current.0)?
                .ok_or("expired snapshot")?
                .previous_result_id,
            Some(original.0.clone())
        );
        assert_eq!(owner.snapshot(&source())?, Some(snapshot));
        assert_eq!(
            owner.finding_result(source().tenant_id, &original.0, &original.1.finding_id)?,
            Some(original.1)
        );
        let revision = store.meta()?.commit_revision;
        assert_eq!(owner.process(now + 1)?, 0);
        assert_eq!(owner.process(now + 1)?, 0);
        assert_eq!(store.meta()?.commit_revision, revision);
    }
    Ok(())
}

#[test]
fn control_graph_refresh_recovery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let provider = Arc::new(FailingInputs(std::sync::atomic::AtomicBool::new(false)));
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
    accept(
        &store,
        &[record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 1, 1, "HEALTHY")?;
    assert_eq!(owner.process(10)?, 1);
    let scope = GraphAndFindingOwner::scope(&source());
    provider.0.store(true, std::sync::atomic::Ordering::Release);
    assert!(owner.refresh(&source(), 11).is_err());
    assert_eq!(owner.process(12)?, 0);
    assert!(owner.process(12).is_err());
    let health = store.processor_health(&scope)?.ok_or("failed health")?;
    assert_eq!(health.state, ProcessorStateV1::ProcessingFailed);
    assert_eq!(health.consumed_cursor, health.accepted_cursor);
    assert!(health.incomplete);
    provider
        .0
        .store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(owner.process(13)?, 0);
    assert_eq!(owner.process(13)?, 0);
    let health = store.processor_health(&scope)?.ok_or("recovered health")?;
    assert_eq!(health.state, ProcessorStateV1::Current);
    assert!(!health.incomplete);
    Ok(())
}
