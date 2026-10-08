use super::*;

#[test]
fn control_graph_overlap_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("analysis"),
        RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1_000_000,
        },
        Default::default(),
    )?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(Inputs::default()))?;
    let records = (1..=383)
        .map(|cursor| record(cursor, &wire(cursor, DeniedBeforeEffect, 2, 2, [20; 16])))
        .collect::<Result<Vec<_>>>()?;
    for batch in records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 383, 1, "HEALTHY")?;
    process_to(&owner, &store, 383, 10)?;
    let original = owner
        .current_findings(source().tenant_id)?
        .into_iter()
        .find(|(_, finding)| finding.evidence[0].durable_cursor == 257)
        .ok_or("overlapping finding")?;
    let now = owner
        .snapshot(&source())?
        .ok_or("snapshot")?
        .witness_deadline_utc_ns
        + 1;
    let mut after = None;
    let mut overlapping = false;
    loop {
        let page = store.graph_snapshots(source().tenant_id, None, after.as_deref(), true)?;
        if page.is_empty() {
            break;
        }
        after = page.last().map(|row| row.0.clone());
        for (_, snapshot, _) in page {
            assert_ne!(snapshot.first_cursor, 257);
            overlapping |= snapshot.last_cursor >= 257;
        }
    }
    assert!(overlapping);
    accept(
        &store,
        &[record(384, &wire(384, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 384, 2, "HEALTHY")?;
    process_to(&owner, &store, 384, now)?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source(), now + 1)?
            .removed_records,
        0
    );
    accept(
        &store,
        &[record(385, &wire(385, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 385, 3, "HEALTHY")?;
    process_to(&owner, &store, 385, now + 2)?;
    let current = owner
        .current_finding(source().tenant_id, &original.1.finding_id)?
        .ok_or("expired finding")?;
    assert_eq!(current.1.state, FindingStateV1::CoverageInsufficient);
    assert!(current.1.limits.contains(&"RETAINED_INPUT_EXPIRED".into()));
    assert_eq!(
        owner
            .snapshot_result(source().tenant_id, &current.0)?
            .ok_or("expired snapshot")?
            .witness_deadline_utc_ns,
        now - 1
    );
    assert_eq!(
        owner.finding_result(source().tenant_id, &original.0, &original.1.finding_id)?,
        Some(original.1)
    );
    Ok(())
}

pub(super) fn process_to(
    owner: &GraphAndFindingOwner,
    store: &AnalysisStore,
    cursor: u64,
    now: u64,
) -> TestResult {
    for _ in 0..32 {
        owner.process(now)?;
        if store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("processor health")?
            .consumed_cursor
            == cursor
        {
            return Ok(());
        }
    }
    Err("required graph progress stopped".into())
}
