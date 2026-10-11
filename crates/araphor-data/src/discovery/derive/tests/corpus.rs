use super::*;

pub(super) fn rare_exports(
    input: &DiscoveryInputManifestV1,
    normal: &BehaviorSnapshotV1,
    replay: &BehaviorSnapshotV1,
    execution: &crate::InstalledAnalysis,
) -> TestResult<()> {
    let prefix = prefix(input)?;
    let groups = groups(input, normal)?;
    assert_eq!(normal.display_groups(execution)?, groups);
    assert_eq!(replay.display_groups(execution)?, groups);
    let routine = groups
        .iter()
        .find(|group| group.key.physical_result == DiscoveryPhysicalResultV1::Unknown)
        .ok_or("routine group absent")?;
    let denied = groups
        .iter()
        .find(|group| group.key.physical_result == DiscoveryPhysicalResultV1::Prevented)
        .ok_or("denied group absent")?;
    assert_eq!(routine.key.static_key, denied.key.static_key);
    let mut previous = routine.clone();
    previous.count = 64;
    previous.coverage = prefix.coverage.clone();
    let baseline = DiscoveryReviewedBaselineV1 {
        snapshot: DiscoveryOwner::derive_recorded(&prefix, execution)?.snapshot,
        reviewer: "operator".into(),
        reviewed_utc_ns: 3000,
        forbidden: vec![denied.key.static_key.clone()],
    };
    assert_eq!(
        baseline.snapshot.display_groups(execution)?,
        vec![previous.clone()]
    );
    let expected = DiscoveryComparisonV1 {
        added: vec![denied.clone()],
        removed: Vec::new(),
        changed_counts: vec![DiscoveryGroupChangeV1 {
            before: previous.clone(),
            after: routine.clone(),
        }],
        changed_results: vec![DiscoveryGroupChangeV1 {
            before: previous,
            after: denied.clone(),
        }],
        changed_identities: Vec::new(),
        new_resources: Vec::new(),
        coverage_before: prefix.coverage,
        coverage_after: input.coverage.clone(),
        lifecycle_before: Vec::new(),
        lifecycle_after: Vec::new(),
        forbidden_groups: groups,
    };
    assert_eq!(normal.compare(&baseline, execution)?, expected);
    assert_eq!(replay.compare(&baseline, execution)?, expected);
    Ok(())
}

fn prefix(input: &DiscoveryInputManifestV1) -> TestResult<DiscoveryInputManifestV1> {
    assert_eq!(input.coverage.len(), 1);
    assert_eq!(input.coverage[0].first_cursor, 1);
    assert_eq!(input.coverage[0].last_cursor, 10001);
    assert_eq!(input.coverage[0].expected_records, 10001);
    assert_eq!(input.coverage[0].state, DiscoveryCoverageStateV1::Healthy);
    let mut records = input
        .records
        .iter()
        .filter(|record| record.id.durable_cursor <= 64)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.id.cmp(&right.id));
    records.dedup_by(|left, right| left.id == right.id);
    assert_eq!(records.len(), 64);
    let contexts = input
        .contexts
        .iter()
        .filter(|context| context.record_id.durable_cursor <= 64)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(contexts.len(), 64);
    let mut coverage = input.coverage.clone();
    coverage[0].last_cursor = 64;
    coverage[0].expected_records = 64;
    Ok(DiscoveryInputManifestV1 {
        schema_version: input.schema_version,
        tenant_id: input.tenant_id,
        source_revision: input.source_revision.clone(),
        proof_kind: input.proof_kind,
        records,
        contexts,
        coverage,
        exclusions: input.exclusions.clone(),
        lifecycle: input.lifecycle.clone(),
    })
}

fn groups(
    input: &DiscoveryInputManifestV1,
    snapshot: &BehaviorSnapshotV1,
) -> TestResult<Vec<BehaviorDisplayGroupV1>> {
    assert_eq!(snapshot.atoms.len(), 2);
    let mut groups = Vec::new();
    for (physical, count, cursors) in [
        (
            DiscoveryPhysicalResultV1::Unknown,
            10000,
            (1..=8).collect::<Vec<_>>(),
        ),
        (DiscoveryPhysicalResultV1::Prevented, 1, vec![10001]),
    ] {
        let atom = snapshot
            .atoms
            .iter()
            .find(|atom| atom.key.physical_result == physical)
            .ok_or("rare atom absent")?;
        let samples = cursors
            .into_iter()
            .map(|cursor| {
                input
                    .records
                    .iter()
                    .find(|record| record.id.durable_cursor == cursor)
                    .map(|record| record.id.clone())
                    .ok_or("rare sample absent")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        groups.push(BehaviorDisplayGroupV1 {
            key: BehaviorDisplayKeyV1::from(&atom.key),
            count,
            members: vec![atom.key.clone()],
            evidence_sample: samples,
            coverage: input.coverage.clone(),
        });
    }
    groups.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(groups)
}
