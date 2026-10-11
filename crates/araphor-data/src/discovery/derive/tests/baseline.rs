use super::*;

#[test]
fn discovery_atoms_baseline() -> TestResult<()> {
    let execution = execution()?;
    let manifest = input()?;
    let original = DiscoveryOwner::derive_recorded(&manifest, &execution)?;
    let mut missing = manifest.clone();
    missing.contexts.clear();
    let missing = DiscoveryOwner::derive_recorded(&missing, &execution)?;
    let actual = serde_json::json!({
        "original": original,
        "missing_context": missing,
    });
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/atoms.json"))?
    );
    Ok(())
}

#[test]
fn discovery_merge_baseline() -> TestResult<()> {
    let execution = execution()?;
    let manifest = input()?;
    let mut first = manifest.clone();
    first.records.retain(|record| record.id.durable_cursor == 1);
    first
        .contexts
        .retain(|context| context.record_id.durable_cursor == 1);
    first.coverage[0].last_cursor = 1;
    first.coverage[0].expected_records = 1;
    let mut second = manifest;
    second
        .records
        .retain(|record| record.id.durable_cursor != 1);
    second
        .contexts
        .retain(|context| context.record_id.durable_cursor != 1);
    second.coverage[0].first_cursor = 2;
    second.coverage[0].expected_records = 2;
    let first = DiscoveryOwner::derive_recorded(&first, &execution)?.snapshot;
    let second = DiscoveryOwner::derive_recorded(&second, &execution)?.snapshot;
    let merged = first.merge(&second, &execution)?;
    let actual = serde_json::json!({
        "merged": merged,
        "groups": merged.display_groups(&execution)?,
    });
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/merge.json"))?
    );
    Ok(())
}

#[test]
fn discovery_compare_baseline() -> TestResult<()> {
    let execution = execution()?;
    let original = input()?;
    let snapshot = DiscoveryOwner::derive_recorded(&original, &execution)?.snapshot;
    let baseline = DiscoveryReviewedBaselineV1 {
        reviewer: "operator".into(),
        reviewed_utc_ns: 3000,
        forbidden: vec![snapshot.atoms[0].key.static_key.clone()],
        snapshot,
    };
    let mut changed = original.clone();
    changed
        .records
        .retain(|record| record.id.durable_cursor != 2);
    changed
        .contexts
        .retain(|context| context.record_id.durable_cursor != 2);
    changed.coverage[0].expected_records = 2;
    let counts = DiscoveryOwner::derive_recorded(&changed, &execution)?
        .snapshot
        .compare(&baseline, &execution)?;
    let mut changed = original.clone();
    edit_record(&mut changed.records[1], |wire| wire.kernel_result = -1)?;
    let outcomes = DiscoveryOwner::derive_recorded(&changed, &execution)?
        .snapshot
        .compare(&baseline, &execution)?;
    let mut changed = original;
    changed.contexts[0].image_digest = "replacement-image".into();
    changed.contexts[1].image_digest = "replacement-image".into();
    let identities = DiscoveryOwner::derive_recorded(&changed, &execution)?
        .snapshot
        .compare(&baseline, &execution)?;
    let actual =
        serde_json::json!({"counts": counts, "outcomes": outcomes, "identities": identities});
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/compare.json"))?
    );
    Ok(())
}
