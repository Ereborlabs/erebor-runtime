use super::*;

#[test]
fn discovery_context_baseline() -> TestResult<()> {
    let (mut request, first) = input()?;
    let mut future = first.clone();
    future.imported_utc_ns = 4000;
    future.document.revision = 2;
    future.document.approver = Some("operator".into());
    future.document.text = "A later review confirms an owner explanation.".into();
    let revisions = vec![future, first.clone()];
    let initial = DiscoveryOwner::select_context(&request, &revisions)?;
    request.cutoff_utc_ns = 4000;
    let later = DiscoveryOwner::select_context(&request, &revisions)?;
    request.cutoff_utc_ns = 3000;
    let mut conflict = first.clone();
    conflict.document.id = "contradictory-owner".into();
    conflict.document.origin = "another owner".into();
    conflict.document.text = "A second owner supplies a different statement.".into();
    let conflicts = DiscoveryOwner::select_context(&request, &[first.clone(), conflict])?;
    for evidence in &mut request.records {
        if evidence.record_id.durable_cursor == 1 {
            evidence.received_utc_ns = None;
        }
    }
    request.owner_facts[0].recorded_utc_ns = 4000;
    let missing = DiscoveryOwner::select_context(&request, std::slice::from_ref(&first))?;
    request.access.sensitivities.clear();
    let denied = DiscoveryOwner::select_context(&request, &[first])?;
    let actual = serde_json::json!({
        "initial": initial, "later": later, "conflicts": conflicts,
        "missing": missing, "denied": denied,
    });
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/context.json"))?
    );
    Ok(())
}
