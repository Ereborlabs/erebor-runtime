use super::super::*;

#[test]
fn late_policy_keeps_history() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let card = ReplayQualification::incident_cards()?.remove(0);
    let source = fixture.card_input(&card, 40)?;
    let graph = &fixture.graph;
    assert_eq!(graph.process(fixture.now)?, 1);
    let snapshot = graph.snapshot(&source)?.ok_or("original graph absent")?;
    let original = snapshot
        .findings
        .into_iter()
        .find(|finding| {
            finding
                .effects
                .iter()
                .any(|effect| effect.evidence.durable_cursor == 1)
        })
        .ok_or("original native finding absent")?;
    let record = fixture.record(&source, 1)?;
    fixture.policy(&record)?;
    assert!(graph.refresh(&source, fixture.now + 300_000_000_000)?);
    assert!(graph.current_findings([99; 16])?.is_empty());
    let (late_id, late) = graph
        .current_finding(source.tenant_id, &original.finding_id)?
        .ok_or("late finding absent")?;
    let selected = graph
        .snapshot_result(source.tenant_id, &late_id)?
        .ok_or("late graph absent")?;
    assert!(selected.findings.contains(&late));
    assert_ne!(late.revision, original.revision);
    assert_eq!(late.state, FindingStateV1::Confirmed);
    assert!(!late.policy_provenance.is_empty());
    assert!(late
        .policy_provenance
        .iter()
        .all(|policy| policy.state == PolicyProvenanceStateV1::Exact));
    assert_eq!(
        graph.finding(original.tenant_id, &original.finding_id, &original.revision)?,
        Some(original)
    );
    let mut contradiction = late.policy_provenance[0].clone();
    contradiction.state = PolicyProvenanceStateV1::Contradicted;
    contradiction.limits = vec!["RECORDED_ACTIVATION_CONTRADICTION".into()];
    fixture.contradiction_input(&record, contradiction)?;
    assert!(graph.refresh(&source, fixture.now + 300_000_000_001)?);
    assert!(graph.current_findings([99; 16])?.is_empty());
    let (conflict_id, conflict) = graph
        .current_finding(source.tenant_id, &late.finding_id)?
        .ok_or("contradicted finding absent")?;
    let snapshot = graph
        .snapshot_result(source.tenant_id, &conflict_id)?
        .ok_or("contradicted graph absent")?;
    assert!(snapshot.findings.contains(&conflict));
    assert_eq!(conflict.reason, FindingReasonV1::Contradiction);
    assert_eq!(conflict.state, FindingStateV1::CoverageInsufficient);
    assert_eq!(
        conflict.effects[0].physical_result,
        GraphPhysicalResultV1::Prevented
    );
    assert_ne!(conflict.revision, late.revision);
    assert_eq!(
        graph.finding(late.tenant_id, &late.finding_id, &late.revision)?,
        Some(late)
    );
    let input = GraphNotificationQualification::replay(&fixture.data, &source, &snapshot)?;
    let mut reordered = input.clone();
    reordered.records.reverse();
    reordered.records.extend(input.records.clone());
    reordered.facts.reverse();
    reordered.facts.extend(input.facts.clone());
    let replay = GraphAndFindingOwner::derive(&reordered, &fixture.execution)?;
    assert_eq!(replay.graph, snapshot.graph);
    assert_eq!(replay.findings, snapshot.findings);
    assert_eq!(
        serde_json::to_vec(&replay.findings)?,
        serde_json::to_vec(&snapshot.findings)?
    );
    let mut foreign = input.clone();
    foreign.source.tenant_id = [99; 16];
    assert!(GraphAndFindingOwner::derive(&foreign, &fixture.execution).is_err());
    let mut conflict = input;
    let mut changed = conflict.records[0].clone();
    changed.original_kernel_sequence = Some(999);
    conflict.records.push(changed);
    assert!(GraphAndFindingOwner::derive(&conflict, &fixture.execution).is_err());
    Ok(())
}
