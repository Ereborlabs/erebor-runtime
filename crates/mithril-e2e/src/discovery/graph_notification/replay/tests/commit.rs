use super::super::*;

#[test]
fn failed_commit_replays_exactly() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let source = fixture.accept(
        3,
        &[
            GraphNotificationQualification::native(1, true),
            GraphNotificationQualification::native(2, false),
        ],
    )?;
    assert!(!fixture.data.discovery_enabled());
    fixture
        .data
        .set_commit_hook(AnalysisCommitStage::BeforeResultCommit, || {
            Err(Error::AnalysisConflict {
                location: snafu::Location::default(),
            })
        })?;
    assert!(fixture.graph.process(fixture.now).is_err());
    assert!(fixture.graph.snapshot(&source)?.is_none());
    for _ in 0..4 {
        if fixture.graph.process(fixture.now)? == 1 {
            break;
        }
    }
    let snapshot = fixture
        .graph
        .snapshot(&source)?
        .ok_or("graph result absent")?;
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].state, FindingStateV1::Confirmed);
    assert_eq!(
        snapshot.findings[0].effects[0].physical_result,
        GraphPhysicalResultV1::Prevented
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
