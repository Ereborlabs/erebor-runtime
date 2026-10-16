use super::super::*;

#[test]
fn node_streams_stay_separate() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let authenticated = AuthenticatedEvidenceNodeV1 {
        tenant_id: fixture.authenticated.tenant_id,
        node_id: "node-b".into(),
        node_boot_id: [14; 16],
        label_epoch: 1,
    };
    let raw = GraphNotificationQualification::native(1, true);
    let local = fixture.accept(130, &[raw])?;
    let remote = fixture.accept_node(131, &[raw], &authenticated, true)?;
    let graph = &fixture.graph;
    for source in [&local, &remote] {
        for _ in 0..32 {
            graph.process(fixture.now)?;
            if graph.snapshot(source)?.is_some() {
                break;
            }
        }
    }
    let first = graph.snapshot(&local)?.ok_or("local graph absent")?;
    let second = graph.snapshot(&remote)?.ok_or("remote graph absent")?;
    assert_ne!(first.findings[0].subject_id, second.findings[0].subject_id);
    assert_eq!(first.findings[0].state, FindingStateV1::Confirmed);
    assert_eq!(second.findings[0].state, FindingStateV1::Confirmed);
    let mut mixed = GraphNotificationQualification::replay(&fixture.data, &local, &first)?;
    mixed.records.push(fixture.record(&remote, 1)?);
    assert!(matches!(
        GraphAndFindingOwner::derive(&mixed, &fixture.execution),
        Err(araphor_analysis::Error::Data {
            source: Error::GraphInvalid {
                field: "replay record identity",
                ..
            }
        })
    ));
    fixture.partial_node_input(&local, &remote)?;
    assert!(graph.refresh(&local, fixture.now + 1)?);
    assert!(graph.current_findings([99; 16])?.is_empty());
    let (result, finding) = graph
        .current_findings(local.tenant_id)?
        .into_iter()
        .find(|(_, finding)| {
            finding.package_id == "HF-XNODE-001"
                && finding.evidence.iter().any(|id| id.stream == local)
        })
        .ok_or("cross-node partial finding absent")?;
    let partial = graph
        .snapshot_result(local.tenant_id, &result)?
        .ok_or("partial graph absent")?;
    assert!(partial.findings.contains(&finding));
    assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
    assert!(finding
        .limits
        .contains(&"REMOTE_RUNTIME_ADMISSION_MISSING".into()));
    assert!(finding
        .limits
        .contains(&"CROSS_NODE_CAUSALITY_UNQUALIFIED".into()));
    assert!(partial
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::NativeParent));
    let input = GraphNotificationQualification::replay(&fixture.data, &local, &partial)?;
    let mut reordered = input.clone();
    reordered.records.reverse();
    reordered.records.extend(input.records.clone());
    reordered.facts.reverse();
    reordered.facts.extend(input.facts.clone());
    let replay = GraphAndFindingOwner::derive(&reordered, &fixture.execution)?;
    assert_eq!(replay.graph, partial.graph);
    assert_eq!(replay.findings, partial.findings);
    assert_eq!(
        serde_json::to_vec(&replay.findings)?,
        serde_json::to_vec(&partial.findings)?
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
