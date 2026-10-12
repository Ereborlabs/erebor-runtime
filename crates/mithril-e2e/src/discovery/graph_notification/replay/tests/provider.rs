use super::super::*;

mod inputs;

#[test]
fn provider_write_needs_bridge() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let (record, provider) = fixture.publication_input()?;
    let source = &record.id.stream;
    assert!(matches!(
        &provider.value,
        GraphFactValueV1::AuthorityUse {
            process_instance_id: None,
            task_cookie: None,
            credential_object_id: None,
            socket_object_id: None,
            workload_binding: None,
            ..
        }
    ));
    assert_eq!(fixture.graph.process(fixture.now)?, 1);
    let snapshot = fixture
        .graph
        .snapshot(source)?
        .ok_or("publication graph absent")?;
    let finding = snapshot
        .findings
        .iter()
        .find(|finding| finding.package_id == "HF-PROC-001")
        .ok_or("publication finding absent")?;
    assert!(snapshot.graph.facts.contains(&provider));
    assert!(snapshot
        .graph
        .edges
        .iter()
        .all(|edge| edge.key.edge_type != GraphEdgeTypeV1::CredentialAuthority));
    assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
    assert!(finding.limits.contains(&"REMOTE_OPERATION_UNPROVEN".into()));
    assert_eq!(finding.effects.len(), 1);
    assert_eq!(
        finding.effects[0].physical_result,
        GraphPhysicalResultV1::Unknown
    );
    let (result_id, current) = fixture
        .graph
        .current_finding(source.tenant_id, &finding.finding_id)?
        .ok_or("current publication finding absent")?;
    assert_eq!(&current, finding);
    assert_eq!(
        fixture
            .graph
            .snapshot_result(source.tenant_id, &result_id)?,
        Some(snapshot.clone())
    );
    let input = GraphNotificationQualification::replay(&fixture.data, source, &snapshot)?;
    let facts = input
        .facts
        .iter()
        .map(GraphFactV1::try_from)
        .collect::<Result<Vec<_>>>()?;
    assert!(facts.contains(&provider));
    let replay = GraphAndFindingOwner::derive(&input, &fixture.execution)?;
    assert_eq!(replay.graph, snapshot.graph);
    assert_eq!(replay.findings, snapshot.findings);
    assert_eq!(
        serde_json::to_vec(&replay.findings)?,
        serde_json::to_vec(&snapshot.findings)?
    );
    Ok(())
}
