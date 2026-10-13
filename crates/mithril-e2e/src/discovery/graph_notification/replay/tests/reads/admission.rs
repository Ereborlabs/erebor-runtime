use super::*;

#[test]
fn admission_keeps_bytes_unproven() -> crate::platform::TestResult<()> {
    let now = 1_791_400_000_000_000_000;
    for (source_id, name, operation, path) in [
        (
            100,
            "open-admission",
            KernelEffectOperationV1::OpenRead,
            GraphReadPathV1::Read,
        ),
        (
            105,
            "mmap-admission-address",
            KernelEffectOperationV1::MmapRead,
            GraphReadPathV1::Mmap,
        ),
    ] {
        let fixture = ReplayQualification::new(now)?;
        let (read, network, authority) =
            fixture.completion_inputs(source_id, name, path, operation, None)?;
        assert_eq!(read.decode()?.operation, operation as u32);
        let source = &read.id.stream;
        let graph = &fixture.graph;
        assert_eq!(graph.process(now)?, 1);
        let earlier = graph.snapshot(source)?.ok_or("earlier graph absent")?;
        let prior = earlier
            .findings
            .iter()
            .find(|finding| finding.package_id == "HF-DW-001")
            .ok_or("earlier credential finding absent")?;
        assert_eq!(prior.state, FindingStateV1::CoverageInsufficient);
        fixture.inputs.insert(authority, "late-authority", 1)?;
        assert!(graph.refresh(source, now + 300_000_000_000)?);
        let (result_id, finding) = graph
            .current_finding(source.tenant_id, &prior.finding_id)?
            .ok_or("current credential finding absent")?;
        let snapshot = graph
            .snapshot_result(source.tenant_id, &result_id)?
            .ok_or("current credential graph absent")?;
        assert_ne!(snapshot.input_manifest, earlier.input_manifest);
        assert!(snapshot.findings.contains(&finding));
        assert_eq!(finding.state, FindingStateV1::CoverageInsufficient);
        assert_eq!(finding.reason, FindingReasonV1::ContextualCredentialPivot);
        assert!(finding.limits.contains(&"CREDENTIAL_BYTES_UNPROVEN".into()));
        assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
        assert_eq!(finding.evidence, vec![read.id.clone(), network.id.clone()]);
        assert_eq!(finding.effects.len(), 2);
        assert!(finding
            .effects
            .iter()
            .all(|effect| effect.physical_result == GraphPhysicalResultV1::Unknown));
        assert!(snapshot.graph.facts.iter().any(|fact| {
            fact.record_id == read.id
                && matches!(
                    &fact.value,
                    GraphFactValueV1::Credential {
                        completion: None,
                        ..
                    }
                )
        }));
        assert!(snapshot
            .graph
            .edges
            .iter()
            .filter(|edge| edge.key.edge_type == GraphEdgeTypeV1::CredentialAuthority)
            .all(|edge| edge.key.cause == GraphCauseV1::Contextual));
        for old in &earlier.findings {
            assert_eq!(
                graph.finding(source.tenant_id, &old.finding_id, &old.revision)?,
                Some(old.clone())
            );
        }
        let input = GraphNotificationQualification::replay(&fixture.data, source, &snapshot)?;
        let replay = GraphAndFindingOwner::derive(&input, &fixture.execution)?;
        assert_eq!(replay.graph, snapshot.graph);
        assert_eq!(replay.findings, snapshot.findings);
    }
    Ok(())
}
