use super::super::*;

mod admission;
mod inputs;
mod memory;

#[test]
fn read_completion_keeps_scope() -> crate::platform::TestResult<()> {
    let now = 1_791_400_000_000_000_000;
    for (source_id, name, path) in [
        (106, "inherited-fd", GraphReadPathV1::InheritedFd),
        (107, "io-uring", GraphReadPathV1::IoUring),
    ] {
        let fixture = ReplayQualification::new(now)?;
        let (read, network, authority) = fixture.completion_inputs(
            source_id,
            name,
            path,
            KernelEffectOperationV1::Read,
            true,
        )?;
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
        assert_eq!(finding.state, FindingStateV1::Confirmed);
        assert_eq!(finding.evidence, vec![read.id.clone(), network.id.clone()]);
        assert!(finding.limits.contains(&"TLS_PAYLOAD_UNOBSERVABLE".into()));
        assert!(finding
            .effects
            .iter()
            .all(|effect| effect.physical_result == GraphPhysicalResultV1::Unknown));
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
        let foreign = ReplayQualification::borrowed_completion(&input, &network.id, [8; 16])?;
        assert!(matches!(
            GraphAndFindingOwner::derive(&foreign, &fixture.execution),
            Err(Error::GraphInvalid {
                field: "credential read completion",
                ..
            })
        ));
        let borrowed = ReplayQualification::borrowed_completion(&input, &read.id, [88; 16])?;
        let unbound = GraphAndFindingOwner::derive(&borrowed, &fixture.execution)?;
        let unbound = unbound
            .findings
            .iter()
            .find(|candidate| candidate.package_id == "HF-DW-001")
            .ok_or("unbound credential finding absent")?;
        assert_eq!(unbound.state, FindingStateV1::CoverageInsufficient);
        assert!(unbound.limits.contains(&"CREDENTIAL_BYTES_UNPROVEN".into()));
    }
    Ok(())
}
