use super::*;

#[test]
fn graph_owner_registers_sources() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    for id in [200, 40] {
        let source = fixture.accept(id, &[GraphNotificationQualification::native(1, true)])?;
        let health = fixture
            .data
            .processor_health(&ProcessorScopeV1 {
                processor_id: GRAPH_PROCESSOR.into(),
                method_version: u64::from(GRAPH_SCHEMA_VERSION),
                identity: source,
            })?
            .ok_or("the new source has no required graph processor")?;
        assert_eq!(health.class, ProcessorClassV1::Required);
        assert_eq!((health.accepted_cursor, health.consumed_cursor), (1, 0));
    }
    Ok(())
}

#[test]
fn graph_owner_wraps_context() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let source = fixture.accept(40, &[GraphNotificationQualification::native(1, true)])?;
    assert_eq!(fixture.graph.process(fixture.now)?, 1);
    let original = fixture.graph.snapshot(&source)?.ok_or("original graph")?;
    let finding = original.findings.first().ok_or("original finding")?;
    let other = fixture.accept(200, &[GraphNotificationQualification::native(1, true)])?;
    assert!(other < source);
    assert_eq!(fixture.graph.process(fixture.now)?, 0);
    assert_eq!(fixture.graph.process(fixture.now)?, 1);
    let retained = fixture.graph.snapshot(&other)?.ok_or("other graph")?;
    let fact = GraphFactV1 {
        record_id: fixture.record(&source, 1)?.id,
        value: GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: true,
            reviewed_policy_revision: "retained-owner-source".into(),
        },
    };
    fixture
        .inputs
        .insert(fact.clone(), "late-owner-baseline", 1)?;
    assert!(fixture.graph.refresh(&source, fixture.now + 1)?);
    let (result, revised) = fixture
        .graph
        .current_finding(source.tenant_id, &finding.finding_id)?
        .ok_or("revised finding")?;
    assert_ne!(revised.revision, finding.revision);
    assert_eq!(revised.required_action, finding.required_action);
    assert_eq!(revised.effects, finding.effects);
    assert_eq!(
        fixture
            .graph
            .finding(source.tenant_id, &finding.finding_id, &finding.revision)?,
        Some(finding.clone())
    );
    assert!(fixture
        .graph
        .snapshot_result(source.tenant_id, &result)?
        .ok_or("revised graph")?
        .graph
        .facts
        .contains(&fact));
    assert_eq!(fixture.graph.snapshot(&other)?, Some(retained));
    assert_eq!(fixture.graph.current_findings(source.tenant_id)?.len(), 2);
    Ok(())
}
