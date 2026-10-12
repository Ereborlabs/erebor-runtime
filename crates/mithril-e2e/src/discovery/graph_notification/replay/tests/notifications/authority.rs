use super::*;

#[test]
fn notification_agent_cannot_acknowledge() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(NOW)?;
    let source = fixture.notification_input()?;
    assert_eq!(fixture.graph.process(NOW)?, 1);
    let snapshot = fixture.graph.snapshot(&source)?.ok_or("graph absent")?;
    assert_eq!(snapshot.findings.len(), 1);
    let finding = &snapshot.findings[0];
    let (result_id, current) = fixture
        .graph
        .current_finding(source.tenant_id, &finding.finding_id)?
        .ok_or("current finding absent")?;
    assert_eq!(&current, finding);
    let reference = NotificationFindingRefV1 {
        result_id,
        finding_id: finding.finding_id.clone(),
    };
    let grants = GraphNotificationQualification::grants(source.tenant_id, NOW);
    let (_store, router) = fixture.notification_router(&grants)?;
    router.route(&fixture.graph, NOW)?;
    router.configure(
        &grants[0],
        fixture.notification_policy("primary", &finding.package_id),
        NOW + 1,
    )?;
    router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 1)?;
    let states = router.obligations(&grants[1], NOW + 1)?;
    assert_eq!(states.len(), 1);
    let key = states[0].key;
    let revision = states[0].finding_revision;
    let advisory = Some(NotificationAdvisoryV1 {
        suggested_priority: NotificationPriorityV1::Info,
        model_label: "benign-refused-to-investigate".into(),
    });
    let receipt = router.record_agent(&grants[2], key, [4; 16], advisory.clone(), NOW + 1)?;
    assert_eq!(receipt.priority(), NotificationPriorityV1::Critical);
    assert_eq!(receipt.deadline_utc_ns, states[0].deadline_utc_ns);
    assert!(receipt.human_acknowledgement.is_none());
    assert_eq!(
        router.record_agent(&grants[2], key, [4; 16], advisory.clone(), NOW + 2)?,
        receipt
    );
    let mut foreign = grants[2].clone();
    foreign.tenant_id = [99; 16];
    assert!(matches!(
        router.record_agent(&foreign, key, [4; 16], advisory, NOW + 2),
        Err(Error::Notification {
            code: NotificationErrorCodeV1::Denied,
            ..
        })
    ));
    assert!(matches!(
        router.acknowledge(&grants[2], key, revision, [5; 16], NOW + 2),
        Err(Error::Notification {
            code: NotificationErrorCodeV1::Denied,
            field: "human acknowledgement",
            ..
        })
    ));
    let mut foreign = grants[1].clone();
    foreign.tenant_id = [99; 16];
    assert!(matches!(
        router.acknowledge(&foreign, key, revision, [6; 16], NOW + 101),
        Err(Error::Notification {
            code: NotificationErrorCodeV1::Denied,
            ..
        })
    ));
    assert_eq!(router.obligations(&grants[1], NOW + 101)?, vec![receipt]);
    assert_eq!(
        fixture
            .graph
            .finding(source.tenant_id, &finding.finding_id, &finding.revision)?,
        Some(finding.clone())
    );
    Ok(())
}
