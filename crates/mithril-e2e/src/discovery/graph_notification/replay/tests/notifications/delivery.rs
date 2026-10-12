use super::*;

#[test]
fn notification_delivery_retries() -> crate::platform::TestResult<()> {
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
    assert_eq!(router.route(&fixture.graph, NOW)?, 1);
    for (route, package) in [("human", "unused-package"), ("primary", "HF-PROC-001")] {
        router.configure(
            &grants[0],
            fixture.notification_policy(route, package),
            NOW + 1,
        )?;
    }
    assert_eq!(
        router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 1)?,
        1
    );
    let sink = IncidentSink::new(finding.finding_id.clone());
    assert_eq!(router.deliver(&fixture.graph, &sink, NOW + 1)?, 2);
    let states = router.obligations(&grants[1], NOW + 1)?;
    assert_eq!(states.len(), 1);
    let failed = &states[0];
    assert_eq!(failed.failure, Some(NotificationFailureV1::TransportFailed));
    assert_eq!(failed.deadline_utc_ns, Some(NOW + 100));
    assert_eq!(
        failed
            .attempts
            .iter()
            .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
            .count(),
        1
    );
    assert!(failed.human_acknowledgement.is_none());
    assert_eq!(
        router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 2)?,
        0
    );
    assert_eq!(router.obligations(&grants[1], NOW + 2)?, states);
    assert_eq!(router.deliver(&fixture.graph, &sink, NOW + 10)?, 0);
    assert_eq!(router.obligations(&grants[1], NOW + 10)?, states);
    assert_eq!(router.deliver(&fixture.graph, &sink, NOW + 11)?, 1);
    let retried = router.obligations(&grants[1], NOW + 11)?;
    assert_eq!(retried.len(), 1);
    let retried = &retried[0];
    assert_eq!(retried.failure, None);
    assert_eq!(retried.deadline_utc_ns, failed.deadline_utc_ns);
    assert_eq!(retried.minimum_priority, failed.minimum_priority);
    assert_eq!(
        retried
            .attempts
            .iter()
            .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
            .count(),
        2
    );
    assert!(retried.human_acknowledgement.is_none());
    Ok(())
}
