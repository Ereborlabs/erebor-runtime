use super::*;

#[test]
fn notification_route_keeps_deadline() -> crate::platform::TestResult<()> {
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
    assert_eq!(router.route(&fixture.graph, NOW)?, 0);
    let health = router.health(&grants[1], NOW)?;
    assert_eq!((health.obligations, health.unrouted), (1, 1));
    assert!(!health.routing_available);
    let mut policy = fixture.notification_policy("human", "unused-package");
    router.configure(&grants[0], policy.clone(), NOW + 1)?;
    policy.route_id = "primary".into();
    policy.package_ids = vec![finding.package_id.clone()];
    router.configure(&grants[0], policy.clone(), NOW + 1)?;
    assert_eq!(
        router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 1)?,
        1
    );
    let states = router.obligations(&grants[1], NOW + 1)?;
    assert_eq!(states.len(), 1);
    let before = &states[0];
    assert_eq!(before.finding.as_ref(), Some(&reference));
    assert_eq!(before.required_action, finding.required_action);
    assert_eq!(before.first_seen_utc_ns, NOW);
    assert_eq!(before.deadline_utc_ns, Some(NOW + 100));
    assert_eq!(before.priority(), NotificationPriorityV1::Critical);
    policy.revision = 2;
    policy.minimum_priority = NotificationPriorityV1::Info;
    policy.acknowledgement_ns = 1_000;
    router.configure(&grants[0], policy, NOW + 2)?;
    assert_eq!(
        router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 2)?,
        1
    );
    let states = router.obligations(&grants[1], NOW + 2)?;
    assert_eq!(states.len(), 1);
    let after = &states[0];
    assert_eq!(after.key, before.key);
    assert_eq!(after.first_seen_utc_ns, before.first_seen_utc_ns);
    assert_eq!(after.deadline_utc_ns, before.deadline_utc_ns);
    assert_eq!(after.minimum_priority, before.minimum_priority);
    assert_eq!(after.source_priority, before.source_priority);
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.route.as_ref().map(|route| route.revision), Some(2));
    assert_eq!(
        router.route_finding(&fixture.graph, source.tenant_id, &reference, NOW + 3)?,
        0
    );
    assert_eq!(router.obligations(&grants[1], NOW + 3)?, states);
    Ok(())
}
