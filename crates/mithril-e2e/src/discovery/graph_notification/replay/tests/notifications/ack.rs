use super::*;

#[test]
fn notification_human_acknowledges_overdue() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(NOW)?;
    let source = fixture.notification_input()?;
    let tenant = source.tenant_id;
    let graph = &fixture.graph;
    assert_eq!(graph.process(NOW)?, 1);
    let snapshot = graph.snapshot(&source)?.ok_or("graph absent")?;
    assert_eq!(snapshot.findings.len(), 1);
    let finding = &snapshot.findings[0];
    let (result_id, current) = graph
        .current_finding(tenant, &finding.finding_id)?
        .ok_or("current finding absent")?;
    assert_eq!(&current, finding);
    let reference = NotificationFindingRefV1 {
        result_id,
        finding_id: finding.finding_id.clone(),
    };
    let grants = GraphNotificationQualification::grants(tenant, NOW);
    let (_store, router) = fixture.notification_router(&grants)?;
    router.route(graph, NOW)?;
    for (route, package) in [("human", "unused-package"), ("primary", "HF-PROC-001")] {
        router.configure(
            &grants[0],
            fixture.notification_policy(route, package),
            NOW + 1,
        )?;
    }
    router.route_finding(graph, tenant, &reference, NOW + 1)?;
    let sink = IncidentSink {
        failed: AtomicBool::new(true),
        finding_id: finding.finding_id.clone(),
    };
    assert_eq!(router.deliver(graph, &sink, NOW + 1)?, 1);
    assert_eq!(router.deliver(graph, &sink, NOW + 101)?, 1);
    let states = router.obligations(&grants[1], NOW + 101)?;
    assert_eq!(states.len(), 1);
    let overdue = &states[0];
    assert!(overdue.overdue(NOW + 101));
    assert_eq!(overdue.deadline_utc_ns, Some(NOW + 100));
    assert_eq!(overdue.overdue_since_utc_ns, Some(NOW + 100));
    assert!(overdue
        .attempts
        .iter()
        .any(|attempt| attempt.kind == AcknowledgementEscalation));
    let key = overdue.key;
    let revision = overdue.finding_revision;
    let human = router.acknowledge(&grants[1], key, revision, [6; 16], NOW + 102)?;
    assert_eq!(human.deadline_utc_ns, overdue.deadline_utc_ns);
    let receipt = NotificationAcknowledgementV1 {
        request_id: [6; 16],
        principal_id: grants[1].principal_id,
        authorization_revision: grants[1].authorization_revision,
        finding_revision: revision,
        acknowledged_utc_ns: NOW + 102,
    };
    assert_eq!(human.human_acknowledgement, Some(receipt));
    assert_eq!(
        router.acknowledge(&grants[1], key, revision, [6; 16], NOW + 103)?,
        human
    );
    assert!(matches!(
        router.acknowledge(&grants[1], key, revision, [7; 16], NOW + 103),
        Err(araphor_analysis::Error::Data {
            source: Error::Notification {
                code: NotificationErrorCodeV1::Conflict,
                field: "acknowledgement retry",
                ..
            }
        })
    ));
    assert!(!human.overdue(NOW + 103));
    assert_eq!(router.deliver(graph, &sink, NOW + 103)?, 0);
    let health = router.health(&grants[1], NOW + 103)?;
    assert_eq!((health.acknowledged, health.overdue), (1, 0));
    assert_eq!(
        graph.finding(tenant, &finding.finding_id, &finding.revision)?,
        Some(finding.clone())
    );
    Ok(())
}
