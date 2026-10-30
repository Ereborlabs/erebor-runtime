use super::*;

#[test]
fn notification_restart_keeps_state() -> crate::platform::TestResult<()> {
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
    let (store, router) = fixture.notification_router(&grants)?;
    assert_eq!(router.route(graph, NOW)?, 1);
    for (route, package) in [("human", "unused-package"), ("primary", "HF-PROC-001")] {
        router.configure(
            &grants[0],
            fixture.notification_policy(route, package),
            NOW + 1,
        )?;
    }
    router.route_finding(graph, tenant, &reference, NOW + 1)?;
    let sink = IncidentSink::new(finding.finding_id.clone());
    assert_eq!(router.deliver(graph, &sink, NOW + 1)?, 2);
    let before = router.obligations(&grants[1], NOW + 1)?;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].failure, Some(TransportFailed));
    assert_eq!(before[0].deadline_utc_ns, Some(NOW + 100));
    assert_eq!(before[0].attempts.len(), 2);
    assert_eq!(before[0].attempts[0].kind, Finding);
    drop(router);
    drop(store);
    let ReplayQualification {
        graph,
        intake,
        data,
        inputs,
        execution,
        authenticated,
        now,
        root,
    } = fixture;
    drop(graph);
    drop(intake);
    drop(execution);
    drop(data);
    let data = Arc::new(AnalysisStore::open(root.path().join("analysis"))?);
    let execution = InstalledAnalysis::testing(Some(data.clone()), authenticated.tenant_id)?;
    let graph = GraphAndFindingOwner::new(data.clone(), inputs, execution)?;
    assert_eq!(graph.snapshot(&source)?, Some(snapshot));
    let store = ControlStore::open(root.path().join("notification-control"))?;
    let authority = Arc::new(ConfiguredNotificationAuthority::new(store, &grants, None)?);
    let router = NotificationRouter::new(data, authority)?;
    assert_eq!(router.obligations(&grants[1], now + 11)?, before);
    router.route_finding(&graph, tenant, &reference, now + 11)?;
    assert_eq!(router.obligations(&grants[1], now + 11)?, before);
    assert_eq!(router.deliver(&graph, &sink, now + 11)?, 1);
    let after = router.obligations(&grants[1], now + 11)?;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].failure, None);
    assert_eq!(after[0].key, before[0].key);
    assert_eq!(after[0].deadline_utc_ns, before[0].deadline_utc_ns);
    assert_eq!(after[0].minimum_priority, before[0].minimum_priority);
    assert_eq!(after[0].attempts.len(), 3);
    assert_eq!(&after[0].attempts[..2], before[0].attempts.as_slice());
    assert_eq!(after[0].attempts[2].kind, Finding);
    assert!(after[0].human_acknowledgement.is_none());
    Ok(())
}
