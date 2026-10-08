use super::*;

#[test]
fn control_notification_stronger_revision_delivers_without_deadline_reset() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let mut route = policy("primary");
    route.retry_limit = 1;
    router.configure(&grant(NotificationPrincipalV1::Human), route, 10)?;
    let mut escalation = policy("escalation");
    escalation.package_ids = vec!["unused-package".into()];
    escalation.retry_limit = 1;
    router.configure(&grant(NotificationPrincipalV1::Human), escalation, 10)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    let sink = Sink::default();
    assert_eq!(router.route(&graph, 100)?, 1);
    assert_eq!(router.deliver(&graph, &sink, 100)?, 1);
    let original = router.obligations(&grant(NotificationPrincipalV1::Human), 101)?[0].clone();
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    assert_eq!(router.route(&graph, 150)?, 1);
    assert_eq!(router.deliver(&graph, &sink, 150)?, 1);
    assert_eq!(router.route(&graph, 151)?, 0);
    assert_eq!(router.deliver(&graph, &sink, 151)?, 0);
    let latest = router.obligations(&grant(NotificationPrincipalV1::Human), 151)?[0].clone();
    assert_eq!(latest.key, original.key);
    assert_eq!(latest.deadline_utc_ns, Some(200));
    assert_eq!(latest.priority(), NotificationPriorityV1::Critical);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(
        calls[1].finding.as_ref().ok_or("finding absent")?.revision,
        finding(2, FindingSeverityV1::Critical).revision
    );
    assert_ne!(
        calls[0].finding.as_ref().ok_or("finding absent")?.revision,
        calls[1].finding.as_ref().ok_or("finding absent")?.revision
    );
    drop(calls);
    assert_eq!(latest.attempts.len(), 1);
    assert_ne!(original.attempts[0].number, latest.attempts[0].number);
    assert_eq!(
        router.finding_version(original.key, original.revision)?,
        original
    );
    assert_eq!(router.deliver(&graph, &sink, 201)?, 1);
    let overdue = router.obligations(&grant(NotificationPrincipalV1::Human), 201)?[0].clone();
    assert!(overdue.overdue(201));
    assert_eq!(overdue.deadline_utc_ns, Some(200));
    assert!(overdue.attempts.iter().any(|attempt| {
        attempt.kind == NotificationDeliveryKindV1::AcknowledgementEscalation
            && attempt.finding_revision == latest.finding_revision
    }));
    let mut changed = finding(3, FindingSeverityV1::Info);
    changed.required_action = Some("inspect new effect".into());
    commit_finding(&store, changed, 3)?;
    assert_eq!(router.route(&graph, 220)?, 1);
    let states = router.obligations(&grant(NotificationPrincipalV1::Human), 221)?;
    assert_eq!(states.len(), 2);
    assert!(states
        .iter()
        .any(|state| state.deadline_utc_ns == Some(320)));
    Ok(())
}

#[test]
fn control_notification_new_revision_can_receive_human_ack_with_original_deadline() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    router.route(&graph, 100)?;
    let human = grant(NotificationPrincipalV1::Human);
    let original = router.obligations(&human, 100)?.remove(0);
    let acknowledged = router.acknowledge(
        &human,
        original.key,
        original.finding_revision,
        [5; 16],
        110,
    )?;
    let old_ack = acknowledged
        .human_acknowledgement
        .ok_or("original acknowledgement is absent")?;
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    router.route(&graph, 201)?;
    let revised = router.obligations(&human, 201)?.remove(0);
    assert_eq!(revised.key, original.key);
    assert_eq!(revised.deadline_utc_ns, Some(200));
    assert_eq!(revised.minimum_priority, NotificationPriorityV1::High);
    assert_eq!(revised.priority(), NotificationPriorityV1::Critical);
    assert_ne!(revised.finding_revision, old_ack.finding_revision);
    assert!(revised.overdue(201));
    assert_eq!(router.health(&human, 201)?.acknowledged, 0);
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 201)?, 2);
    let new_ack =
        router.acknowledge(&human, original.key, revised.finding_revision, [6; 16], 202)?;
    assert_eq!(new_ack.deadline_utc_ns, Some(200));
    assert_eq!(new_ack.overdue_since_utc_ns, Some(200));
    assert_eq!(
        new_ack
            .human_acknowledgement
            .ok_or("revised acknowledgement is absent")?
            .finding_revision,
        revised.finding_revision
    );
    assert!(!new_ack.overdue(202));
    assert_eq!(router.health(&human, 202)?.acknowledged, 1);
    assert_eq!(router.deliver(&graph, &sink, 203)?, 0);
    assert_eq!(
        router
            .finding_version(original.key, acknowledged.revision)?
            .human_acknowledgement,
        Some(old_ack)
    );
    assert_eq!(
        router
            .acknowledge(&human, original.key, revised.finding_revision, [6; 16], 204)?
            .human_acknowledgement,
        new_ack.human_acknowledgement
    );
    assert!(router
        .acknowledge(&human, original.key, revised.finding_revision, [7; 16], 204)
        .is_err());
    Ok(())
}
