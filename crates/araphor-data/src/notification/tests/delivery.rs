use super::*;

#[test]
fn control_notification_failure_acceptance_does_not_acknowledge_overdue_obligation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    router.route(&graph, 100)?;
    let sink = Sink {
        fail_primary: true,
        ..Default::default()
    };
    assert_eq!(router.deliver(&graph, &sink, 100)?, 2);
    router.record_agent(
        &grant(NotificationPrincipalV1::Agent),
        router.obligations(&grant(NotificationPrincipalV1::Human), 101)?[0].key,
        [5; 16],
        Some(NotificationAdvisoryV1 {
            suggested_priority: NotificationPriorityV1::Info,
            model_label: "expected".into(),
        }),
        101,
    )?;
    router.deliver(&graph, &sink, 201)?;
    let state = router.obligations(&grant(NotificationPrincipalV1::Human), 202)?[0].clone();
    assert!(state.human_acknowledgement.is_none());
    assert!(state.overdue(202));
    assert_eq!(state.priority(), NotificationPriorityV1::High);
    assert!(state
        .attempts
        .iter()
        .any(|attempt| attempt.kind == NotificationDeliveryKindV1::AcknowledgementEscalation));
    assert!(sink
        .calls
        .lock()
        .map_err(|_| "sink lock")?
        .iter()
        .any(|call| call.kind == NotificationDeliveryKindV1::AcknowledgementEscalation));
    assert!(router
        .acknowledge(
            &grant(NotificationPrincipalV1::Agent),
            state.key,
            state.finding_revision,
            [6; 16],
            203
        )
        .is_err());
    let ack = router.acknowledge(
        &grant(NotificationPrincipalV1::Human),
        state.key,
        state.finding_revision,
        [6; 16],
        203,
    )?;
    assert_eq!(ack.deadline_utc_ns, Some(200));
    assert_eq!(ack.overdue_since_utc_ns, Some(200));
    assert_eq!(router.deliver(&graph, &sink, 204)?, 0);
    Ok(())
}

#[test]
fn control_notification_restart_reuses_pending_attempt_and_original_deadline() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("data");
    let key;
    {
        let store = Arc::new(AnalysisStore::open(&path)?);
        let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        configure(&router)?;
        commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
        router.route(&graph, 100)?;
        let mut state = router
            .obligations(&grant(NotificationPrincipalV1::Human), 101)?
            .remove(0);
        key = state.key;
        state.attempts.push(NotificationAttemptV1 {
            number: 1,
            kind: NotificationDeliveryKindV1::Finding,
            finding_revision: state.finding_revision,
            context_revision: state.revision,
            priority: state.priority(),
            started_utc_ns: 101,
            completed_utc_ns: None,
            result: None,
        });
        router.save(&mut state)?;
    }
    let store = Arc::new(AnalysisStore::open(&path)?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    let mut updated = policy("primary");
    updated.revision = 2;
    router.configure(&grant(NotificationPrincipalV1::Human), updated, 149)?;
    let sink = Sink::default();
    assert_eq!(router.route(&graph, 150)?, 1);
    assert_eq!(router.deliver(&graph, &sink, 150)?, 1);
    assert_eq!(router.deliver(&graph, &sink, 151)?, 0);
    let states = router.obligations(&grant(NotificationPrincipalV1::Human), 151)?;
    assert_eq!(states[0].key, key);
    assert_eq!(states[0].deadline_utc_ns, Some(200));
    assert_eq!(states[0].attempts.len(), 1);
    assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?[0].attempt, 1);
    assert_eq!(
        sink.calls.lock().map_err(|_| "sink lock")?[0].route_revision,
        1
    );
    assert_eq!(states[0].route.as_ref().ok_or("route absent")?.revision, 2);
    let mut foreign = grant(NotificationPrincipalV1::Human);
    foreign.tenant_id = [7; 16];
    assert!(router
        .acknowledge(&foreign, key, states[0].finding_revision, [8; 16], 152)
        .is_err());
    let mut stale = grant(NotificationPrincipalV1::Human);
    stale.authorization_revision = 2;
    assert!(router.obligations(&stale, 152).is_err());
    Ok(())
}

#[test]
fn control_notification_route_change_keeps_deadline_floors_and_bounded_retry_evidence() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    router.route(&graph, 100)?;
    let original = router
        .obligations(&grant(NotificationPrincipalV1::Human), 100)?
        .remove(0);
    let sink = Sink {
        fail_primary: true,
        ..Default::default()
    };
    router.deliver(&graph, &sink, 100)?;
    router.deliver(&graph, &sink, 101)?;
    let mut updated = policy("primary");
    updated.revision = 2;
    updated.minimum_priority = NotificationPriorityV1::Info;
    updated.acknowledgement_ns = 1_000;
    router.configure(&grant(NotificationPrincipalV1::Human), updated, 102)?;
    assert_eq!(router.route(&graph, 102)?, 1);
    for now in 102..=104 {
        router.deliver(&graph, &sink, now)?;
    }
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 105)?
        .remove(0);
    assert_eq!(state.key, original.key);
    assert_eq!(state.deadline_utc_ns, Some(200));
    assert_eq!(state.minimum_priority, NotificationPriorityV1::High);
    assert_eq!(state.source_priority, NotificationPriorityV1::Warning);
    assert_eq!(state.failure, Some(NotificationFailureV1::RetryExhausted));
    assert_eq!(
        state
            .attempts
            .iter()
            .filter(|attempt| attempt.kind == NotificationDeliveryKindV1::Finding)
            .count(),
        4
    );
    assert!(sink
        .calls
        .lock()
        .map_err(|_| "sink lock")?
        .iter()
        .all(|delivery| delivery.priority >= NotificationPriorityV1::High));
    assert_eq!(
        sink.calls
            .lock()
            .map_err(|_| "sink lock")?
            .iter()
            .filter(|delivery| delivery.kind == NotificationDeliveryKindV1::Finding)
            .map(|delivery| (delivery.route_id.as_str(), delivery.route_revision))
            .collect::<Vec<_>>(),
        [
            ("primary", 1),
            ("primary", 1),
            ("primary", 2),
            ("primary", 2)
        ]
    );
    assert_eq!(router.deliver(&graph, &sink, 105)?, 0);
    assert_eq!(router.deliver(&graph, &sink, 201)?, 1);
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 202)?
        .remove(0);
    assert!(state.overdue(202));
    assert!(state.human_acknowledgement.is_none());
    Ok(())
}

#[test]
fn control_notification_disclosure_denial_keeps_failure_and_authorized_escalation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    router.configure(
        &grant(NotificationPrincipalV1::Human),
        policy("escalation"),
        10,
    )?;
    let mut restricted = policy("primary");
    restricted.max_sensitivity = ContextSensitivityV1::Tenant;
    router.configure(&grant(NotificationPrincipalV1::Human), restricted, 10)?;
    let mut finding = finding(1, FindingSeverityV1::High);
    finding.sensitivity = ContextSensitivityV1::HostRestricted;
    commit_finding(&store, finding, 1)?;
    router.route(&graph, 100)?;
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 100)?, 2);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, NotificationDeliveryKindV1::FailureEscalation);
    drop(calls);
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 101)?
        .remove(0);
    assert_eq!(state.failure, Some(NotificationFailureV1::DisclosureDenied));
    assert_eq!(state.deadline_utc_ns, Some(200));
    let mut limited = grant(NotificationPrincipalV1::Human);
    limited.max_sensitivity = ContextSensitivityV1::Tenant;
    assert!(router.obligations(&limited, 101)?.is_empty());
    assert!(router
        .acknowledge(&limited, state.key, state.finding_revision, [8; 16], 101)
        .is_err());
    Ok(())
}
