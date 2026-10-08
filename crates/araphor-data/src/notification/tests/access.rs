use super::*;

#[test]
fn control_notification_unrouted_health_and_context_compare_are_explicit() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    assert_eq!(router.route(&graph, 100)?, 1);
    let health = router.health(&grant(NotificationPrincipalV1::Human), 101)?;
    assert!(!health.routing_available);
    assert_eq!(health.unrouted, 1);
    let mut state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 101)?
        .remove(0);
    let mut stale = state.clone();
    router.save(&mut state)?;
    stale.failure = Some(NotificationFailureV1::SinkRejected);
    assert!(router.save(&mut stale).is_err());
    Ok(())
}

#[test]
fn control_notification_full_window_keeps_exact_revision_in_immutable_graph_result() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    let finding = finding(256, FindingSeverityV1::High);
    assert!(serde_json::to_vec(&finding.revision)?.len() > 32 * 1024);
    commit_finding(&store, finding.clone(), 256)?;
    assert_eq!(router.route(&graph, 300)?, 1);
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 301)?
        .remove(0);
    assert!(serde_json::to_vec(&state)?.len() < 32 * 1024);
    let reference = state
        .finding
        .as_ref()
        .ok_or("finding reference is absent")?;
    assert_eq!(
        graph
            .finding_result([1; 16], &reference.result_id, &reference.finding_id)?
            .ok_or("finding result is absent")?
            .revision,
        finding.revision
    );
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 301)?, 1);
    assert_eq!(
        sink.calls.lock().map_err(|_| "sink lock")?[0]
            .finding
            .as_ref()
            .ok_or("delivery finding is absent")?
            .revision,
        finding.revision
    );
    Ok(())
}

#[test]
fn control_notification_hidden_pages_advance_without_disclosure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let human = grant(NotificationPrincipalV1::Human);
    let mut approved = policy("primary");
    approved.allow_concerns = true;
    router.configure(&human, approved, 10)?;
    let mut agent = grant(NotificationPrincipalV1::Agent);
    agent
        .operations
        .push(NotificationOperationV1::SubmitConcern);
    for index in 1_u32..=257 {
        let mut concern_id = [0; 16];
        concern_id[12..].copy_from_slice(&index.to_be_bytes());
        router.submit_concern(
            &agent,
            "primary",
            UnconfirmedNotificationConcernV1 {
                concern_id,
                model_label: "possible anomaly".into(),
                summary: "Review the model report".into(),
                context: vec![],
                sensitivity: ContextSensitivityV1::HostRestricted,
                suggested_priority: NotificationPriorityV1::Warning,
            },
            100,
        )?;
    }
    let mut finding = finding(1, FindingSeverityV1::High);
    finding.sensitivity = ContextSensitivityV1::HostRestricted;
    let reference = NotificationFindingRefV1 {
        result_id: "graph-test-1".into(),
        finding_id: finding.finding_id.clone(),
    };
    commit_finding(&store, finding, 1)?;
    assert!(matches!(
        router.route_finding(&graph, [99; 16], &reference, 101),
        Err(crate::Error::Notification {
            code: NotificationErrorCodeV1::Denied,
            field: "current finding scope",
            ..
        })
    ));
    let mut stale = reference.clone();
    stale.result_id = "graph-test-0".into();
    assert!(matches!(
        router.route_finding(&graph, [1; 16], &stale, 101),
        Err(crate::Error::Notification {
            code: NotificationErrorCodeV1::Conflict,
            field: "current finding reference",
            ..
        })
    ));
    assert_eq!(router.route_finding(&graph, [1; 16], &reference, 101)?, 1);
    let mut limited = human.clone();
    limited.max_sensitivity = ContextSensitivityV1::Tenant;
    let mut after = None;
    let mut pages = 0;
    loop {
        let (page, next) = router.obligations_page(&limited, after, 102)?;
        assert!(page.is_empty());
        let Some(next) = next else {
            break;
        };
        assert!(after.is_none_or(|prior: NotificationKeyV1| {
            prior.notification_id < next.notification_id
        }));
        after = Some(next);
        pages += 1;
    }
    assert!(pages >= 2);
    assert_eq!(router.health(&limited, 102)?.obligations, 0);
    let foreign = NotificationKeyV1 {
        tenant_id: [99; 16],
        notification_id: [7; 16],
    };
    assert!(matches!(
        router.obligations_page(&human, Some(foreign), 102),
        Err(crate::Error::Notification {
            code: NotificationErrorCodeV1::Denied,
            field: "notification page scope",
            ..
        })
    ));
    let mut after = None;
    let mut last = None;
    loop {
        let (page, next) = router.obligations_page(&human, after, 102)?;
        for state in page {
            if state.unconfirmed_concern.is_some() {
                last = Some(state);
            }
        }
        let Some(next) = next else {
            break;
        };
        after = Some(next);
    }
    let last = last.ok_or("tail concern absent")?;
    assert_eq!(
        router.submit_concern(
            &agent,
            "primary",
            last.unconfirmed_concern.clone().ok_or("concern absent")?,
            103,
        )?,
        last
    );
    assert!(router
        .acknowledge(&limited, last.key, last.finding_revision, [8; 16], 103)
        .is_err());
    let acknowledged = router.acknowledge(&human, last.key, last.finding_revision, [8; 16], 103)?;
    assert_eq!(acknowledged.deadline_utc_ns, Some(200));
    assert!(acknowledged.human_acknowledgement.is_some());
    assert_eq!(router.health(&human, 103)?.obligations, 258);
    Ok(())
}
