use super::*;

#[test]
fn optional_routes_keep_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("data");
    let store = Arc::new(AnalysisStore::open(&path)?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let mut human = grant(NotificationPrincipalV1::Human);
    human.routes = (0..33).map(|index| format!("route-{index:02}")).collect();
    human.validate()?;
    for name in &human.routes {
        let mut approved = policy("primary");
        approved.route_id = name.clone();
        approved.escalation_route_id = human.routes[0].clone();
        router.configure(&human, approved, 10)?;
    }
    assert_eq!(router.routes(human.tenant_id)?.len(), 33);
    let finding = finding(1, FindingSeverityV1::High);
    commit_finding(&store, finding.clone(), 1)?;
    assert_eq!(route(&router, 100)?, 33);
    assert_eq!(router.related_states(&finding)?.len(), 33);
    let retained = router.obligations(&human, 101)?;
    assert_eq!(retained.len(), 33);
    assert_eq!(route(&router, 102)?, 0);
    drop(router);
    drop(store);
    let store = Arc::new(AnalysisStore::open(path)?);
    let router = NotificationRouter::new(store, Arc::new(Authority))?;
    assert_eq!(router.routes(human.tenant_id)?.len(), 33);
    assert_eq!(router.obligations(&human, 103)?, retained);
    Ok(())
}

#[test]
fn optional_bytes_keep_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("data");
    let store = Arc::new(AnalysisStore::open(&path)?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let mut human = grant(NotificationPrincipalV1::Human);
    human
        .routes
        .extend((0..513).map(|index| format!("route-{index:04}-{}", "r".repeat(50))));
    human.routes.sort();
    router.configure(&human, policy("primary"), 10)?;
    let route = store
        .context_head(
            human.tenant_id,
            NOTIFICATION_ROUTE_OWNER,
            b"primary",
            b"route",
        )?
        .ok_or("route absent")?;
    assert!(route.body.len() > 32 * 1024);
    assert_eq!(ApprovedNotificationRouteV1::try_from(&route)?.grant, human);
    let mut finding = finding(1, FindingSeverityV1::High);
    finding.finding_id = format!("finding:{}", "f".repeat(33 * 1024));
    let reference = NotificationFindingRefV1 {
        finding_id: finding.finding_id.clone(),
        result_id: "graph-test-1".into(),
    };
    commit_finding(&store, finding, 1)?;
    assert_eq!(router.route_finding(human.tenant_id, &reference, 100)?, 1);
    let retained = router.obligations(&human, 101)?;
    let state = retained.first().ok_or("obligation absent")?;
    let context = store
        .context_version(&NotificationRouter::state_key(state))?
        .ok_or("state context absent")?;
    assert!(context.body.len() > 32 * 1024);
    assert_eq!(NotificationObligationV1::try_from(&context)?, *state);
    drop(router);
    drop(store);
    let store = Arc::new(AnalysisStore::open(path)?);
    let router = NotificationRouter::new(store, Arc::new(Authority))?;
    assert_eq!(router.routes(human.tenant_id)?.len(), 1);
    assert_eq!(router.obligations(&human, 102)?, retained);
    Ok(())
}

#[test]
fn configured_limits_keep_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        Default::default(),
        StorageLimitsV1 {
            notification_routes: Some(2),
            notification_states: Some(1),
            context_max_bytes: Some(32 * 1024),
            ..Default::default()
        },
    )?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    let human = grant(NotificationPrincipalV1::Human);
    let mut approved = policy("primary");
    approved.revision = 2;
    approved.allow_concerns = true;
    router.configure(&human, approved.clone(), 11)?;
    let before = store.meta()?;
    router.configure(&human, approved.clone(), 11)?;
    assert_eq!(store.meta()?, before);
    let mut agent = grant(NotificationPrincipalV1::Agent);
    agent
        .operations
        .push(NotificationOperationV1::SubmitConcern);
    for number in 1..=2 {
        router.submit_concern(
            &agent,
            "primary",
            UnconfirmedNotificationConcernV1 {
                concern_id: [number; 16],
                model_label: "review".into(),
                summary: "Review this concern".into(),
                context: Vec::new(),
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Info,
            },
            100,
        )?;
        if number == 1 {
            assert_eq!(router.obligations(&human, 101)?.len(), 1);
        }
    }
    assert!(matches!(
        router.obligations(&human, 101),
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Limit,
                field: "notification read count",
                ..
            }
        })
    ));
    assert_eq!(router.health(&human, 101)?.obligations, 2);
    let before = store.meta()?;
    let mut extra = human.clone();
    extra.routes.push("third".into());
    assert!(matches!(
        router.configure(&extra, policy("third"), 12),
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Limit,
                field: "route count",
                ..
            }
        })
    ));
    assert_eq!(store.meta()?, before);
    let mut large = human.clone();
    large
        .routes
        .extend((0..513).map(|index| format!("route-{index:04}-{}", "r".repeat(50))));
    large.routes.sort();
    approved.revision = 3;
    assert!(matches!(
        router.configure(&large, approved, 12),
        Err(crate::Error::Data {
            source: araphor_data::Error::StorageCapacity {
                resource: "context version bytes",
                ..
            }
        })
    ));
    assert_eq!(store.meta()?, before);
    let routes = router.routes(human.tenant_id)?;
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes
            .iter()
            .find(|route| route.policy.route_id == "primary")
            .ok_or("primary absent")?
            .policy
            .revision,
        2
    );
    assert_eq!(router.health(&human, 101)?.obligations, 2);
    Ok(())
}

#[test]
fn zero_routes_reject_write() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        Default::default(),
        StorageLimitsV1 {
            notification_routes: Some(0),
            ..Default::default()
        },
    )?);
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let before = store.meta()?;
    assert!(matches!(
        router.configure(
            &grant(NotificationPrincipalV1::Human),
            policy("primary"),
            10
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Limit,
                field: "route count",
                ..
            }
        })
    ));
    assert_eq!(store.meta()?, before);
    assert!(router.routes([1; 16])?.is_empty());
    Ok(())
}
