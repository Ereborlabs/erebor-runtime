use super::*;

#[tokio::test]
async fn native_escalation_route_changes() -> TestResult {
    for acknowledged in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        let engine = Engine::new(store.clone(), Limits::default())?;
        let human = grant(NotificationPrincipalV1::Human);
        let sink = Sink::default();
        router.configure(&human, policy("primary"), 10)?;
        commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
        assert_eq!(route(&router, 100)?, 1);
        let update = capture(&engine, NotificationRouter::SQL, 100).await?;
        let delivered = router.consume(&update, &sink)?;
        assert_eq!(delivered.delivered.len(), 1);
        assert_eq!(
            *delivered.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        let first = router.obligations(&human, 100)?.remove(0);
        assert_eq!(first.failure, Some(NotificationFailureV1::NoRoute));
        assert!(first.escalation.is_none());

        router.configure(&human, policy("escalation"), 150)?;
        if acknowledged {
            let saved =
                router.acknowledge(&human, first.key, first.finding_revision, [6; 16], 150)?;
            assert!(saved.escalation.is_none());
            assert!(saved.human_acknowledgement.is_some());
        }
        let update = capture(&engine, NotificationRouter::SQL, 150).await?;
        let added = router.consume(&update, &sink)?;
        assert_eq!(added.routed.len(), 1);
        assert_eq!(
            *added.routed[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        assert_eq!(added.delivered.len(), 1);
        assert_eq!(
            *added.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            0
        );
        let current = router.obligations(&human, 150)?.remove(0);
        assert_eq!(current.key, first.key);
        assert_eq!(current.finding_revision, first.finding_revision);
        assert_eq!(current.deadline_utc_ns, first.deadline_utc_ns);
        assert_eq!(current.attempts, first.attempts);
        assert_eq!(current.failure, None);
        assert_eq!(
            current.escalation.as_ref().map(|route| route.revision),
            Some(1)
        );

        let mut escalation = policy("escalation");
        escalation.revision = 2;
        escalation.minimum_priority = NotificationPriorityV1::Critical;
        router.configure(&human, escalation, 151)?;
        let update = capture(&engine, NotificationRouter::SQL, 151).await?;
        let revised = router.consume(&update, &sink)?;
        assert_eq!(revised.routed.len(), 1);
        assert_eq!(
            *revised.routed[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        assert_eq!(revised.delivered.len(), 1);
        assert_eq!(
            *revised.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            0
        );
        let current = router.obligations(&human, 151)?.remove(0);
        assert_eq!(current.key, first.key);
        assert_eq!(current.finding_revision, first.finding_revision);
        assert_eq!(current.deadline_utc_ns, first.deadline_utc_ns);
        assert_eq!(current.attempts, first.attempts);
        assert_eq!(current.failure, None);
        assert_eq!(current.route.as_ref().map(|route| route.revision), Some(1));
        assert_eq!(
            current.escalation.as_ref().map(|route| route.revision),
            Some(2)
        );
        assert_eq!(current.human_acknowledgement.is_some(), acknowledged);
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 152).await?;
        let stable = router.consume(&update, &sink)?;
        assert!(stable.routed.is_empty() && stable.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);

        let update = capture(&engine, NotificationRouter::SQL, 201).await?;
        let overdue = router.consume(&update, &sink)?;
        assert!(overdue.routed.is_empty());
        assert_eq!(overdue.delivered.len(), usize::from(!acknowledged));
        let calls = sink.calls.lock().map_err(|_| "sink lock")?;
        assert_eq!(calls.len(), if acknowledged { 1 } else { 2 });
        if !acknowledged {
            assert_eq!(
                *overdue.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                1
            );
            let alert = calls.last().ok_or("overdue alert absent")?;
            assert_eq!(
                alert.kind,
                NotificationDeliveryKindV1::AcknowledgementEscalation
            );
            assert_eq!(alert.route_revision, 2);
            assert_eq!(alert.priority, NotificationPriorityV1::Critical);
        }
        drop(calls);
        let current = router.obligations(&human, 201)?.remove(0);
        assert_eq!(current.key, first.key);
        assert_eq!(current.finding_revision, first.finding_revision);
        assert_eq!(current.deadline_utc_ns, first.deadline_utc_ns);
        assert_eq!(current.human_acknowledgement.is_some(), acknowledged);
    }
    Ok(())
}

#[tokio::test]
async fn native_tenant_capacity_isolation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        Default::default(),
        araphor_data::StorageLimitsV1 {
            tenant_revisions: Some(32),
            ..Default::default()
        },
    )?);
    let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let engine = Engine::new(store.clone(), Limits::default())?;
    let sink = Sink::default();
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    assert_eq!(route(&router, 100)?, 1);
    assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
    let initial = router
        .obligations(&grant(NotificationPrincipalV1::Human), 100)?
        .remove(0);
    assert!(initial.attempts.is_empty());

    let mut other = grant(NotificationPrincipalV1::Agent);
    other.tenant_id = [2; 16];
    other
        .operations
        .push(NotificationOperationV1::SubmitConcern);
    for name in ["primary", "escalation"] {
        let mut route = policy(name);
        route.tenant_id = other.tenant_id;
        route.allow_concerns = true;
        router.configure(&other, route, 10)?;
    }
    let concern = router.submit_concern(
        &other,
        "primary",
        UnconfirmedNotificationConcernV1 {
            concern_id: [7; 16],
            model_label: "review".into(),
            summary: "Review this concern".into(),
            context: Vec::new(),
            sensitivity: ContextSensitivityV1::Tenant,
            suggested_priority: NotificationPriorityV1::Info,
        },
        100,
    )?;
    let mut full = false;
    for number in 0..32u32 {
        match store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "quota-input".into(),
                entity_key: number.to_be_bytes().to_vec(),
                lifetime_key: b"input".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        }) {
            Ok(_) => {}
            Err(araphor_data::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            }) => {
                full = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(full);
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    for now in [150, 151] {
        let update = capture(&engine, NotificationRouter::SQL, now).await?;
        assert_eq!(update.snapshot.selection.tenant_id, [1; 16]);
        let calls_before = sink.calls.lock().map_err(|_| "sink lock")?.len();
        let failed = router.consume(&update, &sink)?;
        assert_eq!(failed.routed.len(), 1);
        assert!(matches!(
            &failed.routed[0].1,
            Err(crate::Error::Data {
                source: araphor_data::Error::StorageCapacity {
                    resource: "tenant retained revisions",
                    ..
                }
            })
        ));
        assert!(failed.delivered.is_empty());
        assert_eq!(router.state(initial.key)?, initial);
        assert_eq!(
            sink.calls.lock().map_err(|_| "sink lock")?.len(),
            calls_before
        );
        drop(update);
        let update = capture_tenant(&engine, other.tenant_id, NotificationRouter::SQL, now).await?;
        assert_eq!(update.snapshot.selection.tenant_id, other.tenant_id);
        let healthy = router.consume(&update, &sink)?;
        assert!(healthy.routed.is_empty());
        if now == 150 {
            assert_eq!(healthy.delivered.len(), 1);
            assert_eq!(healthy.delivered[0].0, concern.key);
            assert_eq!(
                *healthy.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                1
            );
        } else {
            assert!(healthy.delivered.is_empty());
        }
    }
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, concern.key);
    drop(calls);
    let current = router.obligations(&other, 151)?.remove(0);
    assert_eq!(current.deadline_utc_ns, concern.deadline_utc_ns);
    assert_eq!(current.attempts.len(), 1);
    assert!(current.attempts[0]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    Ok(())
}
