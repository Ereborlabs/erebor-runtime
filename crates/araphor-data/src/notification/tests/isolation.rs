use super::*;

#[test]
fn control_notification_capacity_isolation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    router.route(&graph, 100)?;

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
    for number in 0..1024u32 {
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
            Err(crate::Error::StorageCapacity {
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
    let sink = Sink::default();
    for now in [150, 151] {
        assert!(matches!(
            router.route(&graph, now),
            Err(crate::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            })
        ));
        assert!(matches!(
            router.deliver(&graph, &sink, now),
            Err(crate::Error::StorageCapacity {
                resource: "tenant retained revisions",
                ..
            })
        ));
    }
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, concern.key);
    let current = router.obligations(&other, 151)?.remove(0);
    assert_eq!(current.deadline_utc_ns, concern.deadline_utc_ns);
    assert_eq!(current.attempts.len(), 1);
    assert!(current.attempts[0]
        .result
        .as_ref()
        .is_some_and(NotificationSinkResultV1::accepted));
    Ok(())
}
