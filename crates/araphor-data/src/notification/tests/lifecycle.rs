use super::*;

#[test]
fn control_notification_stale_ack() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    router.route(&graph, 100)?;
    let human = grant(NotificationPrincipalV1::Human);
    let first = router.obligations(&human, 100)?.remove(0);
    router.acknowledge(&human, first.key, first.finding_revision, [5; 16], 110)?;
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    router.route(&graph, 201)?;
    for request in [[5; 16], [6; 16]] {
        assert!(matches!(
            router.acknowledge(&human, first.key, first.finding_revision, request, 201),
            Err(crate::Error::Notification {
                code: NotificationErrorCodeV1::Conflict,
                field: "acknowledgement finding revision",
                ..
            })
        ));
    }
    let current = router.obligations(&human, 201)?.remove(0);
    assert!(current.overdue(201));
    assert_eq!(router.health(&human, 201)?.acknowledged, 0);
    let acknowledged =
        router.acknowledge(&human, current.key, current.finding_revision, [6; 16], 202)?;
    assert!(!acknowledged.overdue(202));
    Ok(())
}

#[test]
fn control_notification_escalation_update() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    let human = grant(NotificationPrincipalV1::Human);
    router.configure(&human, policy("primary"), 10)?;
    commit_finding(&store, finding(1, FindingSeverityV1::High), 1)?;
    router.route(&graph, 100)?;
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 100)?, 1);
    let first = router.obligations(&human, 100)?.remove(0);
    assert_eq!(first.failure, Some(NotificationFailureV1::NoRoute));
    assert!(first.escalation.is_none());
    router.configure(&human, policy("escalation"), 150)?;
    assert_eq!(router.route(&graph, 150)?, 1);
    let mut escalation = policy("escalation");
    escalation.revision = 2;
    escalation.minimum_priority = NotificationPriorityV1::Critical;
    router.configure(&human, escalation, 151)?;
    assert_eq!(router.route(&graph, 151)?, 1);
    let current = router.obligations(&human, 151)?.remove(0);
    assert_eq!(current.key, first.key);
    assert_eq!(current.finding_revision, first.finding_revision);
    assert_eq!(current.deadline_utc_ns, first.deadline_utc_ns);
    assert_eq!(current.attempts, first.attempts);
    assert_eq!(current.failure, None);
    assert_eq!(
        current.escalation.as_ref().map(|route| route.revision),
        Some(2)
    );
    assert_eq!(router.deliver(&graph, &sink, 201)?, 1);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    let alert = calls.last().ok_or("overdue alert absent")?;
    assert_eq!(
        alert.kind,
        NotificationDeliveryKindV1::AcknowledgementEscalation
    );
    assert_eq!(alert.route_revision, 2);
    assert_eq!(alert.priority, NotificationPriorityV1::Critical);
    Ok(())
}

#[test]
fn control_notification_legacy_attempts() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("data");
    let first;
    {
        let store = Arc::new(AnalysisStore::open(&path)?);
        let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        configure(&router)?;
        let human = grant(NotificationPrincipalV1::Human);
        let sink = Sink::default();
        let mut history = Vec::new();
        let mut original = None;
        for cursor in 1..=50 {
            commit_finding(&store, finding(cursor, FindingSeverityV1::High), cursor)?;
            assert_eq!(router.route(&graph, 100 + cursor)?, 1);
            assert_eq!(router.deliver(&graph, &sink, 100 + cursor)?, 1);
            let mut current = router.obligations(&human, 100 + cursor)?.remove(0);
            assert_eq!(current.attempts.len(), 1);
            assert_eq!(current.attempts[0].number, cursor);
            history.push(current.attempts[0].clone());
            let _ = original.get_or_insert_with(|| current.clone());
            if cursor == 48 {
                current.attempts = history.clone();
                current.attempt_sequence = 0;
                let expected = current.revision;
                current.revision += 1;
                let mut body = serde_json::to_value(&current)?;
                let _ = body
                    .as_object_mut()
                    .ok_or("legacy state object")?
                    .remove("attempt_sequence");
                store.commit_context_checked(
                    &AnalysisContextVersionV1 {
                        key: NotificationRouter::state_key(&current),
                        valid_from_utc_ns: None,
                        valid_until_utc_ns: None,
                        sensitivity: current.sensitivity,
                        body: serde_json::to_vec(&body)?,
                    },
                    expected,
                )?;
            }
        }
        first = original.ok_or("original obligation absent")?;
        assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 50);
    }
    let store = Arc::new(AnalysisStore::open(&path)?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store, Arc::new(Authority))?;
    let human = grant(NotificationPrincipalV1::Human);
    let current = router.obligations(&human, 151)?.remove(0);
    assert_eq!(current.key, first.key);
    assert_eq!(current.deadline_utc_ns, first.deadline_utc_ns);
    assert_eq!(current.attempt_sequence, 50);
    assert_eq!(current.attempts[0].number, 50);
    assert_eq!(router.finding_version(first.key, first.revision)?, first);
    assert_eq!(router.deliver(&graph, &Sink::default(), 151)?, 0);
    Ok(())
}

#[test]
fn control_notification_pending_subject() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    router.route(&graph, 100)?;
    let human = grant(NotificationPrincipalV1::Human);
    let mut pending = router.obligations(&human, 100)?.remove(0);
    pending.attempts.push(NotificationAttemptV1 {
        number: 1,
        kind: NotificationDeliveryKindV1::Finding,
        finding_revision: pending.finding_revision,
        context_revision: pending.revision,
        priority: pending.priority(),
        started_utc_ns: 100,
        completed_utc_ns: None,
        result: None,
    });
    router.save(&mut pending)?;
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    router.route(&graph, 150)?;
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 150)?, 1);
    assert_eq!(router.deliver(&graph, &sink, 151)?, 1);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls[0].attempt, 1);
    assert_eq!(calls[1].attempt, 2);
    assert_eq!(
        calls[0]
            .finding
            .as_ref()
            .ok_or("old subject absent")?
            .revision,
        finding(1, FindingSeverityV1::Warning).revision
    );
    assert_eq!(
        calls[1]
            .finding
            .as_ref()
            .ok_or("new subject absent")?
            .revision,
        finding(2, FindingSeverityV1::Critical).revision
    );
    assert_eq!(
        router.finding_version(pending.key, pending.revision)?,
        pending
    );
    Ok(())
}

#[test]
fn control_notification_pending_escalation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    commit_finding(&store, finding(1, FindingSeverityV1::Warning), 1)?;
    router.route(&graph, 100)?;
    let human = grant(NotificationPrincipalV1::Human);
    let mut pending = router.obligations(&human, 100)?.remove(0);
    pending.attempts.push(NotificationAttemptV1 {
        number: 1,
        kind: NotificationDeliveryKindV1::Finding,
        finding_revision: pending.finding_revision,
        context_revision: pending.revision,
        priority: pending.priority(),
        started_utc_ns: 100,
        completed_utc_ns: Some(100),
        result: Some(NotificationSinkResultV1::Failed {
            reason: NotificationFailureV1::SinkUnavailable,
        }),
    });
    pending.failure = Some(NotificationFailureV1::SinkUnavailable);
    router.save(&mut pending)?;
    pending.attempts.push(NotificationAttemptV1 {
        number: 2,
        kind: NotificationDeliveryKindV1::FailureEscalation,
        finding_revision: pending.finding_revision,
        context_revision: pending.revision,
        priority: pending.priority(),
        started_utc_ns: 100,
        completed_utc_ns: None,
        result: None,
    });
    router.save(&mut pending)?;
    let mut escalation = policy("escalation");
    escalation.revision = 2;
    router.configure(&human, escalation, 150)?;
    commit_finding(&store, finding(2, FindingSeverityV1::Critical), 2)?;
    router.route(&graph, 150)?;
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 150)?, 2);
    let calls = sink.calls.lock().map_err(|_| "sink lock")?;
    assert_eq!(calls[0].attempt, 3);
    assert_eq!(calls[1].attempt, 2);
    assert_eq!(calls[1].kind, NotificationDeliveryKindV1::FailureEscalation);
    assert_eq!(calls[1].route_revision, 1);
    assert_eq!(
        calls[1]
            .finding
            .as_ref()
            .ok_or("old subject absent")?
            .revision,
        finding(1, FindingSeverityV1::Warning).revision
    );
    assert_eq!(
        router.finding_version(pending.key, pending.revision)?,
        pending
    );
    Ok(())
}
