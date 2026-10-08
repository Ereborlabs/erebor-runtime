use super::*;

#[test]
fn control_notification_approved_concern_stays_unconfirmed_and_requires_human_review() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(dir.path().join("data"))?);
    let graph = GraphAndFindingOwner::new(store.clone(), Arc::new(Context))?;
    let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
    configure(&router)?;
    let mut agent = grant(NotificationPrincipalV1::Agent);
    agent
        .operations
        .push(NotificationOperationV1::SubmitConcern);
    let concern = UnconfirmedNotificationConcernV1 {
        concern_id: [7; 16],
        model_label: "possible anomaly".into(),
        summary: "Review the model report".into(),
        context: vec![],
        sensitivity: ContextSensitivityV1::Tenant,
        suggested_priority: NotificationPriorityV1::Warning,
    };
    assert!(router
        .submit_concern(&agent, "primary", concern.clone(), 100)
        .is_err());
    let mut approved = policy("primary");
    approved.revision = 2;
    approved.allow_concerns = true;
    router.configure(&grant(NotificationPrincipalV1::Human), approved, 99)?;
    let state = router.submit_concern(&agent, "primary", concern.clone(), 100)?;
    assert!(state.finding.is_none());
    assert_eq!(state.unconfirmed_concern, Some(concern.clone()));
    assert_eq!(
        router.submit_concern(&agent, "primary", concern, 150)?.key,
        state.key
    );
    assert_eq!(
        router
            .submit_concern(
                &agent,
                "primary",
                state.unconfirmed_concern.clone().ok_or("concern absent")?,
                150
            )?
            .deadline_utc_ns,
        Some(200)
    );
    assert!(graph.findings([1; 16])?.is_empty());
    let sink = Sink::default();
    assert_eq!(router.deliver(&graph, &sink, 101)?, 1);
    router.deliver(&graph, &sink, 201)?;
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), 202)?
        .remove(0);
    assert!(state.overdue(202));
    assert!(state.human_acknowledgement.is_none());
    assert!(sink.calls.lock().map_err(|_| "sink lock")?[0]
        .unconfirmed_concern
        .is_some());
    Ok(())
}
