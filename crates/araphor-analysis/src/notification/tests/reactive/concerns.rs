use super::*;

#[tokio::test]
async fn native_concern_route_changes() -> TestResult {
    for case in ["live", "ack", "stale", "expired", "missing"] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        store.enable_graph_owner()?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        let engine = Engine::new(store.clone(), Limits::default())?;
        let human = grant(NotificationPrincipalV1::Human);
        let mut primary = policy("primary");
        primary.allow_concerns = true;
        router.configure(&human, primary.clone(), 10)?;
        let mut agent = grant(NotificationPrincipalV1::Agent);
        agent
            .operations
            .push(NotificationOperationV1::SubmitConcern);
        let submitted = router.submit_concern(
            &agent,
            "primary",
            UnconfirmedNotificationConcernV1 {
                concern_id: [7; 16],
                model_label: "review".into(),
                summary: "Review this concern".into(),
                context: Vec::new(),
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Warning,
            },
            100,
        )?;
        let sink = Sink::default();
        let update = capture(&engine, NotificationRouter::SQL, 101).await?;
        let delivered = router.consume(&update, &sink)?;
        assert!(delivered.routed.is_empty());
        assert_eq!(delivered.delivered.len(), 1);
        assert_eq!(
            *delivered.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        let mut original = router.obligations(&human, 101)?.remove(0);
        assert_eq!(original.key, submitted.key);
        assert_eq!(original.deadline_utc_ns, Some(200));
        assert_eq!(original.failure, Some(NotificationFailureV1::NoRoute));
        assert!(original
            .attempts
            .last()
            .ok_or("accepted attempt absent")?
            .result
            .as_ref()
            .is_some_and(NotificationSinkResultV1::accepted));
        if case == "ack" || case == "stale" {
            original = router.acknowledge(
                &human,
                original.key,
                original.finding_revision,
                [6; 16],
                110,
            )?;
        }
        if case == "stale" {
            original.finding_revision = original
                .revision
                .checked_add(1)
                .ok_or("fixture revision overflow")?;
            router.save(&mut original)?;
            let update = capture(&engine, NotificationRouter::SQL, 111).await?;
            let delivered = router.consume(&update, &sink)?;
            assert!(delivered.routed.is_empty());
            assert_eq!(delivered.delivered.len(), 1);
            assert_eq!(
                *delivered.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                1
            );
            original = router.obligations(&human, 111)?.remove(0);
            assert!(original
                .human_acknowledgement
                .is_some_and(|ack| ack.finding_revision != original.finding_revision));
            assert!(original
                .attempts
                .last()
                .ok_or("accepted current attempt absent")?
                .result
                .as_ref()
                .is_some_and(NotificationSinkResultV1::accepted));
        }
        if case == "missing" {
            original.route = Some(NotificationRouteRefV1 {
                route_id: "missing".into(),
                revision: 1,
            });
            router.save(&mut original)?;
        }
        if case == "expired" {
            let mut expires = human.clone();
            expires.expires_utc_ns = 115;
            primary.revision = 2;
            primary.minimum_priority = NotificationPriorityV1::Critical;
            router.configure(&expires, primary.clone(), 112)?;
        }
        let mut reader = human.clone();
        if case == "missing" {
            assert!(router.obligations(&human, 119)?.is_empty());
            reader.routes.push("missing".into());
            reader.routes.sort();
            reader.validate()?;
        }
        let before_calls = sink.calls.lock().map_err(|_| "sink lock")?.len();
        router.configure(&human, policy("escalation"), 120)?;
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 120).await?;
        let refreshed = router.consume(&update, &sink)?;
        assert!(refreshed.routed.is_empty());
        let live = case == "live" || case == "stale";
        assert_eq!(refreshed.delivered.len(), usize::from(live));
        if live {
            assert_eq!(
                *refreshed.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                0
            );
            let current = router.obligations(&reader, 120)?.remove(0);
            assert_eq!(
                current.escalation.as_ref().map(|route| route.revision),
                Some(1)
            );
            assert_eq!(current.failure, None);
        } else {
            assert_eq!(store.meta()?, before);
            assert_eq!(router.obligations(&reader, 120)?.remove(0), original);
        }
        if case != "expired" {
            primary.revision = 2;
            primary.minimum_priority = NotificationPriorityV1::Critical;
            router.configure(&human, primary, 130)?;
        }
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 130).await?;
        let refreshed = router.consume(&update, &sink)?;
        assert!(refreshed.routed.is_empty());
        assert_eq!(refreshed.delivered.len(), usize::from(live));
        if live {
            assert_eq!(
                *refreshed.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                0
            );
            let current = router.obligations(&reader, 130)?.remove(0);
            assert_eq!(current.route.as_ref().map(|route| route.revision), Some(2));
            assert_eq!(current.minimum_priority, NotificationPriorityV1::Critical);
        } else {
            assert_eq!(store.meta()?, before);
            assert_eq!(router.obligations(&reader, 130)?.remove(0), original);
        }
        let mut escalation = policy("escalation");
        escalation.revision = 2;
        escalation.minimum_priority = NotificationPriorityV1::Critical;
        router.configure(&human, escalation, 140)?;
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 140).await?;
        let refreshed = router.consume(&update, &sink)?;
        assert!(refreshed.routed.is_empty());
        assert_eq!(refreshed.delivered.len(), usize::from(live));
        if live {
            assert_eq!(
                *refreshed.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                0
            );
        } else {
            assert_eq!(store.meta()?, before);
        }
        let current = router.obligations(&reader, 140)?.remove(0);
        assert_eq!(current.key, original.key);
        assert_eq!(current.finding_revision, original.finding_revision);
        assert_eq!(current.deadline_utc_ns, original.deadline_utc_ns);
        assert_eq!(current.attempts, original.attempts);
        assert_eq!(
            current.human_acknowledgement,
            original.human_acknowledgement
        );
        assert_eq!(current.unconfirmed_concern, original.unconfirmed_concern);
        if live {
            assert_eq!(current.route.as_ref().map(|route| route.revision), Some(2));
            assert_eq!(
                current.escalation.as_ref().map(|route| route.revision),
                Some(2)
            );
            assert_eq!(current.minimum_priority, NotificationPriorityV1::Critical);
            assert_eq!(current.failure, None);
        } else {
            assert_eq!(current, original);
        }
        assert_eq!(
            sink.calls.lock().map_err(|_| "sink lock")?.len(),
            before_calls
        );
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 141).await?;
        let quiet = router.consume(&update, &sink)?;
        assert!(quiet.routed.is_empty() && quiet.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(router.obligations(&reader, 141)?.remove(0), current);
        if live {
            let update = capture(&engine, NotificationRouter::SQL, 201).await?;
            let overdue = router.consume(&update, &sink)?;
            assert!(overdue.routed.is_empty());
            assert_eq!(overdue.delivered.len(), 1);
            assert_eq!(
                *overdue.delivered[0]
                    .1
                    .as_ref()
                    .map_err(|error| error.to_string())?,
                1
            );
            let calls = sink.calls.lock().map_err(|_| "sink lock")?;
            assert_eq!(calls.len(), before_calls + 1);
            let alert = calls.last().ok_or("concern alert absent")?;
            assert_eq!(
                alert.kind,
                NotificationDeliveryKindV1::AcknowledgementEscalation
            );
            assert_eq!(alert.route_revision, 2);
            assert_eq!(alert.priority, NotificationPriorityV1::Critical);
            assert_eq!(alert.deadline_utc_ns, 200);
            assert!(alert.finding.is_none() && alert.unconfirmed_concern.is_some());
        }
    }
    Ok(())
}
