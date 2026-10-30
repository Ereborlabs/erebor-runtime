use super::*;

fn revise_finding(store: &AnalysisStore, result_id: &str, next: FindingV1, now: u64) -> TestResult {
    let (prior, _) = store
        .graph_findings(next.tenant_id, None, Some(&next.finding_id), 1)?
        .pop()
        .ok_or("current finding absent")?;
    let mut snapshot = store
        .graph_result(next.tenant_id, &prior)?
        .ok_or("current graph absent")?;
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.input_manifest, manifest(1));
    assert!(snapshot.input_manifest.context.is_empty());
    let cursor = store
        .processor_health(&snapshot.scope)?
        .ok_or("graph progress absent")?
        .consumed_cursor;
    assert_eq!(cursor, 1);
    snapshot.previous_result_id = Some(prior);
    snapshot.findings[0] = next.clone();
    store.commit_graph_snapshot(
        AnalysisResultCommitV1 {
            scope: snapshot.scope.clone(),
            expected_cursor: cursor,
            consumed_cursor: cursor,
            coverage_revision: 0,
            context_revision: 0,
            result_id: result_id.into(),
            body: Vec::new(),
            created_utc_ns: now,
            witnesses: snapshot
                .input_manifest
                .evidence
                .iter()
                .map(|id| araphor_data::AnalysisWitnessV1 {
                    identity: araphor_data::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
                    cursor: id.durable_cursor,
                    expires_utc_ns: snapshot.witness_deadline_utc_ns,
                })
                .collect(),
            context_refs: Vec::new(),
        },
        araphor_data::analysis::CanonicalGraph::new(snapshot.clone())?,
        &[],
        &[],
        &[],
        false,
        || Ok(()),
    )?;
    assert_eq!(
        store.graph_result(next.tenant_id, result_id)?,
        Some(snapshot)
    );
    let (head, actual) = store
        .graph_findings(next.tenant_id, None, Some(&next.finding_id), 1)?
        .pop()
        .ok_or("revised finding absent")?;
    assert_eq!(head, result_id);
    assert_eq!(actual, next);
    assert_eq!(
        store
            .source_status(&source())?
            .ok_or("source absent")?
            .receipt
            .contiguous_cursor,
        1
    );
    Ok(())
}

#[tokio::test]
async fn native_action_changes() -> TestResult {
    for matched in [true, false] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        let engine = Engine::new(store.clone(), Limits::default())?;
        if matched {
            configure(&router)?;
        }
        let initial = finding(1, FindingSeverityV1::High);
        commit_finding(&store, initial.clone(), 1)?;
        let sink = Sink::default();
        assert_eq!(route(&router, 100)?, 1);
        let update = capture(&engine, NotificationRouter::SQL, 100).await?;
        let delivered = router.consume(&update, &sink)?;
        assert!(delivered.routed.is_empty());
        assert_eq!(delivered.delivered.len(), usize::from(matched));
        for (_, result) in &delivered.delivered {
            assert_eq!(*result.as_ref().map_err(|error| error.to_string())?, 1);
        }
        let human = grant(NotificationPrincipalV1::Human);
        let original = router.obligations(&human, 100)?.remove(0);
        let mut changed = initial.clone();
        changed.required_action = None;
        assert_eq!(changed.evidence, initial.evidence);
        revise_finding(&store, "graph:action-none", changed, 150)?;
        let update = capture(&engine, NotificationRouter::SQL, 150).await?;
        let result = router.consume(&update, &sink)?;
        assert_eq!(result.routed.len(), 1);
        assert_eq!(
            *result.routed[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        assert_eq!(result.delivered.len(), 1);
        assert_eq!(
            *result.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            usize::from(matched)
        );
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 150).await?;
        let stable = router.consume(&update, &sink)?;
        assert!(stable.routed.is_empty() && stable.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(
            sink.calls.lock().map_err(|_| "sink lock")?.len(),
            2 * usize::from(matched)
        );
        let states = router.obligations(&human, 150)?;
        assert_eq!(states.len(), 2);
        assert!(states.iter().any(|state| state.required_action.is_none()));
        assert_eq!(
            states.iter().find(|state| state.key == original.key),
            Some(&original)
        );
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 151).await?;
        let stable = router.consume(&update, &sink)?;
        assert!(stable.routed.is_empty() && stable.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        revise_finding(&store, "graph:action-original", initial, 160)?;
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 160).await?;
        let restored = router.consume(&update, &sink)?;
        assert!(restored.routed.is_empty() && restored.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(router.obligations(&human, 160)?, states);
    }
    Ok(())
}

#[tokio::test]
async fn native_priority_changes() -> TestResult {
    for matched in [true, false] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        let engine = Engine::new(store.clone(), Limits::default())?;
        if matched {
            configure(&router)?;
        }
        let initial = finding(1, FindingSeverityV1::Warning);
        commit_finding(&store, initial.clone(), 1)?;
        let sink = Sink::default();
        assert_eq!(route(&router, 100)?, 1);
        let human = grant(NotificationPrincipalV1::Human);
        let original = router.obligations(&human, 100)?.remove(0);
        let mut raised = initial.clone();
        raised.severity = FindingSeverityV1::Critical;
        revise_finding(&store, "graph:priority-raised", raised, 150)?;
        let update = capture(&engine, NotificationRouter::SQL, 150).await?;
        let result = router.consume(&update, &sink)?;
        assert_eq!(result.routed.len(), 1);
        assert_eq!(
            *result.routed[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        let current = router.obligations(&human, 150)?.remove(0);
        assert_eq!(current.key, original.key);
        assert_eq!(current.finding_revision, original.finding_revision);
        assert_eq!(current.deadline_utc_ns, original.deadline_utc_ns);
        assert_eq!(current.source_priority, NotificationPriorityV1::Critical);
        assert_eq!(current.sensitivity, original.sensitivity);
        assert_eq!(result.delivered.len(), 1);
        assert_eq!(
            *result.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            usize::from(matched)
        );
        if matched {
            let calls = sink.calls.lock().map_err(|_| "sink lock")?;
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].priority, NotificationPriorityV1::Critical);
        } else {
            assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
        }
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 151).await?;
        let stable = router.consume(&update, &sink)?;
        assert!(stable.routed.is_empty() && stable.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        let mut lowered = initial;
        lowered.severity = FindingSeverityV1::Info;
        revise_finding(&store, "graph:priority-lowered", lowered, 160)?;
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 160).await?;
        let result = router.consume(&update, &sink)?;
        assert!(result.routed.is_empty() && result.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(router.obligations(&human, 160)?.remove(0), current);
    }
    Ok(())
}

#[tokio::test]
async fn native_sensitivity_changes() -> TestResult {
    for matched in [true, false] {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let _graph = store.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant([1; 16])])?;
        let router = NotificationRouter::new(store.clone(), Arc::new(Authority))?;
        let engine = Engine::new(store.clone(), Limits::default())?;
        if matched {
            configure(&router)?;
        }
        let mut initial = finding(1, FindingSeverityV1::High);
        initial.sensitivity = ContextSensitivityV1::Public;
        commit_finding(&store, initial.clone(), 1)?;
        let sink = Sink::default();
        assert_eq!(route(&router, 100)?, 1);
        let human = grant(NotificationPrincipalV1::Human);
        let original = router.obligations(&human, 100)?.remove(0);
        let mut raised = initial.clone();
        raised.sensitivity = ContextSensitivityV1::HostRestricted;
        revise_finding(&store, "graph:sensitivity-raised", raised, 150)?;
        let update = capture(&engine, NotificationRouter::SQL, 150).await?;
        let result = router.consume(&update, &sink)?;
        assert_eq!(result.routed.len(), 1);
        assert_eq!(
            *result.routed[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            1
        );
        let current = router.obligations(&human, 150)?.remove(0);
        assert_eq!(current.key, original.key);
        assert_eq!(current.finding_revision, original.finding_revision);
        assert_eq!(current.deadline_utc_ns, original.deadline_utc_ns);
        assert_eq!(current.sensitivity, ContextSensitivityV1::HostRestricted);
        assert_eq!(current.source_priority, original.source_priority);
        assert_eq!(result.delivered.len(), 1);
        assert_eq!(
            *result.delivered[0]
                .1
                .as_ref()
                .map_err(|error| error.to_string())?,
            usize::from(matched)
        );
        if matched {
            assert_eq!(sink.calls.lock().map_err(|_| "sink lock")?.len(), 1);
        } else {
            assert!(sink.calls.lock().map_err(|_| "sink lock")?.is_empty());
        }
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 151).await?;
        let stable = router.consume(&update, &sink)?;
        assert!(stable.routed.is_empty() && stable.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        let mut lowered = initial;
        lowered.sensitivity = ContextSensitivityV1::Tenant;
        revise_finding(&store, "graph:sensitivity-lowered", lowered, 160)?;
        let before = store.meta()?;
        let update = capture(&engine, NotificationRouter::SQL, 160).await?;
        let result = router.consume(&update, &sink)?;
        assert!(result.routed.is_empty() && result.delivered.is_empty());
        assert_eq!(store.meta()?, before);
        assert_eq!(router.obligations(&human, 160)?.remove(0), current);
    }
    Ok(())
}
