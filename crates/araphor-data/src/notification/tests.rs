use super::*;
use crate::{
    AnalysisResultCommitV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, FindingReasonV1,
    FindingSeverityV1, FindingStateV1, GraphContextProvider, GraphPackageCheckpointV1,
    GraphPackageStateV1, GraphRevisionV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    GraphVersionV1, ProcessorScopeV1, ValidatedEvidenceBatchV1, GRAPH_PROCESSOR,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Authority;
impl NotificationAuthorization for Authority {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> Result<()> {
        NotificationErrorCodeV1::Denied.require(
            grant.authorization_revision == 1 && now < grant.expires_utc_ns,
            "test grant",
        )
    }
}
struct Context;
impl GraphContextProvider for Context {
    fn facts(&self, _record: &crate::DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        Ok(vec![])
    }
}
#[derive(Default)]
struct Sink {
    calls: Mutex<Vec<NotificationDeliveryV1>>,
    fail_primary: bool,
}
impl NotificationSink for Sink {
    fn deliver(&self, request: &NotificationDeliveryV1) -> NotificationSinkResultV1 {
        let Ok(mut calls) = self.calls.lock() else {
            return NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable,
            };
        };
        calls.push(request.clone());
        drop(calls);
        if self.fail_primary && request.kind == NotificationDeliveryKindV1::Finding {
            NotificationSinkResultV1::Failed {
                reason: NotificationFailureV1::SinkUnavailable,
            }
        } else {
            NotificationSinkResultV1::Accepted {
                receipt: "accepted".into(),
            }
        }
    }
}

fn grant(principal: NotificationPrincipalV1) -> NotificationGrantV1 {
    NotificationGrantV1 {
        tenant_id: [1; 16],
        principal_id: [9; 16],
        principal,
        authorization_revision: 1,
        routes: vec!["escalation".into(), "primary".into()],
        operations: vec![
            NotificationOperationV1::Configure,
            NotificationOperationV1::Read,
            NotificationOperationV1::Acknowledge,
            NotificationOperationV1::RecordAgent,
        ],
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        expires_utc_ns: 10_000,
    }
}
fn policy(route: &str) -> NotificationPolicyV1 {
    NotificationPolicyV1 {
        tenant_id: [1; 16],
        route_id: route.into(),
        revision: 1,
        package_ids: vec![if route == "primary" {
            "HF-PROC-001".into()
        } else {
            "HF-XNODE-001".into()
        }],
        minimum_priority: NotificationPriorityV1::High,
        acknowledgement_ns: 100,
        retry_limit: 4,
        retry_delay_ns: 1,
        escalation_route_id: "escalation".into(),
        max_sensitivity: ContextSensitivityV1::HostRestricted,
        allow_concerns: false,
    }
}
fn configure(router: &NotificationRouter) -> Result<()> {
    router.configure(
        &grant(NotificationPrincipalV1::Human),
        policy("escalation"),
        10,
    )?;
    router.configure(
        &grant(NotificationPrincipalV1::Human),
        policy("primary"),
        10,
    )
}
fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}
fn finding(cursor: u64, severity: FindingSeverityV1) -> FindingV1 {
    let evidence = vec![DiscoveryRecordIdV1 {
        stream: source(),
        cpu_id: 0,
        durable_cursor: cursor,
    }];
    FindingV1 {
        tenant_id: [1; 16],
        finding_id: "finding:exact-process-key".into(),
        revision: GraphRevisionV1 {
            evidence: (1..=cursor)
                .map(|durable_cursor| DiscoveryRecordIdV1 {
                    stream: source(),
                    cpu_id: 0,
                    durable_cursor,
                })
                .collect(),
            coverage: vec![],
            context: vec![],
            missing_ranges: vec![],
        },
        package_id: "HF-PROC-001".into(),
        package_version: 1,
        subject_id: GraphSubjectKeyV1::native(&source(), GraphSubjectKindV1::Process, vec![4]),
        state: FindingStateV1::Confirmed,
        window_start_utc_ns: 1,
        window_end_utc_ns: 10,
        evidence,
        required_coverage_interval_ids: vec![],
        policy_provenance: vec![],
        effects: vec![],
        reason: FindingReasonV1::UnexpectedEffect,
        severity,
        sensitivity: ContextSensitivityV1::Tenant,
        required_action: Some("review".into()),
        limits: vec![],
    }
}
fn commit_finding(store: &AnalysisStore, finding: FindingV1, cursor: u64) -> Result<()> {
    let scope = ProcessorScopeV1 {
        processor_id: GRAPH_PROCESSOR.into(),
        method_version: 1,
        identity: source(),
    };
    let first_cursor = store
        .source_status(&source())?
        .map_or(1, |status| status.receipt.contiguous_cursor + 1);
    let count = cursor - first_cursor + 1;
    store.accept_validated_batch(
        source(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor,
            last_cursor: cursor,
            intake_utc_ns: cursor,
            framed_records: b"frame".repeat(count as usize).into(),
            frame_ends: (1..=count).map(|index| index as usize * 5).collect(),
        },
    )?;
    store.register_graph(&source())?;
    let revision = finding.revision.clone();
    let witnesses = revision
        .evidence
        .iter()
        .map(|id| crate::AnalysisWitnessV1 {
            identity: crate::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
            cursor: id.durable_cursor,
            expires_utc_ns: 1 + crate::GRAPH_WITNESS_TTL_NS,
        })
        .collect();
    let package = |id: &str| GraphPackageCheckpointV1 {
        package_id: id.into(),
        package_version: 1,
        required_inputs: vec![],
        state: GraphPackageStateV1::Waiting,
        maximum_lateness_ns: 1,
        retention_ttl_ns: 1,
        clock_uncertainty_ns: None,
        late_action: "revise".into(),
        window_ns: 1,
        window_records: 256,
        window_bytes: crate::GRAPH_WINDOW_BYTES,
        coverage_predicate: "covered".into(),
        replay_contract_id: "replay-v1".into(),
        result_states: vec![FindingStateV1::Confirmed],
        accepted_cursor_watermark: cursor,
        observed_boottime_watermark_ns: cursor,
    };
    let snapshot = GraphSnapshotV1 {
        schema_version: 1,
        scope: scope.clone(),
        first_cursor: 1,
        last_cursor: cursor,
        input_manifest: revision.clone(),
        graph: GraphVersionV1 {
            revision,
            subjects: vec![finding.subject_id.clone()],
            edges: vec![],
            branches: vec![],
            facts: vec![],
        },
        findings: vec![finding],
        packages: vec![
            package("HF-PROC-001"),
            package("HF-DW-001"),
            package("HF-XNODE-001"),
        ],
        missing_ranges: vec![],
        input_positions: vec![],
        previous_result_id: None,
        context_notice_revision: 0,
        witness_deadline_utc_ns: 1 + crate::GRAPH_WITNESS_TTL_NS,
    };
    store.commit_graph(
        &AnalysisResultCommitV1 {
            scope,
            expected_cursor: first_cursor - 1,
            consumed_cursor: cursor,
            coverage_revision: 0,
            context_revision: 0,
            result_id: format!("graph-test-{cursor}"),
            body: serde_json::to_vec(&snapshot).context(NotificationEncodingSnafu)?,
            created_utc_ns: cursor,
            witnesses,
            context_refs: vec![],
        },
        true,
    )?;
    Ok(())
}

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
    assert_eq!(latest.attempts.len(), 2);
    assert_ne!(latest.attempts[0].number, latest.attempts[1].number);
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
    let acknowledged = router.acknowledge(&human, original.key, [5; 16], 110)?;
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
    let new_ack = router.acknowledge(&human, original.key, [6; 16], 202)?;
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
            .acknowledge(&human, original.key, [6; 16], 204)?
            .human_acknowledgement,
        new_ack.human_acknowledgement
    );
    assert!(router
        .acknowledge(&human, original.key, [7; 16], 204)
        .is_err());
    Ok(())
}

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
            [6; 16],
            203
        )
        .is_err());
    let ack = router.acknowledge(
        &grant(NotificationPrincipalV1::Human),
        state.key,
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
    assert!(router.acknowledge(&foreign, key, [8; 16], 152).is_err());
    let mut stale = grant(NotificationPrincipalV1::Human);
    stale.authorization_revision = 2;
    assert!(router.obligations(&stale, 152).is_err());
    Ok(())
}

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
        .acknowledge(&limited, state.key, [8; 16], 101)
        .is_err());
    Ok(())
}

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
