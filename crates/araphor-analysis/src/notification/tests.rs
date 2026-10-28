use super::*;
use araphor_data::{
    AnalysisResultCommitV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, FindingReasonV1,
    FindingSeverityV1, FindingStateV1, GraphPackageCheckpointV1, GraphPackageStateV1,
    GraphRevisionV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1, GraphVersionV1,
    ProcessorScopeV1, ValidatedEvidenceBatchV1, GRAPH_PROCESSOR,
};
use snafu::ResultExt as _;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod access;
mod concern;
mod delivery;
mod isolation;
mod lifecycle;
mod limits;
mod reactive;
mod revisions;

pub(crate) struct Authority;
impl NotificationAuthorization for Authority {
    fn check(&self, grant: &NotificationGrantV1, now: u64) -> araphor_data::Result<()> {
        NotificationErrorCodeV1::Denied.require(
            grant.authorization_revision == 1 && now < grant.expires_utc_ns,
            "test grant",
        )
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

pub(crate) fn grant(principal: NotificationPrincipalV1) -> NotificationGrantV1 {
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
pub(crate) fn policy(route: &str) -> NotificationPolicyV1 {
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
pub(crate) fn manifest(cursor: u64) -> GraphRevisionV1 {
    GraphRevisionV1 {
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
    }
}

pub(crate) fn finding(cursor: u64, severity: FindingSeverityV1) -> FindingV1 {
    let evidence = vec![DiscoveryRecordIdV1 {
        stream: source(),
        cpu_id: 0,
        durable_cursor: cursor,
    }];
    FindingV1 {
        tenant_id: [1; 16],
        finding_id: "finding:exact-process-key".into(),
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
    commit_finding_at(store, finding, cursor, 1)
}

pub(crate) fn commit_finding_at(
    store: &AnalysisStore,
    finding: FindingV1,
    cursor: u64,
    now: u64,
) -> Result<()> {
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
            intake_utc_ns: now,
            framed_records: b"frame".repeat(count as usize).into(),
            frame_ends: (1..=count).map(|index| index as usize * 5).collect(),
        },
    )?;
    store.register_graph(&source())?;
    let revision = manifest(cursor);
    let witnesses = revision
        .evidence
        .iter()
        .map(|id| araphor_data::AnalysisWitnessV1 {
            identity: araphor_data::AnalysisStreamIdentityV1::Evidence(id.stream.clone()),
            cursor: id.durable_cursor,
            expires_utc_ns: now + araphor_data::GRAPH_WITNESS_TTL_NS,
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
        coverage_predicate: "covered".into(),
        replay_contract_id: format!("{id}/v1"),
        result_states: vec![FindingStateV1::Confirmed],
        accepted_cursor_watermark: cursor,
        observed_boottime_watermark_ns: cursor,
    };
    let snapshot = GraphSnapshotV1 {
        schema_version: 1,
        scope: scope.clone(),
        first_cursor: 1,
        last_cursor: cursor,
        input_manifest: revision,
        graph: GraphVersionV1 {
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
        previous_result_id: store
            .processor_result(&scope)?
            .map(|result| result.result_id),
        context_notice_revision: 0,
        witness_deadline_utc_ns: now + araphor_data::GRAPH_WITNESS_TTL_NS,
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
            created_utc_ns: now,
            witnesses,
            context_refs: vec![],
        },
        true,
        || Ok(()),
    )?;
    Ok(())
}

fn route(router: &NotificationRouter, now: u64) -> Result<usize> {
    let Some((result_id, finding)) = router
        .store
        .graph_findings(
            [1; 16],
            None,
            Some("finding:exact-process-key"),
            1,
            usize::MAX,
        )?
        .pop()
    else {
        return Ok(0);
    };
    router.route_finding(
        [1; 16],
        &NotificationFindingRefV1 {
            finding_id: finding.finding_id,
            result_id,
        },
        now,
    )
}

fn deliver(router: &NotificationRouter, sink: &dyn NotificationSink, now: u64) -> Result<usize> {
    let state = router
        .obligations(&grant(NotificationPrincipalV1::Human), now)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Invalid,
                field: "test obligation",
            }
            .build()
        })?;
    router.deliver_obligation(state.key, sink, now)
}
