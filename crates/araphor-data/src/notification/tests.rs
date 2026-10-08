use super::*;
use crate::{
    AnalysisResultCommitV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, FindingReasonV1,
    FindingSeverityV1, FindingStateV1, GraphContextProvider, GraphPackageCheckpointV1,
    GraphPackageStateV1, GraphRevisionV1, GraphSnapshotV1, GraphSubjectKeyV1, GraphSubjectKindV1,
    GraphVersionV1, ProcessorScopeV1, ValidatedEvidenceBatchV1, GRAPH_PROCESSOR,
};
use snafu::ResultExt as _;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod access;
mod concern;
mod delivery;
mod isolation;
mod lifecycle;
mod revisions;

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
