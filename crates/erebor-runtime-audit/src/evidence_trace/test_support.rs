use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_policy::Decision;
use serde_json::json;

use super::{EvidenceTraceArtifact, EvidenceTraceRequest};

pub(crate) fn request_with_record() -> EvidenceTraceRequest {
    request_with_records([(
        "allow-process",
        ExecutionSurface::Terminal,
        ActionKind::ProcessExec,
        "google-chrome",
        Decision::Allow { rule_id: None },
        Decision::Allow { rule_id: None },
    )])
}

pub(crate) fn request_with_records(
    records: impl IntoIterator<
        Item = (
            &'static str,
            ExecutionSurface,
            ActionKind,
            &'static str,
            Decision,
            Decision,
        ),
    >,
) -> EvidenceTraceRequest {
    EvidenceTraceRequest::new(
        records
            .into_iter()
            .map(
                |(id, surface, action, uri, policy_decision, final_decision)| {
                    record(id, surface, action, uri, policy_decision, final_decision)
                },
            )
            .collect(),
        json!({
            "rules": [
                {
                    "id": "deny-oauth-callback-network-request",
                    "match": { "surface": "browser_cdp", "action": "network_request" },
                    "decision": "deny",
                    "reason": "callback denied"
                }
            ]
        }),
        json!({ "session": { "runner": { "kind": "linux_host" } } }),
        vec![EvidenceTraceArtifact::new(
            "Audit JSONL",
            "audit.jsonl",
            "abc",
        )],
        "test purpose",
    )
}

fn record(
    id: &str,
    surface: ExecutionSurface,
    action: ActionKind,
    uri: &str,
    policy_decision: Decision,
    final_decision: Decision,
) -> AuditRecord {
    AuditRecord {
        event: RuntimeEvent {
            id: EventId::new(id),
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("openclaw"),
                kind: ActorKind::Agent,
            },
            surface,
            action,
            target: Some(TargetRef {
                label: Some(String::from("target")),
                uri: Some(uri.to_owned()),
            }),
            payload: json!({ "method": "Page.navigate" }),
            risk: RiskMetadata {
                level: RiskLevel::Medium,
                reasons: vec![String::from("test")],
            },
            timestamp: String::from("2026-06-17T00:00:00Z"),
        },
        policy_decision,
        final_decision,
        context_pin: None,
    }
}
