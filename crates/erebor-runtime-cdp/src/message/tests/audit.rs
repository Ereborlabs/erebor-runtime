use erebor_runtime_events::{ActionKind, ActorKind, ExecutionSurface};
use erebor_runtime_policy::{Decision, LocalPolicy};
use serde_json::json;

use super::support::{context, ApproveAll, RecordingAuditSink};
use crate::{CdpCommandDecoder, CdpCommandEnforcer, CdpEnforcementAction};

#[test]
fn audits_forwarded_governed_navigation_with_full_record_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "allow-example-navigation",
          "match": {
            "surface": "browser_cdp",
            "action": "browser_navigate",
            "target_contains": "example.com"
          },
          "decision": "allow"
        }] }"#,
    )?;
    let engine =
        erebor_runtime_core::LocalEnforcementEngine::with_hooks(policy, ApproveAll, sink.clone());
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 3, "method": "Page.navigate", "params": { "url": "https://example.com/" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;
    let records = sink.records();

    assert_eq!(action, CdpEnforcementAction::Forward);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event.session_id.as_str(), "session-1");
    assert_eq!(records[0].event.actor.id, "agent-1");
    assert_eq!(records[0].event.actor.kind, ActorKind::Agent);
    assert_eq!(records[0].event.surface, ExecutionSurface::BrowserCdp);
    assert_eq!(records[0].event.action, ActionKind::BrowserNavigate);
    assert_eq!(
        records[0]
            .event
            .target
            .as_ref()
            .and_then(|target| target.uri.as_deref()),
        Some("https://example.com/")
    );
    assert_eq!(
        records[0].event.payload,
        json!({
            "kind": "command",
            "method": "Page.navigate",
            "message_id": 3,
            "cdp_session_id": null,
            "page": {
                "active_page": null,
                "command_page": null,
                "pages": [],
                "browser_targets": [],
                "client_session_id": null,
                "client_target": null
            },
            "params": { "url": "https://example.com/" }
        })
    );
    assert_eq!(
        records[0].event.risk.reasons,
        vec![String::from("governed CDP method `Page.navigate`")]
    );
    assert_eq!(
        records[0].final_decision,
        Decision::Allow {
            rule_id: Some(String::from("allow-example-navigation"))
        }
    );
    assert_eq!(records[0].policy_decision, records[0].final_decision);
    Ok(())
}

#[test]
fn audits_denied_governed_messages_with_source_method() -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "deny-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "deny",
          "reason": "script evaluation denied"
        }] }"#,
    )?;
    let engine =
        erebor_runtime_core::LocalEnforcementEngine::with_hooks(policy, ApproveAll, sink.clone());
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 9, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;
    let records = sink.records();

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("script evaluation denied")
        }
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].final_decision,
        Decision::Deny {
            reason: String::from("script evaluation denied"),
            rule_id: Some(String::from("deny-script-eval"))
        }
    );
    Ok(())
}

#[test]
fn audits_approval_required_commands_as_pending() -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "approve-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "require_approval",
          "reason": "script evaluation requires approval"
        }] }"#,
    )?;
    let engine =
        erebor_runtime_core::LocalEnforcementEngine::with_hooks(policy, ApproveAll, sink.clone());
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 10, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;
    let records = sink.records();

    assert_eq!(
        action,
        CdpEnforcementAction::AwaitApproval {
            reason: String::from("script evaluation requires approval")
        }
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].final_decision,
        Decision::RequireApproval {
            reason: String::from("script evaluation requires approval"),
            rule_id: Some(String::from("approve-script-eval")),
            approval_id: None
        }
    );
    Ok(())
}
