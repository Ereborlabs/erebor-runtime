use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::RuntimeAuditConfig;
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_policy::{Decision, LocalPolicy, PolicySet};
use serde_json::json;

use super::{BrowserTextObserver, ClientTextAction, ClientTextHandler};
use crate::{
    server::audit::CdpAuditRecorder, BrowserTargetId, CdpSessionContext, CdpSessionState,
    ClientTargetSessions,
};

fn context() -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new("session-1"),
        actor: ActorIdentity {
            id: String::from("agent-1"),
            kind: ActorKind::Agent,
        },
        timestamp: String::from("2026-05-13T00:00:00Z"),
    }
}

#[test]
fn client_text_forwards_allowed_commands() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(r#"{ "rules": [] }"#)?;
    let source =
        r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://example.com/" } }"#;
    let mut client_targets = ClientTargetSessions::default();

    let action = ClientTextHandler::handle(
        &engine,
        &context(),
        &CdpSessionState::default(),
        &mut client_targets,
        source,
        None,
    )?;

    assert_eq!(
        action,
        ClientTextAction::Forward {
            payload: source.to_owned()
        }
    );
    Ok(())
}

#[test]
fn client_text_preserves_session_id_in_block_response() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"{ "rules": [{
          "id": "deny-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "deny",
          "reason": "script evaluation denied"
        }] }"#,
    )?;
    let source = r#"{ "id": 5, "sessionId": "cdp-session-1", "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;
    let mut client_targets = ClientTargetSessions::default();
    client_targets.record_attached("cdp-session-1", BrowserTargetId::new("target-1"));

    let action = ClientTextHandler::handle(
        &engine,
        &context(),
        &CdpSessionState::default(),
        &mut client_targets,
        source,
        None,
    )?;

    assert_eq!(
        action,
        ClientTextAction::Reply {
            payload: json!({
                "id": 5,
                "sessionId": "cdp-session-1",
                "error": {
                    "code": -32000,
                    "message": "script evaluation denied"
                }
            })
        }
    );
    Ok(())
}

#[test]
fn browser_attach_response_maps_client_session_to_target() -> Result<(), Box<dyn std::error::Error>>
{
    let engine = engine(r#"{ "rules": [] }"#)?;
    let mut client_targets = ClientTargetSessions::default();
    let attach = r#"{ "id": 11, "method": "Target.attachToTarget", "params": { "targetId": "target-1", "flatten": true } }"#;
    let action = ClientTextHandler::handle(
        &engine,
        &context(),
        &CdpSessionState::default(),
        &mut client_targets,
        attach,
        None,
    )?;
    assert!(matches!(action, ClientTextAction::Forward { .. }));

    BrowserTextObserver::observe_response(
        &mut client_targets,
        r#"{ "id": 11, "result": { "sessionId": "session-1" } }"#,
    )?;

    assert!(client_targets.has_session("session-1"));
    Ok(())
}

#[test]
fn client_text_appends_denied_command_audit_jsonl() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"{ "rules": [{
          "id": "deny-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "deny",
          "reason": "script evaluation denied"
        }] }"#,
    )?;
    let audit_path = temp_audit_path("denied-command");
    let _cleanup_before = fs::remove_file(&audit_path);
    let recorder = CdpAuditRecorder::new(audit_path.clone(), RuntimeAuditConfig::default());
    let source =
        r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;
    let mut client_targets = ClientTargetSessions::default();

    let action = ClientTextHandler::handle(
        &engine,
        &context(),
        &CdpSessionState::default(),
        &mut client_targets,
        source,
        Some(&recorder),
    )?;

    assert!(matches!(action, ClientTextAction::Reply { .. }));
    let records = read_audit_records(&audit_path)?;
    let _cleanup_after = fs::remove_file(&audit_path);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].final_decision,
        Decision::Deny {
            reason: String::from("script evaluation denied"),
            rule_id: Some(String::from("deny-script-eval")),
        }
    );
    Ok(())
}

fn engine(policy: &str) -> Result<crate::server::CdpEngine, Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(policy)?;
    Ok(erebor_runtime_core::LocalEnforcementEngine::new(
        PolicySet::from_policies(vec![policy]),
    ))
}

fn temp_audit_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "erebor-cdp-{label}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}
