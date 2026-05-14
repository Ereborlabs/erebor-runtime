use erebor_runtime_core::{ApprovalProvider, AuditSink, LocalEnforcementEngine, RuntimeError};
use erebor_runtime_events::{ActorIdentity, EventId, RiskMetadata, RuntimeEvent, SessionId};
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use serde_json::{json, Value};

use crate::{classify_cdp_method, CdpCommand, CdpError, CdpEvent, CdpSessionState};

#[derive(Clone, Debug, PartialEq)]
pub struct CdpSessionContext {
    pub session_id: SessionId,
    pub actor: ActorIdentity,
    pub timestamp: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CdpEnforcementAction {
    Forward,
    Block { reason: String },
    AwaitApproval { reason: String },
}

pub fn enforce_cdp_command<E, A, S>(
    engine: &LocalEnforcementEngine<E, A, S>,
    context: &CdpSessionContext,
    command: &CdpCommand,
) -> Result<CdpEnforcementAction, CdpError>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: AuditSink,
{
    enforce_cdp_command_with_session_state(engine, context, command, &CdpSessionState::default())
}

pub fn enforce_cdp_command_with_session_state<E, A, S>(
    engine: &LocalEnforcementEngine<E, A, S>,
    context: &CdpSessionContext,
    command: &CdpCommand,
    session_state: &CdpSessionState,
) -> Result<CdpEnforcementAction, CdpError>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: AuditSink,
{
    if command.protocol_command().is_none() {
        return Ok(CdpEnforcementAction::Forward);
    }

    let event = normalize_cdp_command(context, command, session_state)?;
    let outcome = engine
        .enforce_with_deferred_approval(&event)
        .map_err(CdpError::enforcement)?;

    Ok(match outcome.policy_decision {
        Decision::RequireApproval { reason, .. } => CdpEnforcementAction::AwaitApproval { reason },
        _ => match outcome.final_decision {
            Decision::Allow { .. } => CdpEnforcementAction::Forward,
            Decision::Deny { reason, .. } => CdpEnforcementAction::Block { reason },
            Decision::RequireApproval { reason, .. } => {
                CdpEnforcementAction::AwaitApproval { reason }
            }
        },
    })
}

pub fn observe_cdp_event(
    context: &CdpSessionContext,
    event: &CdpEvent,
) -> Result<RuntimeEvent, CdpError> {
    normalize_cdp_event(context, event)
}

fn normalize_cdp_command(
    context: &CdpSessionContext,
    command: &CdpCommand,
    session_state: &CdpSessionState,
) -> Result<RuntimeEvent, CdpError> {
    let classification = classify_cdp_method(&command.method)
        .ok_or_else(|| CdpError::unsupported_method(command.method.clone()))?;
    let protocol_command = command
        .protocol_command()
        .ok_or_else(|| CdpError::unsupported_method(command.method.clone()))?;
    let event_id = event_id_from_command(command)?;

    Ok(RuntimeEvent {
        id: EventId::new(event_id),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: classification.surface,
        action: classification.action,
        target: session_state.target_for_command(protocol_command),
        payload: command_payload(
            command,
            session_state.command_page_payload(protocol_command),
        )?,
        risk: RiskMetadata {
            level: classification.risk_level,
            reasons: vec![format!("governed CDP method `{}`", command.method)],
        },
        timestamp: context.timestamp.clone(),
    })
}

fn normalize_cdp_event(
    context: &CdpSessionContext,
    event: &CdpEvent,
) -> Result<RuntimeEvent, CdpError> {
    let classification = classify_cdp_method(event.method())
        .ok_or_else(|| CdpError::unsupported_method(event.method()))?;

    Ok(RuntimeEvent {
        id: EventId::new(event.event_id()),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: classification.surface,
        action: classification.action,
        target: event.target(),
        payload: event_payload(event),
        risk: RiskMetadata {
            level: classification.risk_level,
            reasons: vec![format!("inspected CDP method `{}`", event.method())],
        },
        timestamp: context.timestamp.clone(),
    })
}

fn event_id_from_command(command: &CdpCommand) -> Result<String, CdpError> {
    Ok(command.id.to_string())
}

fn command_payload(command: &CdpCommand, page_context: Value) -> Result<Value, CdpError> {
    let params = command
        .params()
        .ok_or_else(|| CdpError::unsupported_method(command.method.clone()))?;

    Ok(json!({
        "kind": "command",
        "method": command.method,
        "message_id": command.id,
        "page": page_context,
        "params": params,
    }))
}

fn event_payload(event: &CdpEvent) -> Value {
    json!({
        "kind": "event",
        "method": event.method(),
        "event_id": event.event_id(),
        "params": event.params(),
    })
}

impl From<RuntimeError> for CdpError {
    fn from(error: RuntimeError) -> Self {
        Self::enforcement(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use erebor_runtime_core::{ApprovalProvider, ApprovalRequest, ApprovalResponse};
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, ExecutionSurface, SessionId,
    };
    use erebor_runtime_policy::{Decision, LocalPolicy};
    use serde_json::json;

    use super::{
        enforce_cdp_command, enforce_cdp_command_with_session_state, observe_cdp_event,
        CdpEnforcementAction, CdpSessionContext,
    };
    use crate::{decode_cdp_command, decode_cdp_event, CdpSessionState};

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
    fn forwards_ungoverned_messages() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
        let command = decode_cdp_command(r#"{ "id": 1, "method": "Browser.getVersion" }"#)?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;

        assert_eq!(action, CdpEnforcementAction::Forward);
        Ok(())
    }

    #[test]
    fn blocks_denied_governed_messages() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
        let command = decode_cdp_command(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;

        assert_eq!(
            action,
            CdpEnforcementAction::Block {
                reason: String::from("script evaluation denied")
            }
        );
        Ok(())
    }

    #[test]
    fn pauses_approval_required_governed_messages() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "approve-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "require_approval",
                  "reason": "script evaluation requires approval"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
            policy,
            ApproveAll,
            erebor_runtime_core::NoopAuditSink,
        );
        let command = decode_cdp_command(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;

        assert_eq!(
            action,
            CdpEnforcementAction::AwaitApproval {
                reason: String::from("script evaluation requires approval")
            }
        );
        Ok(())
    }

    #[test]
    fn script_eval_policy_can_match_active_page_context() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-email-send",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval",
                    "target_contains": "mail.example.test"
                  },
                  "decision": "deny",
                  "reason": "email send is not allowed from this page"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
        let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
        let navigate = decode_cdp_command(
            r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
        )?;
        state.record_forwarded_command(
            navigate
                .protocol_command()
                .ok_or_else(|| std::io::Error::other("missing navigate command"))?,
        );
        let send = decode_cdp_command(
            r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
        )?;

        let action = enforce_cdp_command_with_session_state(&engine, &context(), &send, &state)?;

        assert_eq!(
            action,
            CdpEnforcementAction::Block {
                reason: String::from("email send is not allowed from this page")
            }
        );
        Ok(())
    }

    #[test]
    fn audits_forwarded_governed_navigation_with_full_record_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sink = RecordingAuditSink::default();
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "allow-example-navigation",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_navigate",
                    "target_contains": "example.com"
                  },
                  "decision": "allow"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
            policy,
            ApproveAll,
            sink.clone(),
        );
        let command = decode_cdp_command(
            r#"{ "id": 3, "method": "Page.navigate", "params": { "url": "https://example.com/" } }"#,
        )?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;
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
                "page": {
                    "active_page": null,
                    "command_page": null,
                    "pages": []
                },
                "params": {
                    "url": "https://example.com/"
                }
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
    fn audits_denied_governed_messages_with_source_method() -> Result<(), Box<dyn std::error::Error>>
    {
        let sink = RecordingAuditSink::default();
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
            policy,
            ApproveAll,
            sink.clone(),
        );
        let command = decode_cdp_command(
            r#"{ "id": 9, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;
        let records = sink.records();

        assert_eq!(
            action,
            CdpEnforcementAction::Block {
                reason: String::from("script evaluation denied")
            }
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].event.payload,
            json!({
                "kind": "command",
                "method": "Runtime.evaluate",
                "message_id": 9,
                "page": {
                    "active_page": null,
                    "command_page": null,
                    "pages": []
                },
                "params": {
                    "expression": "1 + 1"
                }
            })
        );
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
            r#"
            {
              "rules": [
                {
                  "id": "approve-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "require_approval",
                  "reason": "script evaluation requires approval"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
            policy,
            ApproveAll,
            sink.clone(),
        );
        let command = decode_cdp_command(
            r#"{ "id": 10, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_command(&engine, &context(), &command)?;
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

    #[test]
    fn observes_fetch_request_paused_context() -> Result<(), Box<dyn std::error::Error>> {
        let event = decode_cdp_event(
            r#"
            {
              "method": "Fetch.requestPaused",
              "params": {
                "requestId": "fetch-1",
                "request": {
                  "url": "https://example.com/sensitive",
                  "method": "GET",
                  "headers": {},
                  "initialPriority": "Low",
                  "referrerPolicy": "no-referrer"
                },
                "frameId": "frame-1",
                "resourceType": "Document"
              }
            }
            "#,
        )?
        .ok_or_else(|| std::io::Error::other("missing event"))?;

        let runtime_event = observe_cdp_event(&context(), &event)?;

        assert_eq!(runtime_event.id.as_str(), "fetch-1");
        assert_eq!(
            runtime_event.target.and_then(|target| target.uri),
            Some(String::from("https://example.com/sensitive"))
        );
        Ok(())
    }

    #[test]
    fn observes_network_context_without_command_id() -> Result<(), Box<dyn std::error::Error>> {
        let event = decode_cdp_event(
            r#"
            {
              "method": "Network.requestWillBeSent",
              "params": {
                "requestId": "network-1",
                "loaderId": "loader-1",
                "documentURL": "https://example.com/",
                "request": {
                  "url": "https://example.com/",
                  "method": "GET",
                  "headers": {},
                  "initialPriority": "Low",
                  "referrerPolicy": "no-referrer"
                },
                "timestamp": 1.0,
                "wallTime": 1.0,
                "initiator": {
                  "type": "other"
                },
                "redirectHasExtraInfo": false
              }
            }
            "#,
        )?
        .ok_or_else(|| std::io::Error::other("missing event"))?;

        let runtime_event = observe_cdp_event(&context(), &event)?;

        assert_eq!(runtime_event.id.as_str(), "network-1");
        assert_eq!(
            runtime_event.risk.reasons,
            vec![String::from(
                "inspected CDP method `Network.requestWillBeSent`"
            )]
        );
        Ok(())
    }

    #[derive(Clone, Debug)]
    struct ApproveAll;

    impl ApprovalProvider for ApproveAll {
        fn request_approval(
            &self,
            _request: &ApprovalRequest,
        ) -> Result<ApprovalResponse, erebor_runtime_core::ApprovalError> {
            Ok(ApprovalResponse::Approved)
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingAuditSink {
        records: Rc<RefCell<Vec<erebor_runtime_core::AuditRecord>>>,
    }

    impl RecordingAuditSink {
        fn records(&self) -> Vec<erebor_runtime_core::AuditRecord> {
            self.records.borrow().clone()
        }
    }

    impl erebor_runtime_core::AuditSink for RecordingAuditSink {
        fn record(
            &self,
            record: &erebor_runtime_core::AuditRecord,
        ) -> Result<(), erebor_runtime_core::AuditError> {
            self.records.borrow_mut().push(record.clone());
            Ok(())
        }
    }
}
