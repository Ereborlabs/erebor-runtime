use erebor_runtime_core::{ApprovalProvider, AuditSink, LocalEnforcementEngine, RuntimeError};
use erebor_runtime_events::{ActorIdentity, EventId, RiskMetadata, RuntimeEvent, SessionId};
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use serde_json::Value;

use crate::{classify_cdp_method, CdpCommand, CdpError, CdpEvent, GovernedCdpCommand};

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
    if command.protocol_command().is_none() {
        return Ok(CdpEnforcementAction::Forward);
    }

    let event = normalize_cdp_command(context, command)?;
    let outcome = engine.enforce(&event).map_err(CdpError::enforcement)?;

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
) -> Result<RuntimeEvent, CdpError> {
    let classification = classify_cdp_method(&command.method)
        .ok_or_else(|| CdpError::unsupported_method(command.method.clone()))?;
    let event_id = event_id_from_command(command)?;

    Ok(RuntimeEvent {
        id: EventId::new(event_id),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: classification.surface,
        action: classification.action,
        target: command
            .protocol_command()
            .and_then(GovernedCdpCommand::target),
        payload: command.params.clone(),
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
    let classification = classify_cdp_method(&event.method)
        .ok_or_else(|| CdpError::unsupported_method(event.method.clone()))?;

    Ok(RuntimeEvent {
        id: EventId::new(event.protocol_event().event_id()),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: classification.surface,
        action: classification.action,
        target: event.protocol_event().target(),
        payload: event.params.clone(),
        risk: RiskMetadata {
            level: classification.risk_level,
            reasons: vec![format!("inspected CDP method `{}`", event.method)],
        },
        timestamp: context.timestamp.clone(),
    })
}

fn event_id_from_command(command: &CdpCommand) -> Result<String, CdpError> {
    if let Some(id) = command.id.as_ref() {
        return match id {
            Value::String(value) => Ok(value.clone()),
            Value::Number(value) => Ok(value.to_string()),
            _ => Err(CdpError::missing_message_id()),
        };
    }

    Err(CdpError::missing_message_id())
}

impl From<RuntimeError> for CdpError {
    fn from(error: RuntimeError) -> Self {
        Self::enforcement(error)
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_core::{ApprovalProvider, ApprovalRequest, ApprovalResponse};
    use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
    use erebor_runtime_policy::LocalPolicy;

    use super::{enforce_cdp_command, observe_cdp_event, CdpEnforcementAction, CdpSessionContext};
    use crate::{decode_cdp_command, decode_cdp_event};

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
}
