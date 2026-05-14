use erebor_runtime_core::{ApprovalProvider, AuditSink, LocalEnforcementEngine, RuntimeError};
use erebor_runtime_events::{
    ActorIdentity, EventId, RiskMetadata, RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use serde::Deserialize;
use serde_json::Value;

use crate::{classify_cdp_method, CdpError};

#[derive(Clone, Debug, PartialEq)]
pub struct CdpMessage {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

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

pub fn parse_cdp_message(source: &str) -> Result<CdpMessage, CdpError> {
    let raw: RawCdpMessage =
        serde_json::from_str(source).map_err(|error| CdpError::InvalidJson(error.to_string()))?;
    let method = raw.method.ok_or(CdpError::MissingMethod)?;

    Ok(CdpMessage {
        id: raw.id,
        method,
        params: raw.params.unwrap_or(Value::Null),
    })
}

pub fn enforce_cdp_message<E, A, S>(
    engine: &LocalEnforcementEngine<E, A, S>,
    context: &CdpSessionContext,
    message: &CdpMessage,
) -> Result<CdpEnforcementAction, CdpError>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: AuditSink,
{
    if !crate::is_governed_method(&message.method) {
        return Ok(CdpEnforcementAction::Forward);
    }

    let event = normalize_cdp_message(context, message)?;
    let outcome = engine
        .enforce(&event)
        .map_err(|error| CdpError::Enforcement(error.to_string()))?;

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

fn normalize_cdp_message(
    context: &CdpSessionContext,
    message: &CdpMessage,
) -> Result<RuntimeEvent, CdpError> {
    let classification = classify_cdp_method(&message.method)
        .ok_or_else(|| CdpError::UnsupportedMethod(message.method.clone()))?;
    let id = message.id.as_ref().ok_or(CdpError::MissingMessageId)?;
    let event_id = match id {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => return Err(CdpError::MissingMessageId),
    };

    Ok(RuntimeEvent {
        id: EventId::new(event_id),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: classification.surface,
        action: classification.action,
        target: target_from_params(&message.params),
        payload: message.params.clone(),
        risk: RiskMetadata {
            level: classification.risk_level,
            reasons: vec![format!("governed CDP method `{}`", message.method)],
        },
        timestamp: context.timestamp.clone(),
    })
}

fn target_from_params(params: &Value) -> Option<TargetRef> {
    params
        .get("url")
        .and_then(Value::as_str)
        .map(|url| TargetRef {
            label: None,
            uri: Some(url.to_owned()),
        })
}

#[derive(Debug, Deserialize)]
struct RawCdpMessage {
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
}

impl From<RuntimeError> for CdpError {
    fn from(error: RuntimeError) -> Self {
        Self::Enforcement(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_core::{ApprovalProvider, ApprovalRequest, ApprovalResponse};
    use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
    use erebor_runtime_policy::LocalPolicy;

    use super::{enforce_cdp_message, parse_cdp_message, CdpEnforcementAction, CdpSessionContext};

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
        let message = parse_cdp_message(r#"{ "id": 1, "method": "Browser.getVersion" }"#)?;

        let action = enforce_cdp_message(&engine, &context(), &message)?;

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
        let message = parse_cdp_message(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_message(&engine, &context(), &message)?;

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
        let message = parse_cdp_message(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = enforce_cdp_message(&engine, &context(), &message)?;

        assert_eq!(
            action,
            CdpEnforcementAction::AwaitApproval {
                reason: String::from("script evaluation requires approval")
            }
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
