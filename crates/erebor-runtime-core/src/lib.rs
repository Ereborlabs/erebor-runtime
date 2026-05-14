//! Core enforcement loop contracts for erebor-runtime.

use erebor_runtime_events::RuntimeEvent;
use erebor_runtime_policy::{Decision, PolicyError, PolicyEvaluator};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LocalEnforcementEngine<E> {
    evaluator: E,
}

impl<E> LocalEnforcementEngine<E> {
    #[must_use]
    pub fn new(evaluator: E) -> Self {
        Self { evaluator }
    }
}

impl<E> LocalEnforcementEngine<E>
where
    E: PolicyEvaluator,
{
    pub fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, RuntimeError> {
        self.evaluator.evaluate(event).map_err(RuntimeError::from)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
}

#[cfg(test)]
mod tests {
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
        RuntimeEvent, SessionId,
    };
    use erebor_runtime_policy::{Decision, LocalPolicy};

    use super::{LocalEnforcementEngine, RuntimeError};

    fn event() -> RuntimeEvent {
        RuntimeEvent {
            id: EventId::new("evt-1"),
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ProcessExec,
            target: None,
            payload: serde_json::json!({ "command": "git commit" }),
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("commit changes")],
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        }
    }

    #[test]
    fn delegates_to_policy_evaluator() -> Result<(), RuntimeError> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "approve-terminal-exec",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "risk_at_least": "high"
                  },
                  "decision": "require_approval",
                  "reason": "terminal execution requires approval"
                }
              ]
            }
            "#,
        )?;
        let engine = LocalEnforcementEngine::new(policy);

        let decision = engine.evaluate(&event())?;

        assert_eq!(
            decision,
            Decision::RequireApproval {
                reason: String::from("terminal execution requires approval"),
                rule_id: Some(String::from("approve-terminal-exec")),
                approval_id: None,
            }
        );

        Ok(())
    }
}
