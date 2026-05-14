//! Core enforcement loop contracts for erebor-runtime.

use erebor_runtime_events::RuntimeEvent;
use erebor_runtime_policy::{Decision, PolicyError, PolicyEvaluator};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LocalEnforcementEngine<E, A = DenyApprovalProvider, S = NoopAuditSink> {
    evaluator: E,
    approval_provider: A,
    audit_sink: S,
}

impl<E> LocalEnforcementEngine<E, DenyApprovalProvider, NoopAuditSink> {
    #[must_use]
    pub fn new(evaluator: E) -> Self {
        Self {
            evaluator,
            approval_provider: DenyApprovalProvider,
            audit_sink: NoopAuditSink,
        }
    }
}

impl<E, A, S> LocalEnforcementEngine<E, A, S> {
    #[must_use]
    pub fn with_hooks(evaluator: E, approval_provider: A, audit_sink: S) -> Self {
        Self {
            evaluator,
            approval_provider,
            audit_sink,
        }
    }
}

impl<E, A, S> LocalEnforcementEngine<E, A, S>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: AuditSink,
{
    pub fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, RuntimeError> {
        self.enforce(event).map(|outcome| outcome.final_decision)
    }

    pub fn enforce(&self, event: &RuntimeEvent) -> Result<EnforcementOutcome, RuntimeError> {
        let policy_decision = self.evaluator.evaluate(event)?;
        let final_decision = self.resolve_decision(event, &policy_decision);
        let mut outcome = EnforcementOutcome {
            event: event.clone(),
            policy_decision,
            final_decision,
            audit_error: None,
        };

        let audit_record = AuditRecord::from_outcome(&outcome);
        if let Err(error) = self.audit_sink.record(&audit_record) {
            outcome.audit_error = Some(error.to_string());
        }

        Ok(outcome)
    }

    fn resolve_decision(&self, event: &RuntimeEvent, decision: &Decision) -> Decision {
        match decision {
            Decision::Allow { .. } | Decision::Deny { .. } => decision.clone(),
            Decision::RequireApproval {
                reason,
                rule_id,
                approval_id,
            } => {
                let request = ApprovalRequest {
                    event: event.clone(),
                    reason: reason.clone(),
                    rule_id: rule_id.clone(),
                    approval_id: approval_id.clone(),
                };

                match self.approval_provider.request_approval(&request) {
                    Ok(ApprovalResponse::Approved) => Decision::Allow {
                        rule_id: rule_id.clone(),
                    },
                    Ok(ApprovalResponse::Denied { reason })
                    | Ok(ApprovalResponse::TimedOut { reason })
                    | Ok(ApprovalResponse::Unavailable { reason })
                    | Err(ApprovalError::Unavailable { reason }) => Decision::Deny {
                        reason,
                        rule_id: rule_id.clone(),
                    },
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnforcementOutcome {
    pub event: RuntimeEvent,
    pub policy_decision: Decision,
    pub final_decision: Decision,
    pub audit_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalRequest {
    pub event: RuntimeEvent,
    pub reason: String,
    pub rule_id: Option<String>,
    pub approval_id: Option<String>,
}

pub trait ApprovalProvider {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ApprovalResponse, ApprovalError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DenyApprovalProvider;

impl ApprovalProvider for DenyApprovalProvider {
    fn request_approval(
        &self,
        _request: &ApprovalRequest,
    ) -> Result<ApprovalResponse, ApprovalError> {
        Ok(ApprovalResponse::Unavailable {
            reason: String::from("approval provider unavailable"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalResponse {
    Approved,
    Denied { reason: String },
    TimedOut { reason: String },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApprovalError {
    #[error("approval provider unavailable: {reason}")]
    Unavailable { reason: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuditRecord {
    pub event: RuntimeEvent,
    pub policy_decision: Decision,
    pub final_decision: Decision,
}

impl AuditRecord {
    #[must_use]
    pub fn from_outcome(outcome: &EnforcementOutcome) -> Self {
        Self {
            event: outcome.event.clone(),
            policy_decision: outcome.policy_decision.clone(),
            final_decision: outcome.final_decision.clone(),
        }
    }
}

pub trait AuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuditError {
    #[error("audit sink unavailable: {reason}")]
    Unavailable { reason: String },
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
        RuntimeEvent, SessionId,
    };
    use erebor_runtime_policy::{Decision, LocalPolicy};

    use super::{
        ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError,
        AuditRecord, AuditSink, LocalEnforcementEngine, RuntimeError,
    };

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
            Decision::Deny {
                reason: String::from("approval provider unavailable"),
                rule_id: Some(String::from("approve-terminal-exec")),
            }
        );

        Ok(())
    }

    #[test]
    fn approved_action_becomes_allow_and_is_audited() -> Result<(), RuntimeError> {
        let sink = RecordingAuditSink::default();
        let engine = LocalEnforcementEngine::with_hooks(
            approval_policy()?,
            StaticApprovalProvider {
                response: Ok(ApprovalResponse::Approved),
            },
            sink.clone(),
        );

        let outcome = engine.enforce(&event())?;

        assert_eq!(
            outcome.final_decision,
            Decision::Allow {
                rule_id: Some(String::from("approve-terminal-exec")),
            }
        );
        assert_eq!(sink.records().len(), 1);
        assert_eq!(
            sink.records()[0].policy_decision,
            Decision::RequireApproval {
                reason: String::from("terminal execution requires approval"),
                rule_id: Some(String::from("approve-terminal-exec")),
                approval_id: None,
            }
        );

        Ok(())
    }

    #[test]
    fn denied_approval_fails_closed() -> Result<(), RuntimeError> {
        let engine = LocalEnforcementEngine::with_hooks(
            approval_policy()?,
            StaticApprovalProvider {
                response: Ok(ApprovalResponse::Denied {
                    reason: String::from("user denied"),
                }),
            },
            RecordingAuditSink::default(),
        );

        let outcome = engine.enforce(&event())?;

        assert_eq!(
            outcome.final_decision,
            Decision::Deny {
                reason: String::from("user denied"),
                rule_id: Some(String::from("approve-terminal-exec")),
            }
        );

        Ok(())
    }

    #[test]
    fn approval_backend_error_fails_closed() -> Result<(), RuntimeError> {
        let engine = LocalEnforcementEngine::with_hooks(
            approval_policy()?,
            StaticApprovalProvider {
                response: Err(ApprovalError::Unavailable {
                    reason: String::from("socket closed"),
                }),
            },
            RecordingAuditSink::default(),
        );

        let outcome = engine.enforce(&event())?;

        assert_eq!(
            outcome.final_decision,
            Decision::Deny {
                reason: String::from("socket closed"),
                rule_id: Some(String::from("approve-terminal-exec")),
            }
        );

        Ok(())
    }

    #[test]
    fn audit_failure_does_not_block_mvp_decision() -> Result<(), RuntimeError> {
        let engine = LocalEnforcementEngine::with_hooks(
            approval_policy()?,
            StaticApprovalProvider {
                response: Ok(ApprovalResponse::Approved),
            },
            FailingAuditSink,
        );

        let outcome = engine.enforce(&event())?;

        assert_eq!(
            outcome.final_decision,
            Decision::Allow {
                rule_id: Some(String::from("approve-terminal-exec")),
            }
        );
        assert_eq!(
            outcome.audit_error,
            Some(String::from("audit sink unavailable: disk full"))
        );

        Ok(())
    }

    fn approval_policy() -> Result<LocalPolicy, RuntimeError> {
        Ok(LocalPolicy::from_json_str(
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
        )?)
    }

    #[derive(Clone, Debug)]
    struct StaticApprovalProvider {
        response: Result<ApprovalResponse, ApprovalError>,
    }

    impl ApprovalProvider for StaticApprovalProvider {
        fn request_approval(
            &self,
            _request: &ApprovalRequest,
        ) -> Result<ApprovalResponse, ApprovalError> {
            self.response.clone()
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingAuditSink {
        records: std::rc::Rc<RefCell<Vec<AuditRecord>>>,
    }

    impl RecordingAuditSink {
        fn records(&self) -> Vec<AuditRecord> {
            self.records.borrow().clone()
        }
    }

    impl AuditSink for RecordingAuditSink {
        fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.records.borrow_mut().push(record.clone());
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct FailingAuditSink;

    impl AuditSink for FailingAuditSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Unavailable {
                reason: String::from("disk full"),
            })
        }
    }
}
