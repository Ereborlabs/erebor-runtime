use std::{cell::RefCell, rc::Rc};

use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_policy::{Decision, LocalPolicy};

use crate::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, LocalEnforcementEngine, RuntimeError,
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
    let policy = approval_policy()?;
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
fn deferred_approval_remains_pending_and_is_audited() -> Result<(), RuntimeError> {
    let sink = RecordingAuditSink::default();
    let engine = LocalEnforcementEngine::with_hooks(
        approval_policy()?,
        StaticApprovalProvider {
            response: Ok(ApprovalResponse::Approved),
        },
        sink.clone(),
    );

    let outcome = engine.enforce_with_deferred_approval(&event())?;

    assert_eq!(
        outcome.final_decision,
        Decision::RequireApproval {
            reason: String::from("terminal execution requires approval"),
            rule_id: Some(String::from("approve-terminal-exec")),
            approval_id: None,
        }
    );
    assert_eq!(sink.records().len(), 1);
    assert_eq!(
        sink.records()[0].final_decision,
        Decision::RequireApproval {
            reason: String::from("terminal execution requires approval"),
            rule_id: Some(String::from("approve-terminal-exec")),
            approval_id: None,
        }
    );

    Ok(())
}

#[test]
fn approval_backend_error_fails_closed() -> Result<(), RuntimeError> {
    let engine = LocalEnforcementEngine::with_hooks(
        approval_policy()?,
        StaticApprovalProvider {
            response: Err(ApprovalError::unavailable("socket closed")),
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
    LocalPolicy::from_json_str(
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
    )
    .map_err(RuntimeError::policy)
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
    records: Rc<RefCell<Vec<AuditRecord>>>,
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
        Err(AuditError::unavailable("disk full"))
    }
}
