use std::{
    cell::{Cell, RefCell},
    error::Error,
    rc::Rc,
};

use erebor_runtime_context::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextPinSelection, ContextRepository, PinnedContext, ScopeRef, Snapshot, TreeEdit,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_policy::{Decision, LocalPolicy};
use snafu::{Location, ResultExt};

use crate::error::PolicySnafu;
use crate::{
    ApprovalError, ApprovalProvider, ApprovalRequest, ApprovalResponse, AuditError, AuditRecord,
    AuditSink, DurableAuditSink, LocalEnforcementEngine, RuntimeError,
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
            response: Err(ApprovalError::ProviderUnavailable {
                reason: String::from("socket closed"),
                location: Location::default(),
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

#[test]
fn validated_context_pin_reaches_policy_once_and_is_durably_audited() -> Result<(), Box<dyn Error>>
{
    let policy = CountingAllowPolicy::default();
    let sink = RecordingAuditSink::default();
    let engine = LocalEnforcementEngine::with_hooks(
        policy.clone(),
        StaticApprovalProvider {
            response: Ok(ApprovalResponse::Approved),
        },
        sink.clone(),
    );
    let pinned = pinned_context("session-1")?;

    let outcome = engine.enforce_with_context(&event(), &pinned)?;

    assert_eq!(policy.count(), 1);
    assert_eq!(outcome.context_pin.as_ref(), Some(pinned.pin()));
    assert_eq!(sink.records().len(), 1);
    assert_eq!(sink.records()[0].context_pin.as_ref(), Some(pinned.pin()));
    Ok(())
}

#[test]
fn durable_context_audit_failure_returns_no_actionable_outcome() -> Result<(), Box<dyn Error>> {
    let policy = CountingAllowPolicy::default();
    let engine = LocalEnforcementEngine::with_hooks(
        policy.clone(),
        StaticApprovalProvider {
            response: Ok(ApprovalResponse::Approved),
        },
        FailingDurableAuditSink,
    );
    let pinned = pinned_context("session-1")?;

    assert!(matches!(
        engine.enforce_with_context(&event(), &pinned),
        Err(RuntimeError::DurableAudit { .. })
    ));
    assert_eq!(policy.count(), 1);
    Ok(())
}

#[test]
fn context_pin_from_another_session_is_rejected_before_policy_evaluation(
) -> Result<(), Box<dyn Error>> {
    let policy = CountingAllowPolicy::default();
    let engine = LocalEnforcementEngine::with_hooks(
        policy.clone(),
        StaticApprovalProvider {
            response: Ok(ApprovalResponse::Approved),
        },
        RecordingAuditSink::default(),
    );
    let pinned = pinned_context("other-session")?;

    assert!(matches!(
        engine.enforce_with_context(&event(), &pinned),
        Err(RuntimeError::ContextSessionMismatch { .. })
    ));
    assert_eq!(policy.count(), 0);
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
    .context(PolicySnafu)
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

impl DurableAuditSink for RecordingAuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.record(record)
    }
}

#[derive(Clone, Debug)]
struct FailingAuditSink;

impl AuditSink for FailingAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::SinkUnavailable {
            reason: String::from("disk full"),
            location: Location::default(),
        })
    }
}

struct FailingDurableAuditSink;

impl AuditSink for FailingDurableAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        FailingAuditSink.record(record)
    }
}

impl DurableAuditSink for FailingDurableAuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.record(record)
    }
}

#[derive(Clone, Default)]
struct CountingAllowPolicy {
    evaluations: Rc<Cell<usize>>,
}

impl CountingAllowPolicy {
    fn count(&self) -> usize {
        self.evaluations.get()
    }
}

impl erebor_runtime_policy::PolicyEvaluator for CountingAllowPolicy {
    fn evaluate(&self, _event: &RuntimeEvent) -> erebor_runtime_policy::Result<Decision> {
        self.evaluations.set(self.evaluations.get() + 1);
        Ok(Decision::Allow { rule_id: None })
    }
}

fn pinned_context(session_id: &str) -> Result<PinnedContext, Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let repository =
        ContextRepository::init(temp.path().join("context"), FixedMetadataSource::new()?)?;
    repository.initialize_root(
        session_id,
        Snapshot::new(vec![TreeEdit::blob("result", b"selected context")?])?,
        "Initialize context",
    )?;
    Ok(repository.pin_scope_head(
        ScopeRef::root(session_id)?,
        &[ContextPinSelection::blob("result")],
    )?)
}

#[derive(Clone)]
struct FixedMetadataSource {
    metadata: CommitMetadata,
}

impl FixedMetadataSource {
    fn new() -> Result<Self, Box<dyn Error>> {
        let time = CommitTime::new(1_700_000_000, 0)?;
        let signature = CommitSignature::new("Erebor Runtime", "runtime@erebor.dev", time)?;
        Ok(Self {
            metadata: CommitMetadata::new(signature.clone(), signature),
        })
    }
}

impl CommitMetadataSource for FixedMetadataSource {
    fn metadata(&self) -> Result<CommitMetadata, CommitMetadataSourceError> {
        Ok(self.metadata.clone())
    }
}
