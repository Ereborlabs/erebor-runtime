use erebor_runtime_context::{ContextPin, PinnedContext};
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_events::RuntimeEvent;
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};

use crate::error::PolicySnafu;
use crate::RuntimeError;

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

#[derive(Clone, Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ApprovalError {
    #[snafu(display("approval provider unavailable: {reason}"))]
    ProviderUnavailable {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for ApprovalError {
    fn status_code(&self) -> StatusCode {
        StatusCode::Unavailable
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event: RuntimeEvent,
    pub policy_decision: Decision,
    pub final_decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_pin: Option<ContextPin>,
}

impl AuditRecord {
    #[must_use]
    pub fn from_outcome(outcome: &EnforcementOutcome) -> Self {
        Self {
            event: outcome.event.clone(),
            policy_decision: outcome.policy_decision.clone(),
            final_decision: outcome.final_decision.clone(),
            context_pin: outcome.context_pin.clone(),
        }
    }
}

pub trait AuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// An audit sink that confirms one record's durable local acceptance before returning.
pub trait DurableAuditSink: AuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum AuditError {
    #[snafu(display("audit sink unavailable: {reason}"))]
    SinkUnavailable {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for AuditError {
    fn status_code(&self) -> StatusCode {
        StatusCode::Unavailable
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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
        self.enforce_with_mode(event, ApprovalMode::ResolveImmediately)
    }

    pub fn enforce_with_deferred_approval(
        &self,
        event: &RuntimeEvent,
    ) -> Result<EnforcementOutcome, RuntimeError> {
        self.enforce_with_mode(event, ApprovalMode::Defer)
    }

    pub fn record_audit_record(&self, record: &AuditRecord) -> Option<String> {
        self.audit_sink
            .record(record)
            .err()
            .map(|error| error.to_string())
    }

    fn enforce_with_mode(
        &self,
        event: &RuntimeEvent,
        approval_mode: ApprovalMode,
    ) -> Result<EnforcementOutcome, RuntimeError> {
        let mut outcome = self.outcome(event, approval_mode, None)?;

        let audit_record = AuditRecord::from_outcome(&outcome);
        if let Err(error) = self.audit_sink.record(&audit_record) {
            outcome.audit_error = Some(error.to_string());
        }

        Ok(outcome)
    }

    fn outcome(
        &self,
        event: &RuntimeEvent,
        approval_mode: ApprovalMode,
        context_pin: Option<ContextPin>,
    ) -> Result<EnforcementOutcome, RuntimeError> {
        let policy_decision = self.evaluator.evaluate(event).context(PolicySnafu)?;
        let final_decision = self.resolve_decision(event, &policy_decision, approval_mode);
        Ok(EnforcementOutcome {
            event: event.clone(),
            policy_decision,
            final_decision,
            context_pin,
            audit_error: None,
        })
    }

    fn resolve_decision(
        &self,
        event: &RuntimeEvent,
        decision: &Decision,
        approval_mode: ApprovalMode,
    ) -> Decision {
        match decision {
            Decision::Allow { .. } | Decision::Deny { .. } | Decision::Mediate { .. } => {
                decision.clone()
            }
            Decision::RequireApproval {
                reason,
                rule_id,
                approval_id,
            } => match approval_mode {
                ApprovalMode::Defer => decision.clone(),
                ApprovalMode::ResolveImmediately => {
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
                        | Err(ApprovalError::ProviderUnavailable { reason, .. }) => {
                            Decision::Deny {
                                reason,
                                rule_id: rule_id.clone(),
                            }
                        }
                    }
                }
            },
        }
    }
}

impl<E, A, S> LocalEnforcementEngine<E, A, S>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: DurableAuditSink,
{
    /// Enforce from a repository-validated immutable context pin and fail closed on audit loss.
    pub fn enforce_with_context(
        &self,
        event: &RuntimeEvent,
        pinned_context: &PinnedContext,
    ) -> Result<EnforcementOutcome, RuntimeError> {
        if event.session_id.as_str() != pinned_context.session_id() {
            return crate::error::ContextSessionMismatchSnafu {
                event_session_id: event.session_id.as_str().to_owned(),
                pin_session_id: pinned_context.session_id().to_owned(),
            }
            .fail();
        }
        let outcome = self.outcome(
            event,
            ApprovalMode::ResolveImmediately,
            Some(pinned_context.pin().clone()),
        )?;
        let audit_record = AuditRecord::from_outcome(&outcome);
        self.audit_sink
            .record_durable(&audit_record)
            .context(crate::error::DurableAuditSnafu)?;
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalMode {
    ResolveImmediately,
    Defer,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnforcementOutcome {
    pub event: RuntimeEvent,
    pub policy_decision: Decision,
    pub final_decision: Decision,
    pub context_pin: Option<ContextPin>,
    pub audit_error: Option<String>,
}
