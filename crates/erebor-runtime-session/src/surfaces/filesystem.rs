use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::{FilteredAuditSink, JsonlAuditSink};
use erebor_runtime_core::{
    AuditRecord, AuditSink, FileInterceptionOperationKind, FileInterceptionRequest,
    FileOperationSurfaceHandler, RuntimeAuditConfig, SurfaceInterceptionDecision,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, EventId, ExecutionSurface, RiskLevel, RiskMetadata, RuntimeEvent,
    SessionId, TargetRef,
};
use erebor_runtime_policy::{Decision, PolicyEvaluator, PolicySet};
use erebor_runtime_telemetry::warn;

mod mediation;
mod path;

use crate::SessionPlanContext;
use mediation::mediation_decision;
use path::normalize_request_path;

pub struct FilesystemFileOperationHandler {
    policy_set: PolicySet,
    context: FilesystemSessionContext,
    audit: Option<FilesystemAuditRecorder>,
    event_sequence: AtomicU64,
}

impl FilesystemFileOperationHandler {
    #[must_use]
    pub fn new(policy_set: PolicySet, context: FilesystemSessionContext) -> Self {
        Self {
            policy_set,
            context,
            audit: None,
            event_sequence: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn with_audit_jsonl(mut self, path: impl Into<PathBuf>, audit: RuntimeAuditConfig) -> Self {
        self.audit = Some(FilesystemAuditRecorder::new(path, audit));
        self
    }

    fn decide(&self, request: &FileInterceptionRequest<'_>) -> SurfaceInterceptionDecision {
        let event = self.event_for_request(request);
        let policy_decision = match self.policy_set.evaluate(&event) {
            Ok(decision) => decision,
            Err(error) => {
                return SurfaceInterceptionDecision::deny(
                    "filesystem-file-operation-policy-error",
                    error.to_string(),
                );
            }
        };
        let final_decision = policy_decision.clone();
        self.record_audit(&event, &policy_decision, &final_decision);
        surface_decision(policy_decision)
    }

    fn event_for_request(&self, request: &FileInterceptionRequest<'_>) -> RuntimeEvent {
        let normalized_path = normalize_request_path(request.cwd(), request.path());
        let resolved_identity = request
            .resolved_identity()
            .map(|identity| {
                serde_json::json!({
                    "device": identity.device(),
                    "inode": identity.inode(),
                })
            })
            .unwrap_or(serde_json::Value::Null);
        RuntimeEvent {
            id: self.next_event_id(request.operation()),
            session_id: self.context.session_id.clone(),
            actor: self.context.actor.clone(),
            surface: ExecutionSurface::Filesystem,
            action: action_for_operation(request.operation()),
            target: Some(TargetRef {
                label: Some(normalized_path.clone()),
                uri: normalized_path
                    .starts_with('/')
                    .then(|| format!("file://{normalized_path}")),
            }),
            payload: serde_json::json!({
                "kind": "filesystem_file_operation",
                "operation": request.operation().as_str(),
                "path": request.path(),
                "normalized_path": normalized_path,
                "cwd": request.cwd(),
                "pid": request.pid(),
                "ppid": request.ppid(),
                "resolved_identity": resolved_identity,
            }),
            risk: risk_for_operation(request.operation()),
            timestamp: timestamp(),
        }
    }

    fn next_event_id(&self, operation: FileInterceptionOperationKind) -> EventId {
        let sequence = self.event_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        EventId::new(format!(
            "{}-{}-{}",
            self.context.session_id.as_str(),
            operation.as_str(),
            sequence
        ))
    }

    fn record_audit(
        &self,
        event: &RuntimeEvent,
        policy_decision: &Decision,
        final_decision: &Decision,
    ) {
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let record = AuditRecord {
            event: event.clone(),
            policy_decision: policy_decision.clone(),
            final_decision: final_decision.clone(),
        };
        if let Err(error) = audit.record(&record) {
            warn!(
                error;
                "filesystem surface audit record failed",
                session_id = %event.session_id.as_str(),
                event_id = %event.id.as_str()
            );
        }
    }
}

impl FileOperationSurfaceHandler for FilesystemFileOperationHandler {
    fn surface(&self) -> &str {
        "filesystem"
    }

    fn decide_file_operation(
        &self,
        request: &FileInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        self.decide(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemSessionContext {
    session_id: SessionId,
    actor: ActorIdentity,
}

impl FilesystemSessionContext {
    #[must_use]
    pub fn new(session_id: SessionId, actor: ActorIdentity) -> Self {
        Self { session_id, actor }
    }

    pub(crate) fn from_plan(plan: &impl SessionPlanContext) -> Self {
        Self {
            session_id: plan.session_id().clone(),
            actor: ActorIdentity {
                id: plan.actor().id.clone(),
                kind: plan.actor().kind.clone(),
            },
        }
    }
}

struct FilesystemAuditRecorder {
    sink: FilteredAuditSink<JsonlAuditSink>,
}

impl FilesystemAuditRecorder {
    fn new(path: impl Into<PathBuf>, audit: RuntimeAuditConfig) -> Self {
        Self {
            sink: FilteredAuditSink::new(JsonlAuditSink::new(path), audit),
        }
    }

    fn record(&self, record: &AuditRecord) -> Result<(), erebor_runtime_core::AuditError> {
        self.sink.record(record)
    }
}

fn surface_decision(decision: Decision) -> SurfaceInterceptionDecision {
    match decision {
        Decision::Allow { rule_id } => SurfaceInterceptionDecision::allow(
            rule_id.unwrap_or_else(|| String::from("filesystem-file-operation-default-allow")),
            "file operation allowed by filesystem policy",
        ),
        Decision::Deny { reason, rule_id } => SurfaceInterceptionDecision::deny(
            rule_id.unwrap_or_else(|| String::from("filesystem-file-operation-deny")),
            reason,
        ),
        Decision::RequireApproval {
            reason, rule_id, ..
        } => SurfaceInterceptionDecision::require_approval(
            rule_id.unwrap_or_else(|| String::from("filesystem-file-operation-require-approval")),
            reason,
        ),
        Decision::Mediate {
            reason,
            rule_id,
            mediation,
        } => match mediation.and_then(|value| mediation_decision(&value).ok()) {
            Some(mediation) => SurfaceInterceptionDecision::mediate(
                rule_id.unwrap_or_else(|| String::from("filesystem-file-operation-mediate")),
                reason,
                mediation,
            ),
            None => SurfaceInterceptionDecision::deny(
                rule_id
                    .unwrap_or_else(|| String::from("filesystem-file-operation-invalid-mediation")),
                "filesystem mediation metadata is missing or invalid",
            ),
        },
    }
}

fn action_for_operation(operation: FileInterceptionOperationKind) -> ActionKind {
    match operation {
        FileInterceptionOperationKind::Open => ActionKind::FileOpen,
        FileInterceptionOperationKind::Read => ActionKind::FileRead,
        FileInterceptionOperationKind::Mutation => ActionKind::FileMutation,
    }
}

fn risk_for_operation(operation: FileInterceptionOperationKind) -> RiskMetadata {
    let level = match operation {
        FileInterceptionOperationKind::Open | FileInterceptionOperationKind::Read => RiskLevel::Low,
        FileInterceptionOperationKind::Mutation => RiskLevel::Medium,
    };
    RiskMetadata {
        level,
        reasons: vec![operation.as_str().to_owned()],
    }
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests;
