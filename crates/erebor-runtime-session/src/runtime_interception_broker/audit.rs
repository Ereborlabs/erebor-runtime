use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::{FilteredAuditSink, JsonlAuditSink};
use erebor_runtime_core::{
    AuditRecord, AuditSink, RuntimeAuditConfig, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, EventId, ExecutionSurface, RiskLevel, RiskMetadata, RuntimeEvent,
    SessionId, TargetRef,
};
use erebor_runtime_ipc::v1::InterceptionRequest;
use erebor_runtime_policy::Decision;
use erebor_runtime_telemetry::warn;

/// Session-owned durable audit recorder for decisions made through the process
/// interception broker.
pub(crate) struct ProcessExecAuditRecorder {
    session_id: SessionId,
    actor: ActorIdentity,
    sink: FilteredAuditSink<JsonlAuditSink>,
    event_sequence: AtomicU64,
}

impl ProcessExecAuditRecorder {
    #[must_use]
    pub(crate) fn new(
        path: impl Into<PathBuf>,
        session_id: SessionId,
        actor: ActorIdentity,
        audit: RuntimeAuditConfig,
    ) -> Self {
        Self {
            session_id,
            actor,
            sink: FilteredAuditSink::new(JsonlAuditSink::new(path), audit),
            event_sequence: AtomicU64::new(0),
        }
    }

    pub(crate) fn record(
        &self,
        request: &InterceptionRequest,
        surface_decision: &SurfaceInterceptionDecision,
    ) {
        let event = self.event_for_request(request);
        let decision = self.decision_for_request(request, surface_decision);
        let record = AuditRecord {
            event: event.clone(),
            policy_decision: decision.clone(),
            final_decision: decision,
            context_pin: None,
        };
        if let Err(error) = self.sink.record(&record) {
            warn!(
                error;
                "terminal process interception audit record failed",
                session_id = %event.session_id.as_str(),
                event_id = %event.id.as_str()
            );
        }
    }

    fn event_for_request(&self, request: &InterceptionRequest) -> RuntimeEvent {
        let payload = request.process_exec.as_ref();
        let executable = payload
            .map(|operation| operation.executable.as_str())
            .filter(|executable| !executable.is_empty())
            .unwrap_or(&request.executable);
        let argv = payload
            .map(|operation| operation.argv.as_slice())
            .filter(|argv| !argv.is_empty())
            .unwrap_or(&request.argv);
        let handler_id = payload
            .map(|operation| operation.matched_handler_id.as_str())
            .filter(|handler_id| !handler_id.is_empty())
            .unwrap_or(&request.matched_handler_id);

        RuntimeEvent {
            id: self.next_event_id(),
            session_id: self.session_id.clone(),
            actor: self.actor.clone(),
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ProcessExec,
            target: Some(TargetRef {
                label: Some(executable.to_owned()),
                uri: None,
            }),
            payload: serde_json::json!({
                "kind": "process_interception",
                "operation": "process_exec",
                "request_id": request.request_id,
                "executable": executable,
                "command": argv,
                "argv_summary": argv.join(" "),
                "cwd": request.cwd,
                "pid": request.pid,
                "ppid": request.ppid,
                "handler_id": handler_id,
                "guard_timestamp": request.timestamp,
            }),
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("process_exec_interception")],
            },
            timestamp: Self::timestamp(),
        }
    }

    fn decision_for_request(
        &self,
        request: &InterceptionRequest,
        surface_decision: &SurfaceInterceptionDecision,
    ) -> Decision {
        let (decision, rule_id, reason, mediation) = surface_decision.clone().into_parts();
        let handler_id = request
            .process_exec
            .as_ref()
            .map(|operation| operation.matched_handler_id.as_str())
            .filter(|handler_id| !handler_id.is_empty())
            .unwrap_or(&request.matched_handler_id);
        let rule_id = Some(match decision {
            SessionInterceptionDecision::Mediate => {
                self.mediation_audit_rule_id(handler_id, &rule_id)
            }
            SessionInterceptionDecision::Allow
            | SessionInterceptionDecision::Deny
            | SessionInterceptionDecision::RequireApproval => rule_id,
        });

        match decision {
            SessionInterceptionDecision::Allow => Decision::Allow { rule_id },
            SessionInterceptionDecision::Deny => Decision::Deny { reason, rule_id },
            SessionInterceptionDecision::RequireApproval => Decision::RequireApproval {
                reason,
                rule_id,
                approval_id: None,
            },
            SessionInterceptionDecision::Mediate => Decision::Mediate {
                reason,
                rule_id,
                mediation: mediation.map(|mediation| {
                    let (kind, replacement_surface, endpoint, lease_id, print_line, keepalive) =
                        mediation.into_parts();
                    serde_json::json!({
                        "kind": kind,
                        "replacement_surface": replacement_surface,
                        "endpoint": endpoint,
                        "lease_id": lease_id,
                        "print_line": print_line,
                        "keepalive": keepalive,
                    })
                }),
            },
        }
    }

    fn mediation_audit_rule_id(&self, handler_id: &str, fallback_rule_id: &str) -> String {
        let identifier = if handler_id.is_empty() {
            fallback_rule_id
        } else {
            handler_id
        };
        format!("erebor-process-interception-{identifier}")
    }

    fn next_event_id(&self) -> EventId {
        let sequence = self.event_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        EventId::new(format!(
            "{}-process-exec-{sequence}",
            self.session_id.as_str()
        ))
    }

    fn timestamp() -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        format!("unix:{seconds}")
    }
}
