use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_audit::append_durable_audit_record;
use erebor_runtime_core::{
    AuditRecord, FileInterceptionOperationKind, FileInterceptionRequest,
    FileOperationSurfaceHandler, OutputEndpoints, ProcessExecInterceptionRequest,
    ProcessExecSurfaceHandler, SessionInterceptionDecision, SessionSpec,
    SurfaceInterceptionDecision,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_packages::PolicyPackageRevision;
use erebor_runtime_policy::{
    Decision, LayeredDecision, LayeredPolicySet, LocalPolicy, PolicyLayer, PolicySet,
};
use erebor_runtime_session::SessionInterceptionRouterFactory;
use erebor_runtime_session::{
    ChildContextDeliveryHandler, CodexAppServerService, CodexHookService, CodexHookSessionHandlers,
    ContextAgentControlHandler, ContextOperationAdmissionHandler, SessionManagerError,
};
use erebor_runtime_telemetry::warn;
use uuid::Uuid;

use crate::context_dag::SessionContextResolver;
use crate::local_store::DaemonLocalStore;

// The Linux controller moves the descriptor-held executable to this private
// path before the process guard observes Codex or its hook descendants.
const CODEX_LINUX_WORKLOAD_EXECUTABLE: &str = "/run/erebor/admitted-executable";

/// The session-bound policy route. It reconstructs every immutable policy
/// input named by the admitted `SessionSpec`; it never reads a mutable policy
/// path supplied by a client or workload.
pub(super) struct StoredPolicyInterceptionRouterFactory {
    local_store: Arc<DaemonLocalStore>,
    codex_hook_service: Arc<CodexHookService>,
    codex_app_server_service: Arc<CodexAppServerService>,
    context_resolver: Arc<SessionContextResolver>,
    child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
    agent_controls: Arc<dyn ContextAgentControlHandler>,
    operation_admissions: Arc<dyn ContextOperationAdmissionHandler>,
}

impl StoredPolicyInterceptionRouterFactory {
    pub(super) const fn new(
        local_store: Arc<DaemonLocalStore>,
        codex_hook_service: Arc<CodexHookService>,
        codex_app_server_service: Arc<CodexAppServerService>,
        context_resolver: Arc<SessionContextResolver>,
        child_deliveries: Arc<dyn ChildContextDeliveryHandler>,
        agent_controls: Arc<dyn ContextAgentControlHandler>,
        operation_admissions: Arc<dyn ContextOperationAdmissionHandler>,
    ) -> Self {
        Self {
            local_store,
            codex_hook_service,
            codex_app_server_service,
            context_resolver,
            child_deliveries,
            agent_controls,
            operation_admissions,
        }
    }
}

impl SessionInterceptionRouterFactory for StoredPolicyInterceptionRouterFactory {
    fn register(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<(), SessionManagerError> {
        let admission = self
            .local_store
            .validate_session_spec(spec)
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        if admission.package().adapter_id() != "codex-v1" {
            return Ok(());
        }
        let codex = self
            .local_store
            .resolve_codex_installation(
                spec.owner().uid(),
                admission.package_digest(),
                admission.installation_digest(),
                None,
            )
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        let registration = self
            .codex_hook_service
            .register_session(
                spec,
                self.codex_workload_executable(spec, output)?,
                codex.package().definition(),
                self.context_resolver
                    .resolve(spec)
                    .map_err(|error| self.invalid_error(spec, error.to_string()))?,
                CodexHookSessionHandlers::new(
                    Arc::clone(&self.child_deliveries),
                    Arc::clone(&self.operation_admissions),
                    Arc::clone(&self.agent_controls),
                ),
            )
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        if self.is_codex_app_server(spec, codex.package().definition()) {
            if let Err(error) = self
                .codex_app_server_service
                .register(registration.app_server_registration())
            {
                let _result = self
                    .codex_hook_service
                    .unregister(spec.session_id().as_str());
                return Err(self.invalid_error(spec, error.to_string()));
            }
        }
        Ok(())
    }

    fn cleanup(&self, spec: &SessionSpec) -> Result<(), SessionManagerError> {
        self.codex_hook_service
            .unregister(spec.session_id().as_str())
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        Ok(())
    }
}

impl StoredPolicyInterceptionRouterFactory {
    fn codex_workload_executable(
        &self,
        spec: &SessionSpec,
        output: &OutputEndpoints,
    ) -> Result<&'static Path, SessionManagerError> {
        output.prepared_executable().ok_or_else(|| {
            self.invalid_error(
                spec,
                "Codex session has no prepared executable guard identity",
            )
        })?;
        Ok(Path::new(CODEX_LINUX_WORKLOAD_EXECUTABLE))
    }

    fn is_codex_app_server(
        &self,
        spec: &SessionSpec,
        definition: &erebor_runtime_packages::CodexPackageDefinition,
    ) -> bool {
        if spec.tty() {
            return false;
        }
        let Some(executable) = spec.executable() else {
            return false;
        };
        let Some(entrypoint) = definition
            .entrypoint("codex-app-server")
            .filter(|entrypoint| entrypoint.app_server_stdio())
        else {
            return false;
        };
        let mut expected_command = vec![executable.requested_path().display().to_string()];
        expected_command.extend(entrypoint.argv_suffix().iter().cloned());
        spec.command() == expected_command
    }

    fn invalid_error(&self, spec: &SessionSpec, reason: impl Into<String>) -> SessionManagerError {
        SessionManagerError::InvalidRuntime {
            session_id: spec.session_id().as_str().to_owned(),
            reason: reason.into(),
            location: snafu::Location::default(),
        }
    }
}

struct StoredPolicyProcessExecHandler {
    session_id: SessionId,
    policy_set_digest: String,
    policies: std::result::Result<LayeredPolicySet, String>,
}

impl StoredPolicyProcessExecHandler {
    fn from_session(local_store: Arc<DaemonLocalStore>, spec: &SessionSpec) -> Self {
        let policies = local_store
            .policy_packages_for_session(spec)
            .and_then(Self::compile_layers)
            .map_err(|error| error.to_string());
        Self {
            session_id: spec.session_id().clone(),
            policy_set_digest: spec.policy_set().sha256().to_owned(),
            policies,
        }
    }

    fn compile_layers(revisions: Vec<PolicyPackageRevision>) -> crate::Result<LayeredPolicySet> {
        let layers = revisions
            .into_iter()
            .map(|revision| {
                let policies = revision
                    .rules()
                    .values()
                    .map(|source| {
                        let source = std::str::from_utf8(source).map_err(|error| {
                            crate::error::InvalidRequestSnafu {
                                reason: format!(
                                    "policy package `{}` has non-UTF-8 rule bytes: {error}",
                                    revision.manifest().name()
                                ),
                            }
                            .build()
                        })?;
                        LocalPolicy::from_json_str(source).map_err(|error| {
                            crate::error::InvalidRequestSnafu {
                                reason: format!(
                                    "policy package `{}` has an invalid rule: {error}",
                                    revision.manifest().name()
                                ),
                            }
                            .build()
                        })
                    })
                    .collect::<crate::Result<Vec<_>>>()?;
                Ok(PolicyLayer::mandatory(
                    revision.manifest().name(),
                    PolicySet::from_policies(policies),
                ))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        Ok(LayeredPolicySet::new(layers))
    }

    fn event(&self, request: &ProcessExecInterceptionRequest<'_>) -> RuntimeEvent {
        RuntimeEvent {
            id: EventId::new(format!("{}-process-exec", self.session_id.as_str())),
            session_id: self.session_id.clone(),
            actor: ActorIdentity {
                id: String::from("agent"),
                kind: ActorKind::Agent,
            },
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ProcessExec,
            target: Some(TargetRef {
                label: Some(request.executable().to_owned()),
                uri: None,
            }),
            payload: serde_json::json!({
                "command": request.argv(),
                "argv_summary": request.argv().join(" "),
                "handler_id": request.matched_handler_id(),
            }),
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("process_exec_interception")],
            },
            timestamp: String::from("session-runtime"),
        }
    }

    fn decision(&self, decision: LayeredDecision) -> SurfaceInterceptionDecision {
        match decision {
            LayeredDecision::Allow => SurfaceInterceptionDecision::allow(
                format!("policy-set-{}", self.policy_set_digest),
                "all mandatory immutable policy layers allowed the process execution",
            ),
            LayeredDecision::Deny { reason, rule_id } => SurfaceInterceptionDecision::deny(
                rule_id.unwrap_or_else(|| String::from("policy-deny-without-rule-id")),
                reason,
            ),
            LayeredDecision::RequireApproval {
                reason, rule_ids, ..
            } => SurfaceInterceptionDecision::require_approval(
                rule_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| String::from("policy-requires-approval")),
                reason,
            ),
            LayeredDecision::Mediate {
                reason, rule_ids, ..
            } => SurfaceInterceptionDecision::deny(
                rule_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| String::from("policy-requires-mediation")),
                format!(
                    "{reason}; generic-process-v1 has no admitted mediation owner, so the Linux guard denies the effect"
                ),
            ),
        }
    }
}

impl ProcessExecSurfaceHandler for StoredPolicyProcessExecHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        let policy = match &self.policies {
            Ok(policy) => policy,
            Err(reason) => {
                return SurfaceInterceptionDecision::deny(
                    "stored-policy-load-failed",
                    format!("admitted policy package cannot be evaluated: {reason}"),
                );
            }
        };
        match policy.evaluate(&self.event(request)) {
            Ok(decision) => self.decision(decision),
            Err(error) => SurfaceInterceptionDecision::deny(
                "stored-policy-evaluation-failed",
                format!("admitted policy evaluation failed closed: {error}"),
            ),
        }
    }
}

/// The filesystem policy owner for a Session admitted from immutable stored
/// packages. The guard asks this owner before the intercepted operation can
/// reach the filesystem surface.
pub(super) struct StoredPolicyFileOperationHandler {
    session_id: SessionId,
    policy_set_digest: String,
    policies: std::result::Result<LayeredPolicySet, String>,
    audit_path: PathBuf,
}

impl StoredPolicyFileOperationHandler {
    pub(super) fn from_session(local_store: Arc<DaemonLocalStore>, spec: &SessionSpec) -> Self {
        let policies = local_store
            .policy_packages_for_session(spec)
            .and_then(StoredPolicyProcessExecHandler::compile_layers)
            .map_err(|error| error.to_string());
        Self {
            session_id: spec.session_id().clone(),
            policy_set_digest: spec.policy_set().sha256().to_owned(),
            policies,
            audit_path: spec
                .output()
                .root()
                .join("evidence/filesystem-decisions.jsonl"),
        }
    }

    fn event(&self, request: &FileInterceptionRequest<'_>) -> RuntimeEvent {
        let resolved_identity = request.resolved_identity().map_or_else(
            || serde_json::Value::Null,
            |identity| {
                serde_json::json!({
                    "device": identity.device(),
                    "inode": identity.inode(),
                })
            },
        );
        RuntimeEvent {
            id: EventId::new(format!(
                "{}-{}-{}",
                self.session_id.as_str(),
                request.operation().as_str(),
                Uuid::new_v4().simple(),
            )),
            session_id: self.session_id.clone(),
            actor: ActorIdentity {
                id: String::from("agent"),
                kind: ActorKind::Agent,
            },
            surface: ExecutionSurface::Filesystem,
            action: Self::action(request.operation()),
            target: Some(TargetRef {
                label: Some(request.path().to_owned()),
                uri: request
                    .path()
                    .starts_with('/')
                    .then(|| format!("file://{}", request.path())),
            }),
            payload: serde_json::json!({
                "kind": "filesystem_file_operation",
                "operation": request.operation().as_str(),
                "path": request.path(),
                "cwd": request.cwd(),
                "pid": request.pid(),
                "ppid": request.ppid(),
                "resolved_identity": resolved_identity,
            }),
            risk: RiskMetadata {
                level: Self::risk(request.operation()),
                reasons: vec![request.operation().as_str().to_owned()],
            },
            timestamp: Self::timestamp(),
        }
    }

    fn action(operation: FileInterceptionOperationKind) -> ActionKind {
        match operation {
            FileInterceptionOperationKind::Open => ActionKind::FileOpen,
            FileInterceptionOperationKind::Read => ActionKind::FileRead,
            FileInterceptionOperationKind::Mutation => ActionKind::FileMutation,
        }
    }

    fn risk(operation: FileInterceptionOperationKind) -> RiskLevel {
        match operation {
            FileInterceptionOperationKind::Open | FileInterceptionOperationKind::Read => {
                RiskLevel::Low
            }
            FileInterceptionOperationKind::Mutation => RiskLevel::Medium,
        }
    }

    fn timestamp() -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        format!("unix:{seconds}")
    }

    fn decision(&self, decision: LayeredDecision) -> SurfaceInterceptionDecision {
        match decision {
            LayeredDecision::Allow => SurfaceInterceptionDecision::allow(
                format!("policy-set-{}", self.policy_set_digest),
                "all mandatory immutable policy layers allowed the filesystem operation",
            ),
            LayeredDecision::Deny { reason, rule_id } => SurfaceInterceptionDecision::deny(
                rule_id.unwrap_or_else(|| String::from("policy-deny-without-rule-id")),
                reason,
            ),
            LayeredDecision::RequireApproval {
                reason, rule_ids, ..
            } => SurfaceInterceptionDecision::require_approval(
                rule_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| String::from("policy-requires-approval")),
                reason,
            ),
            LayeredDecision::Mediate {
                reason, rule_ids, ..
            } => SurfaceInterceptionDecision::deny(
                rule_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| String::from("policy-requires-mediation")),
                format!(
                    "{reason}; no filesystem mediation binding is admitted for this session, so the Linux guard denies the effect"
                ),
            ),
        }
    }

    fn record_audit(&self, event: &RuntimeEvent, decision: &SurfaceInterceptionDecision) {
        let policy_decision = Self::audit_decision(decision);
        let final_decision = match &policy_decision {
            Decision::RequireApproval {
                reason, rule_id, ..
            } => Decision::Deny {
                reason: format!(
                    "{reason}; denied fail-closed because the filesystem guard cannot satisfy approvals"
                ),
                rule_id: rule_id.clone(),
            },
            _ => policy_decision.clone(),
        };
        let record = AuditRecord {
            event: event.clone(),
            policy_decision,
            final_decision,
            context_pin: None,
        };
        if let Err(error) = append_durable_audit_record(&self.audit_path, &record) {
            warn!(
                error;
                "filesystem surface audit record failed",
                session_id = %event.session_id.as_str(),
                event_id = %event.id.as_str()
            );
        }
    }

    fn audit_decision(decision: &SurfaceInterceptionDecision) -> Decision {
        let (kind, rule_id, reason, mediation) = decision.clone().into_parts();
        let rule_id = Some(rule_id);
        match kind {
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
}

impl FileOperationSurfaceHandler for StoredPolicyFileOperationHandler {
    fn surface(&self) -> &str {
        "filesystem"
    }

    fn decide_file_operation(
        &self,
        request: &FileInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        let event = self.event(request);
        let decision = match &self.policies {
            Ok(policy) => match policy.evaluate(&event) {
                Ok(decision) => self.decision(decision),
                Err(error) => SurfaceInterceptionDecision::deny(
                    "stored-policy-evaluation-failed",
                    format!("admitted policy evaluation failed closed: {error}"),
                ),
            },
            Err(reason) => SurfaceInterceptionDecision::deny(
                "stored-policy-load-failed",
                format!("admitted policy package cannot be evaluated: {reason}"),
            ),
        };
        self.record_audit(&event, &decision);
        decision
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erebor_runtime_audit::read_audit_records;
    use erebor_runtime_core::{
        FileInterceptionOperationKind, FileInterceptionRequest, FileOperationSurfaceHandler,
        ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    };
    use erebor_runtime_packages::PolicyPackageRevision;

    use super::{StoredPolicyFileOperationHandler, StoredPolicyProcessExecHandler};

    fn revision(source: &[u8]) -> Result<PolicyPackageRevision, Box<dyn std::error::Error>> {
        Ok(PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(String::from("terminal.json"), source.to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?)
    }

    #[test]
    fn mandatory_policy_layers_deny_when_any_layer_denies() -> Result<(), Box<dyn std::error::Error>>
    {
        let handler = StoredPolicyProcessExecHandler {
            session_id: erebor_runtime_events::SessionId::new("session-1"),
            policy_set_digest: "a".repeat(64),
            policies: StoredPolicyProcessExecHandler::compile_layers(vec![
                revision(
                    br#"{"rules":[{"id":"allow","match":{"surface":"terminal"},"decision":"allow"}]}"#,
                )?,
                revision(
                    br#"{"rules":[{"id":"deny","match":{"surface":"terminal"},"decision":"deny","reason":"blocked"}]}"#,
                )?,
            ])
            .map_err(|error| error.to_string()),
        };
        let argv = vec![String::from("id")];
        let (decision, rule_id, reason, _) = handler
            .decide_process_exec(&ProcessExecInterceptionRequest::new(
                "/usr/bin/id",
                &argv,
                "",
            ))
            .into_parts();
        assert_eq!(decision, SessionInterceptionDecision::Deny);
        assert_eq!(rule_id, "deny");
        assert_eq!(reason, "blocked");
        Ok(())
    }

    #[test]
    fn mediation_fails_closed_without_a_generic_mediation_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handler = StoredPolicyProcessExecHandler {
            session_id: erebor_runtime_events::SessionId::new("session-1"),
            policy_set_digest: "a".repeat(64),
            policies: StoredPolicyProcessExecHandler::compile_layers(vec![revision(
                br#"{"rules":[{"id":"mediate","match":{"surface":"terminal"},"decision":"mediate","mediation":{"kind":"managed"}}]}"#,
            )?])
            .map_err(|error| error.to_string()),
        };
        let argv = vec![String::from("id")];
        let (decision, _, reason, _) = handler
            .decide_process_exec(&ProcessExecInterceptionRequest::new(
                "/usr/bin/id",
                &argv,
                "",
            ))
            .into_parts();
        assert_eq!(decision, SessionInterceptionDecision::Deny);
        assert!(reason.contains("no admitted mediation owner"));
        Ok(())
    }

    #[test]
    fn filesystem_policy_layers_deny_before_a_mutation_can_proceed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let audit_path = temporary.path().join("filesystem-decisions.jsonl");
        let handler = StoredPolicyFileOperationHandler {
            session_id: erebor_runtime_events::SessionId::new("session-1"),
            policy_set_digest: "a".repeat(64),
            policies: StoredPolicyProcessExecHandler::compile_layers(vec![
                revision(
                    br#"{"rules":[{"id":"allow-filesystem","match":{"surface":"filesystem"},"decision":"allow"}]}"#,
                )?,
                revision(
                    br#"{"rules":[{"id":"deny-private-state","match":{"surface":"filesystem","action":"file_mutation","target_contains":".erebor-denied"},"decision":"deny","reason":"private state mutation is blocked"}]}"#,
                )?,
            ])
            .map_err(|error| error.to_string()),
            audit_path: audit_path.clone(),
        };
        let (decision, rule_id, reason, _) = handler
            .decide_file_operation(&FileInterceptionRequest::new(
                FileInterceptionOperationKind::Mutation,
                "/run/erebor/state/codex/.erebor-denied",
                "/run/erebor/state/codex",
                100,
                99,
            ))
            .into_parts();
        assert_eq!(decision, SessionInterceptionDecision::Deny);
        assert_eq!(rule_id, "deny-private-state");
        assert_eq!(reason, "private state mutation is blocked");
        let records = read_audit_records(audit_path)?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].event.surface,
            erebor_runtime_events::ExecutionSurface::Filesystem
        );
        assert_eq!(
            records[0].event.action,
            erebor_runtime_events::ActionKind::FileMutation
        );
        assert!(matches!(
            records[0].final_decision,
            erebor_runtime_policy::Decision::Deny { .. }
        ));
        Ok(())
    }
}
