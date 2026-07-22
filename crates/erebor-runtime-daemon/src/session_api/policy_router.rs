use std::sync::Arc;

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionSpec,
    SurfaceInterceptionDecision,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_packages::PolicyPackageRevision;
use erebor_runtime_policy::{
    LayeredDecision, LayeredPolicySet, LocalPolicy, PolicyLayer, PolicySet,
};
use erebor_runtime_session::{SessionInterceptionRouter, SessionInterceptionRouterFactory};
use erebor_runtime_session::{CodexAppServerService, CodexHookService, SessionManagerError};

use crate::local_store::DaemonLocalStore;

/// The session-bound policy route. It reconstructs every immutable policy
/// input named by the admitted `SessionSpec`; it never reads a mutable policy
/// path supplied by a client or workload.
pub(super) struct StoredPolicyInterceptionRouterFactory {
    local_store: Arc<DaemonLocalStore>,
    codex_hook_service: Arc<CodexHookService>,
    codex_app_server_service: Arc<CodexAppServerService>,
}

impl StoredPolicyInterceptionRouterFactory {
    pub(super) const fn new(
        local_store: Arc<DaemonLocalStore>,
        codex_hook_service: Arc<CodexHookService>,
        codex_app_server_service: Arc<CodexAppServerService>,
    ) -> Self {
        Self {
            local_store,
            codex_hook_service,
            codex_app_server_service,
        }
    }
}

impl SessionInterceptionRouterFactory for StoredPolicyInterceptionRouterFactory {
    fn router(&self, spec: &SessionSpec) -> Result<SessionInterceptionRouter, SessionManagerError> {
        let router = SessionInterceptionRouter::new().with_process_exec_handler(
            StoredPolicyProcessExecHandler::from_session(Arc::clone(&self.local_store), spec),
        );
        let admission = self
            .local_store
            .validate_session_spec(spec)
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        if admission.package().adapter_id() != "codex-v1" {
            return Ok(router);
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
            .register_session(spec, codex.package().definition())
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        self.codex_app_server_service
            .register(registration.app_server_registration())
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        Ok(registration.with_interception_router(router))
    }

    fn cleanup(&self, spec: &SessionSpec) -> Result<(), SessionManagerError> {
        self.codex_hook_service
            .unregister(spec.session_id().as_str())
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        self.codex_app_server_service
            .unregister(spec.session_id().as_str())
            .map_err(|error| self.invalid_error(spec, error.to_string()))?;
        Ok(())
    }
}

impl StoredPolicyInterceptionRouterFactory {
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
                )
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use erebor_runtime_core::{
        ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    };
    use erebor_runtime_packages::PolicyPackageRevision;

    use super::StoredPolicyProcessExecHandler;

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
}
