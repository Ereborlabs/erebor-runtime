use std::{collections::HashMap, fmt, sync::Arc};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SessionInterceptionDecision,
    SurfaceInterceptionDecision,
};
use erebor_runtime_ipc::v1::{
    AllowDecision, DecisionKind, InterceptionDecision, InterceptionRequest, MediateDecision,
};

use super::{
    constants::DEFAULT_TIMEOUT_MS,
    decision::deny_decision,
    mediation::{SessionMediationIntent, SessionMediationRegistry},
};

#[derive(Clone, Debug)]
pub(super) struct SessionRegistration {
    pub(super) token: String,
    pub(super) broker_id: String,
    pub(super) handlers: HashMap<String, SessionInterceptionHandler>,
    pub(super) router: SessionInterceptionRouter,
    pub(super) mediators: SessionMediationRegistry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionHandler {
    id: String,
    decision: SessionInterceptionDecision,
    reason: String,
    mediate: Option<SessionMediationIntent>,
}

impl SessionInterceptionHandler {
    #[must_use]
    pub fn allow(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Allow,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn deny(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Deny,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn require_approval(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::RequireApproval,
            reason: reason.into(),
            mediate: None,
        }
    }

    #[must_use]
    pub fn mediate(
        id: impl Into<String>,
        reason: impl Into<String>,
        intent: SessionMediationIntent,
    ) -> Self {
        Self {
            id: id.into(),
            decision: SessionInterceptionDecision::Mediate,
            reason: reason.into(),
            mediate: Some(intent),
        }
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default)]
pub struct SessionInterceptionRouter {
    process_exec: Option<Arc<dyn ProcessExecSurfaceHandler>>,
}

impl SessionInterceptionRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_process_exec_handler(
        mut self,
        handler: impl ProcessExecSurfaceHandler + 'static,
    ) -> Self {
        self.process_exec = Some(Arc::new(handler));
        self
    }

    pub(super) fn decide_process_exec(
        &self,
        request: &InterceptionRequest,
    ) -> Option<SurfaceInterceptionDecision> {
        let process_exec_request =
            ProcessExecInterceptionRequest::new(&request.executable, &request.argv);
        self.process_exec
            .as_ref()
            .map(|handler| handler.decide_process_exec(&process_exec_request))
    }
}

impl fmt::Debug for SessionInterceptionRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionInterceptionRouter")
            .field(
                "process_exec",
                &self.process_exec.as_ref().map(|handler| handler.surface()),
            )
            .finish()
    }
}

impl SessionInterceptionHandler {
    pub(super) fn decision_for_request(
        &self,
        request: &InterceptionRequest,
        mediators: &SessionMediationRegistry,
    ) -> InterceptionDecision {
        match self.decision {
            SessionInterceptionDecision::Allow => InterceptionDecision {
                request_id: request.request_id,
                decision: DecisionKind::Allow as i32,
                rule_id: self.id.clone(),
                reason: self.reason.clone(),
                timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                allow: Some(AllowDecision {
                    exec_target: String::new(),
                }),
                deny: None,
                mediate: None,
            },
            SessionInterceptionDecision::Deny => {
                deny_decision(request.request_id, &self.id, self.reason.clone())
            }
            SessionInterceptionDecision::RequireApproval => InterceptionDecision {
                request_id: request.request_id,
                decision: DecisionKind::RequireApproval as i32,
                rule_id: self.id.clone(),
                reason: self.reason.clone(),
                timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                allow: None,
                deny: None,
                mediate: None,
            },
            SessionInterceptionDecision::Mediate => {
                let Some(intent) = self.mediate.as_ref() else {
                    return deny_decision(
                        request.request_id,
                        &self.id,
                        "mediate handler has no replacement intent",
                    );
                };
                let outcome = match mediators.mediate(request, intent) {
                    Ok(outcome) => outcome,
                    Err(reason) => return deny_decision(request.request_id, &self.id, reason),
                };
                InterceptionDecision {
                    request_id: request.request_id,
                    decision: DecisionKind::Mediate as i32,
                    rule_id: self.id.clone(),
                    reason: self.reason.clone(),
                    timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                    allow: None,
                    deny: None,
                    mediate: Some(MediateDecision {
                        kind: outcome.kind,
                        replacement_surface: outcome.replacement_surface,
                        endpoint: outcome.endpoint,
                        lease_id: outcome.lease_id,
                        print_line: outcome.print_line,
                        keepalive: outcome.keepalive,
                    }),
                }
            }
        }
    }
}
