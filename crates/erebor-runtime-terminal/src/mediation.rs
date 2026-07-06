use std::sync::Arc;

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessInterceptionDecision, ProcessMediationHandlerConfig,
    ProcessMediationReplacementSurface, SurfaceInterceptionDecision, SurfaceMediationDecision,
    TerminalSurfaceConfig,
};

pub trait TerminalProcessMediationCapability: Send + Sync {
    fn mediate_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
        handler: &ProcessMediationHandlerConfig,
    ) -> Result<SurfaceMediationDecision, String>;
}

#[derive(Default)]
pub(crate) struct TerminalProcessMediationPolicy {
    handlers: Vec<ProcessMediationHandlerConfig>,
    capability: Option<Arc<dyn TerminalProcessMediationCapability>>,
}

impl TerminalProcessMediationPolicy {
    pub(crate) fn from_config(config: &TerminalSurfaceConfig) -> Self {
        let handlers = if config.process_interception().enabled() {
            config.process_interception().handlers().to_vec()
        } else {
            Vec::new()
        };

        Self {
            handlers,
            capability: None,
        }
    }

    pub(crate) fn set_capability(
        &mut self,
        capability: impl TerminalProcessMediationCapability + 'static,
    ) {
        self.capability = Some(Arc::new(capability));
    }

    pub(crate) fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        let handler_id = request.matched_handler_id();
        let Some(handler) = self
            .handlers
            .iter()
            .find(|handler| handler.id() == handler_id)
        else {
            return SurfaceInterceptionDecision::deny(
                "terminal-process-exec-unknown-interception-handler",
                format!("process interception handler `{handler_id}` is not configured"),
            );
        };

        match handler.decision() {
            ProcessInterceptionDecision::Allow => SurfaceInterceptionDecision::allow(
                handler.id(),
                handler.decision().terminal_process_reason(),
            ),
            ProcessInterceptionDecision::Deny => SurfaceInterceptionDecision::deny(
                handler.id(),
                handler.decision().terminal_process_reason(),
            ),
            ProcessInterceptionDecision::RequireApproval => {
                SurfaceInterceptionDecision::require_approval(
                    handler.id(),
                    handler.decision().terminal_process_reason(),
                )
            }
            ProcessInterceptionDecision::Mediate => self.decide_mediation(request, handler),
        }
    }

    fn decide_mediation(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
        handler: &ProcessMediationHandlerConfig,
    ) -> SurfaceInterceptionDecision {
        let Some(capability) = self.capability.as_ref() else {
            return SurfaceInterceptionDecision::deny(
                handler.id(),
                handler.replacement().surface().missing_capability_reason(),
            );
        };

        match capability.mediate_process_exec(request, handler) {
            Ok(mediation) => SurfaceInterceptionDecision::mediate(
                handler.id(),
                handler.decision().terminal_process_reason(),
                mediation,
            ),
            Err(reason) => SurfaceInterceptionDecision::deny(handler.id(), reason),
        }
    }
}

trait TerminalProcessDecisionReason {
    fn terminal_process_reason(self) -> &'static str;
}

impl TerminalProcessDecisionReason for ProcessInterceptionDecision {
    fn terminal_process_reason(self) -> &'static str {
        match self {
            Self::Allow => "process launch allowed by terminal process surface",
            Self::Deny => "process launch denied by terminal process surface",
            Self::RequireApproval => {
                "process launch requires approval from terminal process surface"
            }
            Self::Mediate => "process launch mediated by terminal process surface",
        }
    }
}

trait MissingMediationCapabilityReason {
    fn missing_capability_reason(self) -> String;
}

impl MissingMediationCapabilityReason for ProcessMediationReplacementSurface {
    fn missing_capability_reason(self) -> String {
        match self {
            Self::BrowserCdp => {
                String::from("browser_cdp process mediation capability is unavailable")
            }
        }
    }
}
