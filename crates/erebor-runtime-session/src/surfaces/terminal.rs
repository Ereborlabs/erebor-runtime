pub(crate) mod browser_cdp_process_mediation;

use std::path::PathBuf;

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_core::{
    ProcessInterceptionHandlerKind, RuntimeAuditConfig, SessionRunnerKind,
    TerminalProcessInterceptionMode, TerminalSurfaceConfig,
};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_terminal::TerminalProcessExecValidator;

use self::browser_cdp_process_mediation::BrowserCdpProcessMediationCapability;
use crate::{
    interception_backend::{
        ProcessExecInterceptionInput, ProcessExecMediationInput, ProcessExecMediationMode,
    },
    runtime_interception_broker::SessionInterceptionRouter,
    SessionExecutionError, SessionPlanContext,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct TerminalProcessSurface<'a> {
    config: Option<&'a TerminalSurfaceConfig>,
}

impl<'a> TerminalProcessSurface<'a> {
    pub(crate) const fn absent() -> Self {
        Self { config: None }
    }

    pub(crate) const fn present(config: &'a TerminalSurfaceConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub(crate) fn uses_managed_browser_cdp_mediation(config: &TerminalSurfaceConfig) -> bool {
        config.process_interception().enabled()
            && config
                .process_interception()
                .handlers()
                .iter()
                .any(|handler| handler.kind() == ProcessInterceptionHandlerKind::ManagedBrowserCdp)
    }

    pub(crate) fn backend_input(
        &self,
        plan: &impl SessionPlanContext,
    ) -> Result<Option<ProcessExecInterceptionInput<'a>>, SessionExecutionError> {
        let Some(config) = self.config else {
            return Ok(None);
        };

        let mediation = config.process_interception();
        if mediation.enabled() && plan.runner_kind() != SessionRunnerKind::LinuxHost {
            return Err(SessionExecutionError::guard_config(
                "terminal process interception currently supports linux-host sessions only",
            ));
        }

        Ok(Some(ProcessExecInterceptionInput::new(
            ProcessExecMediationInput::new(
                mediation.enabled(),
                process_exec_mediation_mode(mediation.mode()),
                mediation.handlers(),
            ),
            plan.audit().surfaces().terminal().level(),
            plan.audit().surfaces().terminal().debug_commands().to_vec(),
            config.tty(),
        )))
    }

    pub(crate) fn router(
        &self,
        browser_cdp_endpoint: Option<&str>,
        lazy_browser_cdp: Option<LazyBrowserCdpProcessMediation>,
    ) -> Result<SessionInterceptionRouter, SessionExecutionError> {
        let Some(config) = self.config else {
            return Ok(SessionInterceptionRouter::new());
        };

        let mut validator = TerminalProcessExecValidator::from_config(config)
            .map_err(SessionExecutionError::terminal_surface)?;

        if let Some(capability) =
            self.browser_cdp_process_mediation_capability(browser_cdp_endpoint, lazy_browser_cdp)?
        {
            validator = validator.with_process_mediation_capability(capability);
        }

        Ok(SessionInterceptionRouter::new().with_process_exec_handler(validator))
    }

    fn browser_cdp_process_mediation_capability(
        &self,
        browser_cdp_endpoint: Option<&str>,
        lazy_browser_cdp: Option<LazyBrowserCdpProcessMediation>,
    ) -> Result<Option<BrowserCdpProcessMediationCapability>, SessionExecutionError> {
        let Some(config) = self.config else {
            return Ok(None);
        };

        if !Self::uses_managed_browser_cdp_mediation(config) {
            return Ok(None);
        }

        if let Some(lazy) = lazy_browser_cdp {
            return lazy.into_capability().map(Some);
        }

        Ok(browser_cdp_endpoint.map(BrowserCdpProcessMediationCapability::new))
    }
}

#[derive(Clone)]
pub(crate) struct LazyBrowserCdpProcessMediation {
    config: erebor_runtime_core::BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
}

impl LazyBrowserCdpProcessMediation {
    pub(crate) fn new(
        config: erebor_runtime_core::BrowserCdpSurfaceConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
        audit_jsonl: Option<PathBuf>,
        audit: RuntimeAuditConfig,
    ) -> Self {
        Self {
            config,
            policy_set,
            context,
            audit_jsonl,
            audit,
        }
    }

    fn into_capability(
        self,
    ) -> Result<BrowserCdpProcessMediationCapability, SessionExecutionError> {
        BrowserCdpProcessMediationCapability::lazy(
            self.config,
            self.policy_set,
            self.context,
            self.audit_jsonl,
            self.audit,
        )
        .map_err(SessionExecutionError::guard_io)
    }
}

fn process_exec_mediation_mode(mode: TerminalProcessInterceptionMode) -> ProcessExecMediationMode {
    match mode {
        TerminalProcessInterceptionMode::Shim => ProcessExecMediationMode::Shim,
    }
}
