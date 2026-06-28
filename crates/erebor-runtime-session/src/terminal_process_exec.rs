use erebor_runtime_core::{
    SessionRunnerKind, TerminalProcessInterceptionMode, TerminalSurfaceConfig,
};
use erebor_runtime_ipc::v1::InterceptionRequest;
use erebor_runtime_terminal::{
    TerminalProcessGuardDecision, TerminalProcessPolicy, TerminalProcessPolicyDecision,
};

use crate::control_broker::{
    ProcessExecSurfaceHandler, SessionInterceptionRouter, SurfaceInterceptionDecision,
};
use crate::interception_backend::{
    ProcessExecInterceptionInput, ProcessExecMediationInput, ProcessExecMediationMode,
};
use crate::{SessionExecutionError, SessionPlanContext};

pub(crate) fn backend_input_from_surface<'a>(
    terminal: &'a TerminalSurfaceConfig,
    plan: &impl SessionPlanContext,
) -> Result<ProcessExecInterceptionInput<'a>, SessionExecutionError> {
    let mediation = terminal.process_interception();
    if mediation.enabled() && plan.runner_kind() != SessionRunnerKind::LinuxHost {
        return Err(SessionExecutionError::guard_config(
            "terminal process interception currently supports linux-host sessions only",
        ));
    }

    Ok(ProcessExecInterceptionInput::new(
        ProcessExecMediationInput::new(
            mediation.enabled(),
            process_exec_mediation_mode(mediation.mode()),
            mediation.handlers(),
        ),
        plan.audit().surfaces().terminal().level(),
        plan.audit().surfaces().terminal().debug_commands().to_vec(),
        terminal.tty(),
    ))
}

pub(crate) fn register_surface_handler(
    router: SessionInterceptionRouter,
    terminal: &TerminalSurfaceConfig,
) -> Result<SessionInterceptionRouter, SessionExecutionError> {
    Ok(router.with_process_exec_handler(TerminalProcessExecSurfaceHandler::new(terminal)?))
}

struct TerminalProcessExecSurfaceHandler {
    policy: TerminalProcessPolicy,
}

impl TerminalProcessExecSurfaceHandler {
    fn new(config: &TerminalSurfaceConfig) -> Result<Self, SessionExecutionError> {
        Ok(Self {
            policy: TerminalProcessPolicy::from_config(config)
                .map_err(SessionExecutionError::terminal_surface)?,
        })
    }
}

impl ProcessExecSurfaceHandler for TerminalProcessExecSurfaceHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(&self, request: &InterceptionRequest) -> SurfaceInterceptionDecision {
        self.policy
            .decide_process_exec(&request.executable, &request.argv)
            .map_or_else(default_allow_process_exec, surface_decision)
    }
}

fn surface_decision(decision: TerminalProcessPolicyDecision) -> SurfaceInterceptionDecision {
    match decision.decision() {
        TerminalProcessGuardDecision::Allow => {
            SurfaceInterceptionDecision::allow(decision.rule_id(), decision.reason())
        }
        TerminalProcessGuardDecision::Deny => {
            SurfaceInterceptionDecision::deny(decision.rule_id(), decision.reason())
        }
        TerminalProcessGuardDecision::RequireApproval => {
            SurfaceInterceptionDecision::require_approval(decision.rule_id(), decision.reason())
        }
    }
}

fn default_allow_process_exec() -> SurfaceInterceptionDecision {
    SurfaceInterceptionDecision::allow(
        "terminal-process-exec-default-allow",
        "process execution allowed by terminal policy",
    )
}

fn process_exec_mediation_mode(mode: TerminalProcessInterceptionMode) -> ProcessExecMediationMode {
    match mode {
        TerminalProcessInterceptionMode::Shim => ProcessExecMediationMode::Shim,
    }
}
