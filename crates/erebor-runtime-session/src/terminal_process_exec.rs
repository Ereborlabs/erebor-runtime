use erebor_runtime_core::{
    SessionInterceptionOperation, SessionRunnerKind, SessionSurfaceStartPlan,
    TerminalProcessInterceptionMode, TerminalSurfaceConfig,
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

pub(crate) fn backend_input_from_start_plan<'a>(
    start_plan: &'a SessionSurfaceStartPlan,
    plan: &impl SessionPlanContext,
) -> Result<Option<ProcessExecInterceptionInput<'a>>, SessionExecutionError> {
    if !start_plan
        .interception()
        .operation_supported(SessionInterceptionOperation::ProcessExec)
    {
        return Ok(None);
    }

    backend_input_from_terminal(start_plan.terminal(), plan)
}

pub(crate) fn router_from_start_plan(
    start_plan: &SessionSurfaceStartPlan,
) -> Result<SessionInterceptionRouter, SessionExecutionError> {
    if !start_plan
        .interception()
        .operation_supported(SessionInterceptionOperation::ProcessExec)
    {
        return Ok(SessionInterceptionRouter::new());
    }

    let Some(terminal) = start_plan.terminal() else {
        return Ok(SessionInterceptionRouter::new());
    };

    Ok(SessionInterceptionRouter::new()
        .with_process_exec_handler(TerminalProcessExecSurfaceHandler::new(terminal)?))
}

fn backend_input_from_terminal<'a>(
    terminal: Option<&'a TerminalSurfaceConfig>,
    plan: &impl SessionPlanContext,
) -> Result<Option<ProcessExecInterceptionInput<'a>>, SessionExecutionError> {
    let Some(terminal) = terminal else {
        return Ok(None);
    };

    let mediation = terminal.process_interception();
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
        terminal.tty(),
    )))
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
