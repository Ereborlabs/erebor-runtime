use erebor_runtime_core::{
    RuntimeConfig, RuntimeError, SessionAdoptPlan, SessionRunOutcome, SessionRunPlan,
    SessionRunnerKind, SessionRunnerLauncher,
};

use crate::{
    diagnostic::SessionDiagnosticOutcome,
    registry_lifecycle::{
        finish_registry_diagnostic, finish_registry_session, prepare_registry_session,
        PreparedSession,
    },
    session_side_resources::{start_adopt_session_side_resources, start_session_side_resources},
    SessionExecutionError,
};

pub struct SessionExecutionService;

impl SessionExecutionService {
    pub fn run_plan(
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
    ) -> Result<SessionRunOutcome, SessionExecutionError> {
        let prepared_session = prepare_registry_session(config, plan)?;
        let result = Self::run_plan_inner(config, plan, prepared_session.as_ref());
        finish_registry_session(prepared_session.as_ref(), plan.session_id(), &result)?;
        result
    }

    fn run_plan_inner(
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
        prepared_session: Option<&PreparedSession>,
    ) -> Result<SessionRunOutcome, SessionExecutionError> {
        let side_resources = start_session_side_resources(config, plan, prepared_session)?;

        match plan.runner().kind() {
            SessionRunnerKind::Docker => SessionRunnerLauncher::run_with_docker_options(
                plan,
                side_resources.environment(),
                side_resources.docker_options(),
            ),
            SessionRunnerKind::LinuxHost => SessionRunnerLauncher::run_with_linux_host_options(
                plan,
                side_resources.environment(),
                side_resources.linux_host_options(),
            ),
        }
        .map_err(SessionExecutionError::runtime)
    }

    pub fn run_diagnostic(
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
    ) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
        let prepared_session = prepare_registry_session(config, plan)?;
        let result = Self::run_diagnostic_inner(config, plan, prepared_session.as_ref());
        finish_registry_diagnostic(prepared_session.as_ref(), plan, &result)?;
        result
    }

    fn run_diagnostic_inner(
        config: &RuntimeConfig,
        plan: &SessionRunPlan,
        prepared_session: Option<&PreparedSession>,
    ) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
        let side_resources = start_session_side_resources(config, plan, prepared_session)?;
        let outcome = match plan.runner().kind() {
            SessionRunnerKind::Docker => SessionRunnerLauncher::run_capture_with_docker_options(
                plan,
                side_resources.environment(),
                side_resources.docker_options(),
            ),
            SessionRunnerKind::LinuxHost => {
                SessionRunnerLauncher::run_capture_with_linux_host_options(
                    plan,
                    side_resources.environment(),
                    side_resources.linux_host_options(),
                )
            }
        }
        .map_err(SessionExecutionError::runtime)?;

        if outcome.run().exit_code() == Some(0) {
            Ok(SessionDiagnosticOutcome::new(
                outcome.stdout().to_owned(),
                outcome.stderr().to_owned(),
            ))
        } else {
            Err(SessionExecutionError::diagnostic_failed(format!(
                "guarded {} diagnostic exited with code {:?}: {}",
                plan.runner().kind().as_str(),
                outcome.run().exit_code(),
                outcome.stderr().trim()
            )))
        }
    }

    pub fn adopt_plan(
        config: &RuntimeConfig,
        plan: &SessionAdoptPlan,
    ) -> Result<SessionRunOutcome, SessionExecutionError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => Err(SessionExecutionError::runtime(
                RuntimeError::unsupported_session_runner_operation("docker", "adopt"),
            )),
            SessionRunnerKind::LinuxHost => {
                let side_resources = start_adopt_session_side_resources(config, plan)?;
                let linux_host_options = side_resources.linux_host_adopt_options(plan.pid())?;
                SessionRunnerLauncher::adopt_with_linux_host_options(
                    plan,
                    side_resources.environment(),
                    &linux_host_options,
                )
                .map_err(SessionExecutionError::runtime)
            }
        }
    }

    pub fn adopt_plan_capture(
        config: &RuntimeConfig,
        plan: &SessionAdoptPlan,
    ) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
        let outcome = match plan.runner().kind() {
            SessionRunnerKind::Docker => {
                return Err(SessionExecutionError::runtime(
                    RuntimeError::unsupported_session_runner_operation("docker", "adopt"),
                ));
            }
            SessionRunnerKind::LinuxHost => {
                let side_resources = start_adopt_session_side_resources(config, plan)?;
                let linux_host_options = side_resources.linux_host_adopt_options(plan.pid())?;
                SessionRunnerLauncher::adopt_capture_with_linux_host_options(
                    plan,
                    side_resources.environment(),
                    &linux_host_options,
                )
            }
        }
        .map_err(SessionExecutionError::runtime)?;

        if outcome.run().exit_code() == Some(0) {
            Ok(SessionDiagnosticOutcome::new(
                outcome.stdout().to_owned(),
                outcome.stderr().to_owned(),
            ))
        } else {
            Err(SessionExecutionError::diagnostic_failed(format!(
                "guarded {} adoption exited with code {:?}: {}",
                plan.runner().kind().as_str(),
                outcome.run().exit_code(),
                outcome.stderr().trim()
            )))
        }
    }
}
