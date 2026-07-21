use erebor_runtime_core::{
    RuntimeConfig, RuntimeError, SessionAdoptPlan, SessionRunOutcome, SessionRunPlan,
    SessionRunnerKind, SessionRunnerLauncher,
};
use snafu::{Location, ResultExt};

use crate::{
    agents::codex::CodexAppServerTransportBroker,
    diagnostic::SessionDiagnosticOutcome,
    error::{DiagnosticFailedSnafu, RuntimeSnafu},
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

        if let Some(profile) = plan
            .command()
            .first()
            .and_then(|command| config.codex.matching_profile(std::path::Path::new(command)))
            .filter(|profile| CodexAppServerTransportBroker::configured_for(profile))
        {
            let _prepared_session = prepared_session.ok_or_else(|| SessionExecutionError::CodexSession {
                source: Box::new(crate::CodexSessionError::IncompatibleProfile {
                    reason: String::from(
                        "a brokered Codex App Server session requires a durable session context repository",
                    ),
                    location: Location::default(),
                }),
                location: Location::default(),
            })?;
            let reconciliation = side_resources.codex_prompt_reconciliation().ok_or_else(|| {
                SessionExecutionError::CodexSession {
                    source: Box::new(crate::CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "a brokered Codex App Server session requires the authenticated hook reconciler",
                        ),
                        location: Location::default(),
                    }),
                    location: Location::default(),
                }
            })?;
            let lease_owner = side_resources.codex_invocation_lease_owner().ok_or_else(|| {
                SessionExecutionError::CodexSession {
                    source: Box::new(crate::CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "a brokered Codex App Server session requires the invocation lease owner",
                        ),
                        location: Location::default(),
                    }),
                    location: Location::default(),
                }
            })?;
            let context_dag = lease_owner
                .context_dag()
                .context(crate::error::CodexSessionSnafu)?
                .ok_or_else(|| {
                SessionExecutionError::CodexSession {
                    source: Box::new(crate::CodexSessionError::IncompatibleProfile {
                        reason: String::from(
                            "a brokered Codex App Server session requires a durable Codex Context DAG owner",
                        ),
                        location: Location::default(),
                    }),
                    location: Location::default(),
                }
            })?;
            return CodexAppServerTransportBroker::new(
                profile,
                plan,
                context_dag,
                reconciliation,
                lease_owner,
            )
            .and_then(|broker| {
                broker.run(
                    side_resources.environment(),
                    side_resources.linux_host_options(),
                )
            })
            .context(crate::error::CodexSessionSnafu);
        }

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
        .context(RuntimeSnafu)
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
        .context(RuntimeSnafu)?;

        if outcome.run().exit_code() == Some(0) {
            Ok(SessionDiagnosticOutcome::new(
                outcome.stdout().to_owned(),
                outcome.stderr().to_owned(),
            ))
        } else {
            DiagnosticFailedSnafu {
                reason: format!(
                    "guarded {} diagnostic exited with code {:?}: {}",
                    plan.runner().kind().as_str(),
                    outcome.run().exit_code(),
                    outcome.stderr().trim()
                ),
            }
            .fail()
        }
    }

    pub fn adopt_plan(
        config: &RuntimeConfig,
        plan: &SessionAdoptPlan,
    ) -> Result<SessionRunOutcome, SessionExecutionError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => Err(SessionExecutionError::Runtime {
                source: Box::new(RuntimeError::UnsupportedSessionRunnerOperation {
                    runner: String::from("docker"),
                    operation: String::from("adopt"),
                    location: Location::default(),
                }),
                location: Location::default(),
            }),
            SessionRunnerKind::LinuxHost => {
                let side_resources = start_adopt_session_side_resources(config, plan)?;
                let linux_host_options = side_resources.linux_host_adopt_options(plan.pid())?;
                SessionRunnerLauncher::adopt_with_linux_host_options(
                    plan,
                    side_resources.environment(),
                    &linux_host_options,
                )
                .context(RuntimeSnafu)
            }
        }
    }

    pub fn adopt_plan_capture(
        config: &RuntimeConfig,
        plan: &SessionAdoptPlan,
    ) -> Result<SessionDiagnosticOutcome, SessionExecutionError> {
        let outcome = match plan.runner().kind() {
            SessionRunnerKind::Docker => {
                return Err(SessionExecutionError::Runtime {
                    source: Box::new(RuntimeError::UnsupportedSessionRunnerOperation {
                        runner: String::from("docker"),
                        operation: String::from("adopt"),
                        location: Location::default(),
                    }),
                    location: Location::default(),
                });
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
        .context(RuntimeSnafu)?;

        if outcome.run().exit_code() == Some(0) {
            Ok(SessionDiagnosticOutcome::new(
                outcome.stdout().to_owned(),
                outcome.stderr().to_owned(),
            ))
        } else {
            DiagnosticFailedSnafu {
                reason: format!(
                    "guarded {} adoption exited with code {:?}: {}",
                    plan.runner().kind().as_str(),
                    outcome.run().exit_code(),
                    outcome.stderr().trim()
                ),
            }
            .fail()
        }
    }
}
