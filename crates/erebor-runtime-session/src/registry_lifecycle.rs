use std::path::{Path, PathBuf};

use erebor_runtime_core::{
    RuntimeConfig, RuntimeError, SessionRegistry, SessionRegistryFinish, SessionRunOutcome,
    SessionRunPlan,
};
use erebor_runtime_events::SessionId;
use snafu::ResultExt;

use crate::{
    diagnostic::SessionDiagnosticOutcome, error::SessionRegistrySnafu, SessionExecutionError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionStorage {
    audit_path: PathBuf,
}

impl SessionStorage {
    fn new(audit_path: PathBuf) -> Self {
        Self { audit_path }
    }

    pub(crate) fn audit_path(&self) -> &Path {
        &self.audit_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedSession {
    registry: SessionRegistry,
    storage: SessionStorage,
}

impl PreparedSession {
    pub(crate) fn storage(&self) -> &SessionStorage {
        &self.storage
    }
}

pub(crate) fn prepare_registry_session(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
) -> Result<Option<PreparedSession>, SessionExecutionError> {
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry
        .start_session(config, plan)
        .context(SessionRegistrySnafu)?;
    let storage = SessionStorage::new(started.audit_path().to_path_buf());
    Ok(Some(PreparedSession { registry, storage }))
}

pub(crate) fn finish_registry_session(
    prepared_session: Option<&PreparedSession>,
    session_id: &SessionId,
    result: &Result<SessionRunOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let update = match result {
        Ok(outcome) => SessionRegistryFinish::succeeded(outcome),
        Err(error) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(session_id, update)
        .context(SessionRegistrySnafu)?;
    Ok(())
}

pub(crate) fn finish_registry_diagnostic(
    prepared_session: Option<&PreparedSession>,
    plan: &SessionRunPlan,
    result: &Result<SessionDiagnosticOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let update = match result {
        Ok(_outcome) => {
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(plan.runner().kind(), Some(0)))
        }
        Err(error) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(plan.session_id(), update)
        .context(SessionRegistrySnafu)?;
    Ok(())
}

fn session_exit_code_from_error(error: &SessionExecutionError) -> Option<i32> {
    match error {
        SessionExecutionError::Runtime {
            source: RuntimeError::SessionRunnerExit { code, .. },
            ..
        } => *code,
        SessionExecutionError::DiagnosticFailed { .. } => None,
        _ => None,
    }
}
