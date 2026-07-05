use std::path::{Path, PathBuf};

use erebor_runtime_core::{
    FilesystemSurfaceConfig, RuntimeConfig, RuntimeError, SessionRegistry, SessionRegistryFinish,
    SessionRunOutcome, SessionRunPlan,
};
use erebor_runtime_events::SessionId;
use erebor_runtime_filesystem::{
    commit_session_checkpoint, FilesystemSessionStorage, FilesystemVolumeStorageRequest,
};
use snafu::ResultExt;

use crate::{
    diagnostic::SessionDiagnosticOutcome,
    error::{FilesystemSurfaceSnafu, InvalidConfigSnafu, SessionRegistrySnafu},
    SessionExecutionError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionStorage {
    audit_path: PathBuf,
    filesystem: Option<FilesystemSessionStorage>,
}

impl SessionStorage {
    fn new(audit_path: PathBuf, filesystem: Option<FilesystemSessionStorage>) -> Self {
        Self {
            audit_path,
            filesystem,
        }
    }

    pub(crate) fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    pub(crate) fn filesystem(&self) -> Option<&FilesystemSessionStorage> {
        self.filesystem.as_ref()
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
    let surface_plan = config
        .surface_start_plan_for_session(plan)
        .context(InvalidConfigSnafu)?;
    let filesystem_result = surface_plan.filesystem().map_or(Ok(None), |filesystem| {
        prepare_filesystem_storage(started.record().session_dir.as_path(), filesystem)
    });
    let filesystem = match filesystem_result {
        Ok(filesystem) => filesystem,
        Err(error) => {
            let _result = registry.finish_session(
                plan.session_id(),
                SessionRegistryFinish::failed(None, error.to_string()),
            );
            return Err(error);
        }
    };
    let storage = SessionStorage::new(started.audit_path().to_path_buf(), filesystem);
    Ok(Some(PreparedSession { registry, storage }))
}

fn prepare_filesystem_storage(
    session_dir: &Path,
    filesystem: &FilesystemSurfaceConfig,
) -> Result<Option<FilesystemSessionStorage>, SessionExecutionError> {
    if filesystem.volumes().is_empty() {
        return Ok(None);
    }

    let volumes = filesystem
        .volumes()
        .iter()
        .map(|volume| {
            FilesystemVolumeStorageRequest::new(
                volume.id(),
                volume.host_path(),
                volume.session_path(),
                volume.mode(),
            )
            .context(FilesystemSurfaceSnafu)
        })
        .collect::<Result<Vec<_>, _>>()?;

    FilesystemSessionStorage::prepare(session_dir, volumes)
        .map(Some)
        .context(FilesystemSurfaceSnafu)
}

pub(crate) fn finish_registry_session(
    prepared_session: Option<&PreparedSession>,
    session_id: &SessionId,
    result: &Result<SessionRunOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let filesystem_result =
        checkpoint_successful_filesystem_layers(prepared_session, session_id, result.is_ok());
    let update = match (result, &filesystem_result) {
        (Ok(outcome), Ok(())) => SessionRegistryFinish::succeeded(outcome),
        (Ok(_outcome), Err(error)) => SessionRegistryFinish::failed(None, error.to_string()),
        (Err(error), _) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(session_id, update)
        .context(SessionRegistrySnafu)?;
    filesystem_result
}

pub(crate) fn finish_registry_diagnostic(
    prepared_session: Option<&PreparedSession>,
    plan: &SessionRunPlan,
    result: &Result<SessionDiagnosticOutcome, SessionExecutionError>,
) -> Result<(), SessionExecutionError> {
    let Some(prepared_session) = prepared_session else {
        return Ok(());
    };
    let filesystem_result = checkpoint_successful_filesystem_layers(
        prepared_session,
        plan.session_id(),
        result.is_ok(),
    );
    let update = match (result, &filesystem_result) {
        (Ok(_outcome), Ok(())) => {
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(plan.runner().kind(), Some(0)))
        }
        (Ok(_outcome), Err(error)) => SessionRegistryFinish::failed(None, error.to_string()),
        (Err(error), _) => {
            SessionRegistryFinish::failed(session_exit_code_from_error(error), error.to_string())
        }
    };
    prepared_session
        .registry
        .finish_session(plan.session_id(), update)
        .context(SessionRegistrySnafu)?;
    filesystem_result
}

fn checkpoint_successful_filesystem_layers(
    prepared_session: &PreparedSession,
    session_id: &SessionId,
    successful: bool,
) -> Result<(), SessionExecutionError> {
    if !successful {
        return Ok(());
    }
    if let Some(storage) = prepared_session.storage().filesystem() {
        commit_session_checkpoint(storage, session_id.as_str()).context(FilesystemSurfaceSnafu)?;
    }
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
