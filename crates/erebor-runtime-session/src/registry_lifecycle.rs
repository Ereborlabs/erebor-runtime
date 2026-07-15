use std::path::{Path, PathBuf};

use erebor_runtime_core::{
    FilesystemRevertConfig, FilesystemSurfaceConfig, RuntimeConfig, RuntimeError, SessionRegistry,
    SessionRegistryFinish, SessionRunOutcome, SessionRunPlan,
};
use erebor_runtime_events::SessionId;
use erebor_runtime_filesystem::{
    FilesystemCheckpointCommit, FilesystemPromotion, FilesystemPromotionOptions,
    FilesystemSessionStorage, FilesystemSessionWorkCommitRequest, FilesystemVolumeStorageRequest,
};
use snafu::{Location, ResultExt};

use crate::{
    diagnostic::SessionDiagnosticOutcome,
    error::{FilesystemSurfaceSnafu, InvalidConfigSnafu, SessionRegistrySnafu},
    SessionExecutionError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionStorage {
    audit_path: PathBuf,
    filesystem: Option<PreparedFilesystemStorage>,
}

impl SessionStorage {
    fn new(audit_path: PathBuf, filesystem: Option<PreparedFilesystemStorage>) -> Self {
        Self {
            audit_path,
            filesystem,
        }
    }

    pub(crate) fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    pub(crate) fn filesystem(&self) -> Option<&FilesystemSessionStorage> {
        self.filesystem
            .as_ref()
            .map(PreparedFilesystemStorage::storage)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedFilesystemStorage {
    storage: FilesystemSessionStorage,
    revert: FilesystemRevertConfig,
}

impl PreparedFilesystemStorage {
    fn new(storage: FilesystemSessionStorage, revert: FilesystemRevertConfig) -> Self {
        Self { storage, revert }
    }

    fn storage(&self) -> &FilesystemSessionStorage {
        &self.storage
    }

    fn revert(&self) -> &FilesystemRevertConfig {
        &self.revert
    }
}

pub(crate) struct PreparedSession {
    registry: SessionRegistry,
    storage: SessionStorage,
    session_id: String,
    context_repository: erebor_runtime_context::ContextRepository,
}

impl PreparedSession {
    pub(crate) fn storage(&self) -> &SessionStorage {
        &self.storage
    }

    fn verify_context_repository(&self) -> Result<(), SessionExecutionError> {
        self.context_repository
            .scope_refs()
            .map(|_| ())
            .map_err(
                |source| erebor_runtime_core::SessionRegistryError::ContextRepository {
                    session_id: self.session_id.clone(),
                    path: self.context_repository.path().to_path_buf(),
                    source: Box::new(source),
                    location: Location::default(),
                },
            )
            .context(SessionRegistrySnafu)
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
    let codex_managed_storage_required = plan.runner().kind()
        == erebor_runtime_core::SessionRunnerKind::LinuxHost
        && plan
            .command()
            .first()
            .is_some_and(|command| config.codex.matching_profile(Path::new(command)).is_some());
    let filesystem_result = surface_plan.filesystem().map_or(Ok(None), |filesystem| {
        prepare_filesystem_storage(
            started.record().session_dir.as_path(),
            filesystem,
            codex_managed_storage_required,
        )
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
    let context_repository = started.into_context_repository();
    Ok(Some(PreparedSession {
        registry,
        storage,
        session_id: plan.session_id().as_str().to_owned(),
        context_repository,
    }))
}

fn prepare_filesystem_storage(
    session_dir: &Path,
    filesystem: &FilesystemSurfaceConfig,
    codex_managed_storage_required: bool,
) -> Result<Option<PreparedFilesystemStorage>, SessionExecutionError> {
    if filesystem.volumes().is_empty() && !codex_managed_storage_required {
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
        .map(|storage| {
            Some(PreparedFilesystemStorage::new(
                storage,
                filesystem.revert().clone(),
            ))
        })
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
    prepared_session.verify_context_repository()?;
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
    prepared_session.verify_context_repository()?;
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
    if let Some(filesystem) = prepared_session.storage().filesystem.as_ref() {
        if filesystem.revert().promote_on_session_finish() {
            let options = FilesystemPromotionOptions::from_parts(
                filesystem.revert().preimage_size_limit_bytes(),
                filesystem.revert().preimage_backend(),
            );
            FilesystemPromotion::promote_checkpoint(
                filesystem.storage(),
                session_id.as_str(),
                options,
            )
            .context(FilesystemSurfaceSnafu)?;
        } else if let Some(rule) = filesystem.revert().autocommit().session_finish_rule() {
            let request =
                FilesystemSessionWorkCommitRequest::autocommit(session_id.as_str(), rule.id())
                    .context(FilesystemSurfaceSnafu)?;
            filesystem
                .storage()
                .commit_session_work(request)
                .context(FilesystemSurfaceSnafu)?;
        } else {
            FilesystemCheckpointCommit::commit(filesystem.storage(), session_id.as_str())
                .context(FilesystemSurfaceSnafu)?;
        }
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
