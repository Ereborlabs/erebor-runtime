use erebor_runtime_core::{
    FileInterceptionOperationKind, FileInterceptionRequest, FileOperationSurfaceHandler,
    SessionInterceptionDecision,
};
use erebor_runtime_filesystem::{
    FilesystemRetentionInventory, FilesystemRetentionPrune, FilesystemSessionWorkCatalog,
    FilesystemSessionWorkCommitRequest, FilesystemSessionWorkRename, FilesystemSessionWorkRollback,
    FilesystemSessionWorkTarget, FilesystemTransactionCatalog, FilesystemTransactionRename,
    FilesystemTransactionRollback, FilesystemTransactionTarget,
};
use erebor_runtime_ipc::v1::{FilesystemOperationKind, FilesystemOperationResponse};
use snafu::ResultExt;

use crate::{
    error::{InvalidRequestSnafu, SessionSnafu},
    Result,
};

use super::{policy_router::StoredPolicyFileOperationHandler, DaemonSessionApi};

impl DaemonSessionApi {
    pub(crate) fn filesystem_query(
        &self,
        owner_uid: u32,
        session_reference: &str,
        operation: i32,
        target: &str,
        output_format: &str,
    ) -> Result<FilesystemOperationResponse> {
        let session_id = self.resolve_session_reference(owner_uid, session_reference)?;
        let storage = self
            .manager
            .filesystem_storage(owner_uid, &session_id)
            .context(SessionSnafu)?;
        match Self::operation(operation)? {
            FilesystemOperationKind::TransactionsList => {
                let transactions =
                    FilesystemTransactionCatalog::load(&storage).map_err(Self::filesystem_error)?;
                let session_work = FilesystemSessionWorkCatalog::load(&storage, &session_id)
                    .map_err(Self::filesystem_error)?;
                Self::render(
                    serde_json::json!({
                        "transactions": transactions,
                        "sessionWork": session_work,
                    }),
                    output_format,
                )
            }
            FilesystemOperationKind::TransactionsShow => {
                let target = Self::required("target", target)?;
                let result = match FilesystemTransactionTarget::show(&storage, target) {
                    Ok(transaction) => {
                        serde_json::to_value(transaction).map_err(Self::json_error)?
                    }
                    Err(_) => serde_json::to_value(
                        FilesystemSessionWorkTarget::show(&storage, &session_id, target)
                            .map_err(Self::filesystem_error)?,
                    )
                    .map_err(Self::json_error)?,
                };
                Self::render(result, output_format)
            }
            FilesystemOperationKind::RetentionList => {
                let inventory =
                    FilesystemRetentionInventory::load(&storage).map_err(Self::filesystem_error)?;
                Self::render(inventory, output_format)
            }
            _ => InvalidRequestSnafu {
                reason: String::from("filesystem query operation is not read-only"),
            }
            .fail(),
        }
    }

    pub(crate) fn filesystem_mutation(
        &self,
        owner_uid: u32,
        session_reference: &str,
        operation: i32,
        target: &str,
        name: &str,
        output_format: &str,
    ) -> Result<FilesystemOperationResponse> {
        let session_id = self.resolve_session_reference(owner_uid, session_reference)?;
        let record = self
            .manager
            .inspect(owner_uid, &session_id)
            .context(SessionSnafu)?;
        self.authorize_filesystem_mutation(record.spec(), target)?;
        let storage = self
            .manager
            .filesystem_storage(owner_uid, &session_id)
            .context(SessionSnafu)?;
        match Self::operation(operation)? {
            FilesystemOperationKind::TransactionsCommit => {
                let mut request = FilesystemSessionWorkCommitRequest::user(&session_id)
                    .map_err(Self::filesystem_error)?;
                if !name.trim().is_empty() {
                    request.set_name(name).map_err(Self::filesystem_error)?;
                }
                Self::render(
                    storage
                        .commit_session_work(request)
                        .map_err(Self::filesystem_error)?,
                    output_format,
                )
            }
            FilesystemOperationKind::TransactionsRename => {
                let target = Self::required("target", target)?;
                let name = Self::required("name", name)?;
                let result = match FilesystemTransactionRename::rename(&storage, target, name) {
                    Ok(rename) => serde_json::json!({
                        "handle": rename.handle(),
                        "name": rename.name(),
                    }),
                    Err(_) => {
                        let rename = FilesystemSessionWorkRename::rename(
                            &storage,
                            &session_id,
                            target,
                            name,
                        )
                        .map_err(Self::filesystem_error)?;
                        serde_json::json!({
                            "handle": rename.handle(),
                            "name": rename.name(),
                        })
                    }
                };
                Self::render(result, output_format)
            }
            FilesystemOperationKind::TransactionsRollback => {
                let target = Self::required("target", target)?;
                let result = match FilesystemTransactionRollback::rollback(&storage, target) {
                    Ok(rollback) => serde_json::to_value(rollback).map_err(Self::json_error)?,
                    Err(_) => serde_json::to_value(
                        FilesystemSessionWorkRollback::rollback(&storage, &session_id, target)
                            .map_err(Self::filesystem_error)?,
                    )
                    .map_err(Self::json_error)?,
                };
                Self::render(result, output_format)
            }
            FilesystemOperationKind::RetentionPrune => {
                let target = Self::required("target", target)?;
                Self::render(
                    FilesystemRetentionPrune::prune(&storage, target)
                        .map_err(Self::filesystem_error)?,
                    output_format,
                )
            }
            _ => InvalidRequestSnafu {
                reason: String::from("filesystem mutation operation is not supported"),
            }
            .fail(),
        }
    }

    fn operation(value: i32) -> Result<FilesystemOperationKind> {
        FilesystemOperationKind::try_from(value).map_err(|_error| {
            InvalidRequestSnafu {
                reason: format!("unknown filesystem operation `{value}`"),
            }
            .build()
        })
    }

    fn required<'a>(field: &str, value: &'a str) -> Result<&'a str> {
        if value.trim().is_empty() {
            return InvalidRequestSnafu {
                reason: format!("filesystem {field} must not be empty"),
            }
            .fail();
        }
        Ok(value)
    }

    fn authorize_filesystem_mutation(
        &self,
        spec: &erebor_runtime_core::SessionSpec,
        target: &str,
    ) -> Result<()> {
        let decision = StoredPolicyFileOperationHandler::from_session(
            std::sync::Arc::clone(&self.local_store),
            spec,
        )
        .decide_file_operation(&FileInterceptionRequest::new(
            FileInterceptionOperationKind::Mutation,
            if target.is_empty() {
                "daemon://filesystem/session-work"
            } else {
                target
            },
            "daemon-control",
            0,
            0,
        ));
        let (decision, rule_id, reason, _mediation) = decision.into_parts();
        if decision == SessionInterceptionDecision::Allow {
            return Ok(());
        }
        InvalidRequestSnafu {
            reason: format!(
                "filesystem operation denied by immutable PolicySet rule `{rule_id}`: {reason}"
            ),
        }
        .fail()
    }

    fn render(
        value: impl serde::Serialize,
        output_format: &str,
    ) -> Result<FilesystemOperationResponse> {
        let output = match output_format {
            "json" => serde_json::to_string(&value),
            "text" => serde_json::to_string_pretty(&value),
            _ => {
                return InvalidRequestSnafu {
                    reason: format!("unsupported filesystem output format `{output_format}`"),
                }
                .fail()
            }
        }
        .map_err(Self::json_error)?;
        Ok(FilesystemOperationResponse { output })
    }

    fn filesystem_error(error: erebor_runtime_filesystem::FilesystemError) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: format!("filesystem operation failed: {error}"),
        }
        .build()
    }

    fn json_error(error: serde_json::Error) -> crate::DaemonError {
        InvalidRequestSnafu {
            reason: format!("filesystem operation result cannot be encoded: {error}"),
        }
        .build()
    }
}
