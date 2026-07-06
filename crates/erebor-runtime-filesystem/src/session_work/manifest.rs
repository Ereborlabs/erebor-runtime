use serde::{Deserialize, Serialize};

use super::commit::FilesystemSessionWorkCommitSource;

pub const SESSION_WORK_MANIFEST_FILE: &str = "erebor-session-work.json";
pub const SESSION_WORK_MANIFEST_KIND: &str = "erebor.filesystem.session_work";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemSessionWorkManifest {
    pub kind: String,
    pub version: u32,
    pub session_id: String,
    pub transaction_id: String,
    pub parent_transaction_id: Option<String>,
    pub source: FilesystemSessionWorkCommitSource,
    pub autocommit_rule_id: Option<String>,
    pub action_request_id: Option<String>,
    pub checkpoint_ref: String,
    pub committed_at_unix_ms: u64,
    pub volumes: Vec<FilesystemSessionWorkVolume>,
}

impl FilesystemSessionWorkManifest {
    pub(super) fn new(request: FilesystemSessionWorkManifestRequest) -> Self {
        Self {
            kind: String::from(SESSION_WORK_MANIFEST_KIND),
            version: 1,
            session_id: request.session_id,
            transaction_id: request.transaction_id,
            parent_transaction_id: request.parent_transaction_id,
            source: request.source,
            autocommit_rule_id: request.autocommit_rule_id,
            action_request_id: request.action_request_id,
            checkpoint_ref: request.checkpoint_ref,
            committed_at_unix_ms: request.committed_at_unix_ms,
            volumes: request.volumes,
        }
    }
}

pub(super) struct FilesystemSessionWorkManifestRequest {
    pub(super) session_id: String,
    pub(super) transaction_id: String,
    pub(super) parent_transaction_id: Option<String>,
    pub(super) source: FilesystemSessionWorkCommitSource,
    pub(super) autocommit_rule_id: Option<String>,
    pub(super) action_request_id: Option<String>,
    pub(super) checkpoint_ref: String,
    pub(super) committed_at_unix_ms: u64,
    pub(super) volumes: Vec<FilesystemSessionWorkVolume>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemSessionWorkVolume {
    pub volume_id: String,
    pub layer_ref: String,
}
