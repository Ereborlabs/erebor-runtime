use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ResultExt;

use crate::{
    config::DaemonConfig,
    error::{IdempotencyCapacitySnafu, IdempotencyConflictSnafu, IoSnafu},
    Result,
};
use erebor_runtime_core::{ActiveSessionSignal, SessionSpec};
use erebor_runtime_packages::PolicyPackageRevision;

pub(crate) struct DaemonIdempotencyStore {
    directory: PathBuf,
    session_state_root: PathBuf,
    capacity: usize,
    retry_horizon: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyAction {
    Execute(Box<MutationIntent>),
    ResumePending(Box<MutationIntent>),
    ReturnCompleted(MutationResponse),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum MutationIntent {
    Reload {
        configuration: DaemonConfig,
        generation: u64,
    },
    Stop,
    SessionCreate {
        spec: Box<SessionSpec>,
    },
    SessionStart {
        uid: u32,
        session_id: String,
    },
    SessionStop {
        uid: u32,
        session_id: String,
        grace_period_seconds: u64,
    },
    SessionKill {
        uid: u32,
        session_id: String,
        signal: ActiveSessionSignal,
    },
    SessionRemove {
        uid: u32,
        session_id: String,
        force: bool,
    },
    SessionAttach {
        uid: u32,
        session_id: String,
        request_input_lease: bool,
        client_instance_id: String,
    },
    SessionInputLeaseRenew {
        uid: u32,
        session_id: String,
        lease_id: String,
        client_instance_id: String,
    },
    SessionInputLeaseRelease {
        uid: u32,
        session_id: String,
        lease_id: String,
        client_instance_id: String,
    },
    SessionPrune {
        uid: u32,
        terminal_before_unix_ms: u64,
        maximum_sessions: u32,
    },
    SessionAliasSet {
        uid: u32,
        alias: String,
        session_id: String,
    },
    SessionAliasRemove {
        uid: u32,
        alias: String,
    },
    SessionSetRetentionHold {
        uid: u32,
        session_id: String,
        retention_hold: bool,
    },
    ApprovalApprove {
        owner_uid: u32,
        approval_id: String,
    },
    ApprovalDeny {
        owner_uid: u32,
        approval_id: String,
        reason: String,
    },
    PolicyPackageApply {
        uid: u32,
        policy: PolicyPackageRevision,
    },
    PolicySetCreate {
        uid: u32,
        root_minimum_digest: String,
        package_minimum_digests: Vec<String>,
        local_override_digest: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct MutationResponse {
    pub(crate) message_kind: String,
    pub(crate) payload: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct MutationScope {
    uid: u32,
    operation: String,
    key: String,
}

#[derive(Deserialize, Serialize)]
struct MutationRecord {
    scope: MutationScope,
    fingerprint: String,
    state: MutationState,
    intent: MutationIntent,
    response: Option<MutationResponse>,
    completed_at_unix_ms: Option<u64>,
    retain_until_unix_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
enum MutationState {
    Pending,
    Completed,
}

impl DaemonIdempotencyStore {
    pub(crate) fn new(
        directory: PathBuf,
        session_state_root: PathBuf,
        capacity: usize,
        retry_horizon: Duration,
    ) -> Self {
        Self {
            directory,
            session_state_root,
            capacity,
            retry_horizon,
        }
    }

    pub(crate) fn prepare(
        &self,
        uid: u32,
        operation: &str,
        key: &str,
        fingerprint: [u8; 32],
        intent: MutationIntent,
    ) -> Result<IdempotencyAction> {
        let path = self.record_path(uid, operation, key);
        let expected = hex(fingerprint);
        if path.exists() {
            let record = self.read_record(&path)?;
            if record.fingerprint != expected
                || record.scope.uid != uid
                || record.scope.operation != operation
                || record.scope.key != key
            {
                return IdempotencyConflictSnafu.fail();
            }
            return Ok(match record.state {
                MutationState::Pending => IdempotencyAction::ResumePending(Box::new(record.intent)),
                MutationState::Completed => {
                    let response = record.response.ok_or_else(|| {
                        crate::error::InvalidRequestSnafu {
                            reason: format!(
                                "completed idempotency record `{}` has no response",
                                path.display()
                            ),
                        }
                        .build()
                    })?;
                    IdempotencyAction::ReturnCompleted(response)
                }
            });
        }

        self.make_room()?;
        self.write_record(
            &path,
            &MutationRecord {
                scope: MutationScope {
                    uid,
                    operation: operation.to_string(),
                    key: key.to_string(),
                },
                fingerprint: expected,
                state: MutationState::Pending,
                intent: intent.clone(),
                response: None,
                completed_at_unix_ms: None,
                retain_until_unix_ms: None,
            },
        )?;
        Ok(IdempotencyAction::Execute(Box::new(intent)))
    }

    pub(crate) fn complete(
        &self,
        uid: u32,
        operation: &str,
        key: &str,
        fingerprint: [u8; 32],
        intent: MutationIntent,
        response: MutationResponse,
    ) -> Result<()> {
        let path = self.record_path(uid, operation, key);
        let completed_at_unix_ms = unix_time_ms();
        self.write_record(
            &path,
            &MutationRecord {
                scope: MutationScope {
                    uid,
                    operation: operation.to_string(),
                    key: key.to_string(),
                },
                fingerprint: hex(fingerprint),
                state: MutationState::Completed,
                intent,
                response: Some(response),
                completed_at_unix_ms: Some(completed_at_unix_ms),
                retain_until_unix_ms: Some(
                    completed_at_unix_ms.saturating_add(self.retry_horizon.as_millis() as u64),
                ),
            },
        )
    }

    fn make_room(&self) -> Result<()> {
        let mut records = self.record_paths()?;
        while records.len() >= self.capacity {
            let mut oldest_completed = None;
            for (index, path) in records.iter().enumerate() {
                let record = self.read_record(path)?;
                if matches!(record.state, MutationState::Completed)
                    && self.record_can_be_released(&record)
                {
                    let modified_at = modified_at(path);
                    if oldest_completed
                        .as_ref()
                        .is_none_or(|(_, oldest)| modified_at < *oldest)
                    {
                        oldest_completed = Some((index, modified_at));
                    }
                }
            }
            let Some((index, _modified_at)) = oldest_completed else {
                return IdempotencyCapacitySnafu {
                    capacity: self.capacity,
                }
                .fail();
            };
            let path = records.remove(index);
            fs::remove_file(&path).context(IoSnafu {
                action: "evicting completed daemon idempotency record",
                path: &path,
            })?;
        }
        Ok(())
    }

    fn record_can_be_released(&self, record: &MutationRecord) -> bool {
        let now = unix_time_ms();
        if record.retain_until_unix_ms.is_none_or(|until| until > now) {
            return false;
        }
        let Some((uid, session_id)) = record.intent.session_scope() else {
            return true;
        };
        let session_directory = self
            .session_state_root
            .join("users")
            .join(uid.to_string())
            .join("sessions")
            .join(session_id);
        if session_directory.join("output").exists() {
            return false;
        }
        let path = session_directory.join("session.json");
        let Ok(source) = fs::read(path) else {
            return false;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&source) else {
            return false;
        };
        let removed = value.get("state").and_then(serde_json::Value::as_str) == Some("removed");
        let tombstone_horizon = value
            .get("updated_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .map(|updated| updated.saturating_add(self.retry_horizon.as_millis() as u64));
        removed && tombstone_horizon.is_some_and(|until| until <= now)
    }

    fn record_paths(&self) -> Result<Vec<PathBuf>> {
        let entries = fs::read_dir(&self.directory).context(IoSnafu {
            action: "reading daemon idempotency directory",
            path: &self.directory,
        })?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.context(IoSnafu {
                action: "reading daemon idempotency directory entry",
                path: &self.directory,
            })?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                records.push(path);
            }
        }
        Ok(records)
    }

    fn read_record(&self, path: &Path) -> Result<MutationRecord> {
        let source = fs::read(path).context(IoSnafu {
            action: "reading daemon idempotency record",
            path,
        })?;
        serde_json::from_slice(&source).map_err(|source| crate::DaemonError::InvalidConfig {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })
    }

    fn record_path(&self, uid: u32, operation: &str, key: &str) -> PathBuf {
        let mut digest = Sha256::new();
        digest.update(b"erebor.daemon.idempotency.v1\0");
        digest.update(uid.to_le_bytes());
        digest.update(operation.as_bytes());
        digest.update([0]);
        digest.update(key.as_bytes());
        self.directory
            .join(format!("{}.json", hex(digest.finalize())))
    }

    fn write_record(&self, path: &Path, record: &MutationRecord) -> Result<()> {
        let encoded =
            serde_json::to_vec(record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: path.to_path_buf(),
                source,
                location: snafu::Location::default(),
            })?;
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .context(IoSnafu {
                action: "writing daemon idempotency record",
                path: &temporary,
            })?;
        file.write_all(&encoded).context(IoSnafu {
            action: "writing daemon idempotency record",
            path: &temporary,
        })?;
        file.sync_all().context(IoSnafu {
            action: "syncing daemon idempotency record",
            path: &temporary,
        })?;
        fs::rename(&temporary, path).context(IoSnafu {
            action: "publishing daemon idempotency record",
            path,
        })?;
        File::open(&self.directory)
            .context(IoSnafu {
                action: "opening daemon idempotency directory",
                path: &self.directory,
            })?
            .sync_all()
            .context(IoSnafu {
                action: "syncing daemon idempotency directory",
                path: &self.directory,
            })
    }
}

impl MutationIntent {
    pub(crate) fn session_scope(&self) -> Option<(u32, &str)> {
        match self {
            Self::SessionCreate { spec } => Some((spec.owner().uid(), spec.session_id().as_str())),
            Self::SessionStart { uid, session_id }
            | Self::SessionStop {
                uid, session_id, ..
            }
            | Self::SessionKill {
                uid, session_id, ..
            }
            | Self::SessionRemove {
                uid, session_id, ..
            }
            | Self::SessionAttach {
                uid, session_id, ..
            }
            | Self::SessionInputLeaseRenew {
                uid, session_id, ..
            }
            | Self::SessionInputLeaseRelease {
                uid, session_id, ..
            }
            | Self::SessionSetRetentionHold {
                uid, session_id, ..
            } => Some((*uid, session_id)),
            Self::Reload { .. }
            | Self::Stop
            | Self::SessionPrune { .. }
            | Self::SessionAliasSet { .. }
            | Self::SessionAliasRemove { .. }
            | Self::ApprovalApprove { .. }
            | Self::ApprovalDeny { .. }
            | Self::PolicyPackageApply { .. }
            | Self::PolicySetCreate { .. } => None,
        }
    }
}

fn modified_at(path: &Path) -> SystemTime {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
