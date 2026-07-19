use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ResultExt;

use crate::{
    config::DaemonConfig,
    error::{IdempotencyCapacitySnafu, IdempotencyConflictSnafu, IoSnafu},
    Result,
};

pub(crate) struct DaemonIdempotencyStore {
    directory: PathBuf,
    capacity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyAction {
    Execute(MutationIntent),
    ResumePending(MutationIntent),
    ReturnCompleted(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum MutationIntent {
    Reload {
        configuration: DaemonConfig,
        generation: u64,
    },
    Stop,
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
    message: Option<String>,
}

#[derive(Deserialize, Serialize)]
enum MutationState {
    Pending,
    Completed,
}

impl DaemonIdempotencyStore {
    pub(crate) fn new(directory: PathBuf, capacity: usize) -> Self {
        Self {
            directory,
            capacity,
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
                MutationState::Pending => IdempotencyAction::ResumePending(record.intent),
                MutationState::Completed => {
                    IdempotencyAction::ReturnCompleted(record.message.unwrap_or_default())
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
                message: None,
            },
        )?;
        Ok(IdempotencyAction::Execute(intent))
    }

    pub(crate) fn complete(
        &self,
        uid: u32,
        operation: &str,
        key: &str,
        fingerprint: [u8; 32],
        intent: MutationIntent,
        message: String,
    ) -> Result<()> {
        let path = self.record_path(uid, operation, key);
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
                message: Some(message),
            },
        )
    }

    fn make_room(&self) -> Result<()> {
        let mut records = self.record_paths()?;
        while records.len() >= self.capacity {
            let mut oldest_completed = None;
            for (index, path) in records.iter().enumerate() {
                let record = self.read_record(path)?;
                if matches!(record.state, MutationState::Completed) {
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

fn modified_at(path: &Path) -> SystemTime {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
