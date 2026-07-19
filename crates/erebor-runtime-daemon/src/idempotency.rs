use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::ResultExt;

use crate::{
    error::{IdempotencyConflictSnafu, IoSnafu},
    Result,
};

pub(crate) struct DaemonIdempotencyStore {
    directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyAction {
    Execute,
    ReturnCompleted(String),
}

#[derive(Deserialize, Serialize)]
struct MutationRecord {
    fingerprint: String,
    state: MutationState,
    message: Option<String>,
}

#[derive(Deserialize, Serialize)]
enum MutationState {
    Pending,
    Completed,
}

impl DaemonIdempotencyStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub(crate) fn prepare(
        &self,
        uid: u32,
        operation: &str,
        key: &str,
        fingerprint: [u8; 32],
    ) -> Result<IdempotencyAction> {
        let path = self.record_path(uid, operation, key);
        let expected = hex(fingerprint);
        if path.exists() {
            let source = fs::read(&path).context(IoSnafu {
                action: "reading daemon idempotency record",
                path: &path,
            })?;
            let record: MutationRecord = serde_json::from_slice(&source).map_err(|source| {
                crate::DaemonError::InvalidConfig {
                    path: path.clone(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            if record.fingerprint != expected {
                return IdempotencyConflictSnafu.fail();
            }
            return Ok(match record.state {
                MutationState::Pending => IdempotencyAction::Execute,
                MutationState::Completed => {
                    IdempotencyAction::ReturnCompleted(record.message.unwrap_or_default())
                }
            });
        }

        self.write_record(
            &path,
            &MutationRecord {
                fingerprint: expected,
                state: MutationState::Pending,
                message: None,
            },
        )?;
        Ok(IdempotencyAction::Execute)
    }

    pub(crate) fn complete(
        &self,
        uid: u32,
        operation: &str,
        key: &str,
        fingerprint: [u8; 32],
        message: String,
    ) -> Result<()> {
        let path = self.record_path(uid, operation, key);
        self.write_record(
            &path,
            &MutationRecord {
                fingerprint: hex(fingerprint),
                state: MutationState::Completed,
                message: Some(message),
            },
        )
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

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
