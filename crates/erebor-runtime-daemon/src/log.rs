use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RENDERED_MESSAGE_BYTES: usize = 512;

use serde::{Deserialize, Serialize};
use snafu::ResultExt;

use crate::{
    error::{IoSnafu, StateLockSnafu},
    Result,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DaemonLogRecord {
    pub sequence: u64,
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

pub(crate) struct DaemonLogStore {
    path: PathBuf,
    maximum_bytes: u64,
    state: Mutex<DaemonLogState>,
}

struct DaemonLogRenderer;

struct DaemonLogState {
    file: File,
    next_sequence: u64,
}

impl DaemonLogStore {
    pub(crate) fn open(path: PathBuf, maximum_bytes: u64) -> Result<Self> {
        let next_sequence = Self::next_sequence(&path)?;
        let file = Self::open_append(&path)?;
        Ok(Self {
            path,
            maximum_bytes,
            state: Mutex::new(DaemonLogState {
                file,
                next_sequence,
            }),
        })
    }

    pub(crate) fn record(&self, level: &str, message: impl Into<String>) -> Result<()> {
        let mut state = self.lock()?;
        let record = DaemonLogRecord {
            sequence: state.next_sequence,
            timestamp: timestamp(),
            level: level.to_string(),
            message: DaemonLogRenderer::render(message.into()),
        };
        let source =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        let current_bytes = state
            .file
            .metadata()
            .context(IoSnafu {
                action: "inspecting daemon log",
                path: &self.path,
            })?
            .len();
        if current_bytes > 0
            && current_bytes.saturating_add(source.len() as u64 + 1) > self.maximum_bytes
        {
            self.rotate(&mut state)?;
        }
        state.file.write_all(&source).context(IoSnafu {
            action: "writing daemon log",
            path: &self.path,
        })?;
        state.file.write_all(b"\n").context(IoSnafu {
            action: "terminating daemon log record",
            path: &self.path,
        })?;
        state.file.sync_data().context(IoSnafu {
            action: "syncing daemon log",
            path: &self.path,
        })?;
        state.next_sequence = state.next_sequence.saturating_add(1);
        Ok(())
    }

    pub(crate) fn records_after(
        &self,
        after_sequence: u64,
        maximum: usize,
    ) -> Result<Vec<DaemonLogRecord>> {
        let file = File::open(&self.path).context(IoSnafu {
            action: "opening daemon log",
            path: &self.path,
        })?;
        let mut records = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.context(IoSnafu {
                action: "reading daemon log",
                path: &self.path,
            })?;
            let record = serde_json::from_str::<DaemonLogRecord>(&line).map_err(|source| {
                crate::DaemonError::InvalidConfig {
                    path: self.path.clone(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            if record.sequence > after_sequence {
                records.push(record);
            }
            if records.len() == maximum {
                break;
            }
        }
        Ok(records)
    }

    fn rotate(&self, state: &mut DaemonLogState) -> Result<()> {
        state.file.sync_all().context(IoSnafu {
            action: "syncing daemon log before rotation",
            path: &self.path,
        })?;
        let rotated = self.path.with_extension("jsonl.1");
        if rotated.exists() {
            fs::remove_file(&rotated).context(IoSnafu {
                action: "removing rotated daemon log",
                path: &rotated,
            })?;
        }
        fs::rename(&self.path, &rotated).context(IoSnafu {
            action: "rotating daemon log",
            path: &self.path,
        })?;
        state.file = Self::open_append(&self.path)?;
        Ok(())
    }

    fn open_append(path: &PathBuf) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o640)
            .open(path)
            .context(IoSnafu {
                action: "opening daemon log for append",
                path,
            })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).context(IoSnafu {
            action: "setting daemon log permissions",
            path,
        })?;
        Ok(file)
    }

    fn next_sequence(path: &PathBuf) -> Result<u64> {
        if !path.exists() {
            return Ok(1);
        }
        let file = File::open(path).context(IoSnafu {
            action: "opening daemon log for sequence recovery",
            path,
        })?;
        let mut sequence = 1;
        for line in BufReader::new(file).lines() {
            let line = line.context(IoSnafu {
                action: "reading daemon log for sequence recovery",
                path,
            })?;
            let record = serde_json::from_str::<DaemonLogRecord>(&line).map_err(|source| {
                crate::DaemonError::InvalidConfig {
                    path: path.clone(),
                    source,
                    location: snafu::Location::default(),
                }
            })?;
            sequence = sequence.max(record.sequence.saturating_add(1));
        }
        Ok(sequence)
    }

    fn lock(&self) -> Result<MutexGuard<'_, DaemonLogState>> {
        self.state.lock().map_err(|_error| StateLockSnafu.build())
    }
}

impl DaemonLogRenderer {
    fn render(message: String) -> String {
        if Self::has_sensitive_label(&message) {
            return String::from("[redacted sensitive daemon diagnostic]");
        }
        if message.len() <= MAX_RENDERED_MESSAGE_BYTES {
            return message;
        }
        let end = message
            .char_indices()
            .take_while(|(index, _)| *index < MAX_RENDERED_MESSAGE_BYTES)
            .map(|(index, character)| index + character.len_utf8())
            .last()
            .unwrap_or_default();
        format!("{}…", &message[..end])
    }

    fn has_sensitive_label(message: &str) -> bool {
        let message = message.to_ascii_lowercase();
        [
            "secret",
            "credential",
            "password",
            "token",
            "ticket",
            "payload",
        ]
        .iter()
        .any(|label| message.contains(label))
    }
}

fn timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}.{}", duration.as_secs(), duration.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt};

    use tempfile::TempDir;

    use super::DaemonLogStore;

    #[test]
    fn daemon_logs_redact_sensitive_diagnostics_and_are_not_world_readable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("daemon.jsonl");
        let store = DaemonLogStore::open(path.clone(), 4096)?;
        store.record(
            "WARN",
            "secret=configuration-secret credential=registry-secret token=package-secret ticket=hook-secret payload=workload-secret",
        )?;

        let record = store.records_after(0, 1)?.remove(0);
        assert_eq!(record.message, "[redacted sensitive daemon diagnostic]");
        assert!(!fs::read_to_string(&path)?.contains("configuration-secret"));
        assert_eq!(fs::metadata(&path)?.mode() & 0o077, 0o040);
        Ok(())
    }

    #[test]
    fn daemon_log_sequence_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let root = TempDir::new()?;
        let path = root.path().join("daemon.jsonl");
        let store = DaemonLogStore::open(path.clone(), 4096)?;
        store.record("INFO", "first")?;
        drop(store);

        let resumed = DaemonLogStore::open(path, 4096)?;
        resumed.record("INFO", "second")?;
        let records = resumed.records_after(0, 2)?;
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[1].sequence, 2);
        Ok(())
    }
}
