use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

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

struct DaemonLogState {
    file: File,
    next_sequence: u64,
}

impl DaemonLogStore {
    pub(crate) fn open(path: PathBuf, maximum_bytes: u64) -> Result<Self> {
        let file = Self::open_append(&path)?;
        Ok(Self {
            path,
            maximum_bytes,
            state: Mutex::new(DaemonLogState {
                file,
                next_sequence: 1,
            }),
        })
    }

    pub(crate) fn record(&self, level: &str, message: impl Into<String>) -> Result<()> {
        let mut state = self.lock()?;
        if state
            .file
            .metadata()
            .context(IoSnafu {
                action: "inspecting daemon log",
                path: &self.path,
            })?
            .len()
            >= self.maximum_bytes
        {
            self.rotate(&mut state)?;
        }
        let record = DaemonLogRecord {
            sequence: state.next_sequence,
            timestamp: timestamp(),
            level: level.to_string(),
            message: message.into(),
        };
        let source =
            serde_json::to_vec(&record).map_err(|source| crate::DaemonError::InvalidConfig {
                path: self.path.clone(),
                source,
                location: snafu::Location::default(),
            })?;
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
        OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .context(IoSnafu {
                action: "opening daemon log for append",
                path,
            })
    }

    fn lock(&self) -> Result<MutexGuard<'_, DaemonLogState>> {
        self.state.lock().map_err(|_error| StateLockSnafu.build())
    }
}

fn timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}.{}", duration.as_secs(), duration.subsec_nanos())
}
