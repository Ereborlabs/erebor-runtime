use std::{fs, path::Path};

use snafu::{Location, ResultExt};

use crate::error::{DecodeRecordSnafu, EncodeRecordSnafu, ReadRecordSnafu, WriteRecordSnafu};
use crate::{SessionRegistryError, SessionRegistryRecord};

use super::SESSION_RECORD_FILE;

pub(super) struct SessionRecordIo<'a> {
    root: &'a Path,
}

impl<'a> SessionRecordIo<'a> {
    pub(super) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(super) fn write_record(
        &self,
        record: &SessionRegistryRecord,
    ) -> Result<(), SessionRegistryError> {
        fs::create_dir_all(&record.session_dir).context(crate::error::CreateDirSnafu {
            path: record.session_dir.clone(),
        })?;
        let path = record.session_dir.join(SESSION_RECORD_FILE);
        let source = serde_json::to_string_pretty(record)
            .context(EncodeRecordSnafu { path: path.clone() })?;
        fs::write(&path, format!("{source}\n")).context(WriteRecordSnafu { path })
    }

    pub(super) fn read_record(
        &self,
        path: &Path,
    ) -> Result<SessionRegistryRecord, SessionRegistryError> {
        let source = fs::read_to_string(path).context(ReadRecordSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_str(&source).context(DecodeRecordSnafu {
            path: path.to_path_buf(),
        })
    }

    pub(super) fn list_sessions(&self) -> Result<Vec<SessionRegistryRecord>, SessionRegistryError> {
        let mut records = Vec::new();
        let entries = match fs::read_dir(self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(source) => {
                return Err(SessionRegistryError::ReadRecord {
                    path: self.root.to_path_buf(),
                    source,
                    location: Location::default(),
                });
            }
        };

        for entry in entries {
            let entry = entry.context(ReadRecordSnafu {
                path: self.root.to_path_buf(),
            })?;
            let path = entry.path().join(SESSION_RECORD_FILE);
            if path.exists() {
                records.push(self.read_record(&path)?);
            }
        }

        records.sort_by(|left, right| {
            right
                .started_at_unix_ms
                .cmp(&left.started_at_unix_ms)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        Ok(records)
    }
}
