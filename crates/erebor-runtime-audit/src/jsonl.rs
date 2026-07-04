use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use erebor_runtime_core::{AuditError, AuditRecord, AuditSink};
use snafu::{Location, ResultExt};
use tracing::debug;

use crate::error::{
    AuditInvalidRecordSnafu, AuditOpenSnafu, AuditReadSnafu, AuditSerializeRecordSnafu,
    AuditWriteSnafu,
};
use crate::AuditLogError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonlAuditSink {
    path: PathBuf,
}

impl JsonlAuditSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        append_audit_record(&self.path, record).map_err(|error| AuditError::SinkUnavailable {
            reason: error.to_string(),
            location: Location::default(),
        })
    }
}

pub fn append_audit_record(
    path: impl AsRef<Path>,
    record: &AuditRecord,
) -> Result<(), AuditLogError> {
    let path = path.as_ref();
    debug!(
        path = %path.display(),
        event_id = record.event.id.as_str(),
        "appending audit record"
    );
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context(AuditOpenSnafu {
            path: path.to_path_buf(),
        })?;

    serde_json::to_writer(&mut file, record).context(AuditSerializeRecordSnafu {
        path: path.to_path_buf(),
    })?;
    file.write_all(b"\n").context(AuditWriteSnafu {
        path: path.to_path_buf(),
    })?;
    file.flush().context(AuditWriteSnafu {
        path: path.to_path_buf(),
    })?;

    Ok(())
}

pub fn read_audit_records(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, AuditLogError> {
    let path = path.as_ref();
    debug!(path = %path.display(), "reading audit records");
    let file = File::open(path).context(AuditOpenSnafu {
        path: path.to_path_buf(),
    })?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.context(AuditReadSnafu {
            path: path.to_path_buf(),
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str(&line).context(AuditInvalidRecordSnafu {
            path: path.to_path_buf(),
            line: index + 1,
        })?;
        records.push(record);
    }

    debug!(
        path = %path.display(),
        record_count = records.len(),
        "read audit records"
    );
    Ok(records)
}
