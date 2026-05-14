use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use erebor_runtime_core::{AuditError, AuditRecord, AuditSink};

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
        append_audit_record(&self.path, record)
            .map_err(|error| AuditError::unavailable(error.to_string()))
    }
}

pub fn append_audit_record(
    path: impl AsRef<Path>,
    record: &AuditRecord,
) -> Result<(), AuditLogError> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| AuditLogError::open(path.to_path_buf(), source))?;

    serde_json::to_writer(&mut file, record)
        .map_err(|source| AuditLogError::serialize_record(path.to_path_buf(), source))?;
    file.write_all(b"\n")
        .map_err(|source| AuditLogError::write(path.to_path_buf(), source))?;
    file.flush()
        .map_err(|source| AuditLogError::write(path.to_path_buf(), source))?;

    Ok(())
}

pub fn read_audit_records(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, AuditLogError> {
    let path = path.as_ref();
    let file =
        File::open(path).map_err(|source| AuditLogError::open(path.to_path_buf(), source))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| AuditLogError::read(path.to_path_buf(), source))?;

        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str(&line).map_err(|source| {
            AuditLogError::invalid_record(path.to_path_buf(), index + 1, source)
        })?;
        records.push(record);
    }

    Ok(records)
}
