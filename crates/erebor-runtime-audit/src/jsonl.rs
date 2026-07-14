use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use erebor_runtime_core::{AuditError, AuditRecord, AuditSink, DurableAuditSink};
use erebor_runtime_telemetry::debug;
use snafu::{Location, ResultExt};

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
        append_audit_record(&self.path, record).map_err(audit_sink_error)
    }
}

impl DurableAuditSink for JsonlAuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError> {
        append_durable_audit_record(&self.path, record).map_err(audit_sink_error)
    }
}

pub fn append_audit_record(
    path: impl AsRef<Path>,
    record: &AuditRecord,
) -> Result<(), AuditLogError> {
    append_record(path.as_ref(), record, false)
}

/// Append one audit record and confirm the file's local data durability before success.
pub fn append_durable_audit_record(
    path: impl AsRef<Path>,
    record: &AuditRecord,
) -> Result<(), AuditLogError> {
    append_record(path.as_ref(), record, true)
}

fn append_record(path: &Path, record: &AuditRecord, durable: bool) -> Result<(), AuditLogError> {
    debug!(
        path = %path.display(),
        session_id = %record.event.session_id.as_str(),
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

    write_audit_record(path, record, &mut file, durable)?;

    Ok(())
}

fn write_audit_record(
    path: &Path,
    record: &AuditRecord,
    file: &mut impl AuditAppendFile,
    durable: bool,
) -> Result<(), AuditLogError> {
    serde_json::to_writer(&mut *file, record).context(AuditSerializeRecordSnafu {
        path: path.to_path_buf(),
    })?;
    file.write_all(b"\n").context(AuditWriteSnafu {
        path: path.to_path_buf(),
    })?;
    file.flush().context(AuditWriteSnafu {
        path: path.to_path_buf(),
    })?;
    if durable {
        file.sync_data().context(AuditWriteSnafu {
            path: path.to_path_buf(),
        })?;
    }
    Ok(())
}

fn audit_sink_error(error: AuditLogError) -> AuditError {
    AuditError::SinkUnavailable {
        reason: error.to_string(),
        location: Location::default(),
    }
}

trait AuditAppendFile: Write {
    fn sync_data(&self) -> io::Result<()>;
}

impl AuditAppendFile for File {
    fn sync_data(&self) -> io::Result<()> {
        File::sync_data(self)
    }
}

pub fn read_audit_records(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, AuditLogError> {
    let path = path.as_ref();
    debug!("reading audit records", path = %path.display());
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

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use erebor_runtime_core::AuditRecord;

    use super::{write_audit_record, AuditAppendFile};
    use crate::tests::audit_record;
    use crate::AuditLogError;

    #[derive(Clone, Copy)]
    enum FailurePoint {
        Write,
        Flush,
        Sync,
    }

    struct FailingAuditFile {
        failure: FailurePoint,
    }

    impl Write for FailingAuditFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if matches!(self.failure, FailurePoint::Write) {
                return Err(io::Error::other("write failed"));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if matches!(self.failure, FailurePoint::Flush) {
                return Err(io::Error::other("flush failed"));
            }
            Ok(())
        }
    }

    impl AuditAppendFile for FailingAuditFile {
        fn sync_data(&self) -> io::Result<()> {
            if matches!(self.failure, FailurePoint::Sync) {
                return Err(io::Error::other("sync failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn durable_append_surfaces_write_flush_and_sync_failures() {
        let record: AuditRecord = audit_record(
            "evt-durable",
            erebor_runtime_policy::Decision::Allow { rule_id: None },
        );
        for failure in [FailurePoint::Write, FailurePoint::Flush, FailurePoint::Sync] {
            let mut file = FailingAuditFile { failure };
            let result = write_audit_record(
                std::path::Path::new("audit.jsonl"),
                &record,
                &mut file,
                true,
            );
            match failure {
                FailurePoint::Write => {
                    assert!(matches!(result, Err(AuditLogError::SerializeRecord { .. })));
                }
                FailurePoint::Flush | FailurePoint::Sync => {
                    assert!(matches!(result, Err(AuditLogError::Write { .. })));
                }
            }
        }
    }
}
