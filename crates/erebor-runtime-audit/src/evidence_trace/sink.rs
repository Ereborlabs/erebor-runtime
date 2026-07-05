use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{error::EvidenceWriteFileSnafu, EvidenceTraceError};

use super::{EvidenceTraceReceipt, EvidenceTraceReport};

pub trait EvidenceTraceSink {
    fn send(
        &self,
        report: &EvidenceTraceReport,
    ) -> Result<EvidenceTraceReceipt, EvidenceTraceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEvidenceTraceSink {
    path: PathBuf,
}

impl FileEvidenceTraceSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EvidenceTraceSink for FileEvidenceTraceSink {
    fn send(
        &self,
        report: &EvidenceTraceReport,
    ) -> Result<EvidenceTraceReceipt, EvidenceTraceError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).context(EvidenceWriteFileSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        fs::write(&self.path, report.markdown()).context(EvidenceWriteFileSnafu {
            path: self.path.clone(),
        })?;
        Ok(EvidenceTraceReceipt::new(
            self.path.display().to_string(),
            report.markdown().len(),
            report.sha256(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::evidence_trace::{
        test_support::request_with_record, EvidenceTraceSink, FileEvidenceTraceSink,
        MarkdownEvidenceTraceRenderer,
    };

    #[test]
    fn file_sink_writes_report() -> Result<(), Box<dyn std::error::Error>> {
        let report = MarkdownEvidenceTraceRenderer.render(&request_with_record())?;
        let path = temp_path("evidence-trace.md")?;
        let sink = FileEvidenceTraceSink::new(&path);

        let receipt = sink.send(&report)?;

        assert_eq!(receipt.bytes_written(), report.markdown().len());
        assert!(fs::read_to_string(&path)?.contains("Governed OpenClaw Evidence Trace"));
        let _result = fs::remove_file(path);
        Ok(())
    }

    fn temp_path(filename: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("erebor-runtime-audit-evidence-{nanos}-{filename}")))
    }
}
