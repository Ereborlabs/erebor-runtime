#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceReport {
    session_id: String,
    markdown: String,
    sha256: String,
}

impl EvidenceTraceReport {
    #[must_use]
    pub(crate) fn new(
        session_id: impl Into<String>,
        markdown: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            markdown: markdown.into(),
            sha256: sha256.into(),
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.markdown
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTraceReceipt {
    destination: String,
    bytes_written: usize,
    report_sha256: String,
}

impl EvidenceTraceReceipt {
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        bytes_written: usize,
        report_sha256: impl Into<String>,
    ) -> Self {
        Self {
            destination: destination.into(),
            bytes_written,
            report_sha256: report_sha256.into(),
        }
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    #[must_use]
    pub fn report_sha256(&self) -> &str {
        &self.report_sha256
    }
}
