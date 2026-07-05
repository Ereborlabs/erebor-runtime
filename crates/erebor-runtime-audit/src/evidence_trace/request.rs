use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::ExecutionSurface;
use erebor_runtime_policy::Decision;
use serde_json::Value;
use snafu::ResultExt;

use crate::{error::EvidenceAuditLogSnafu, read_audit_records, EvidenceTraceError};

use super::{EvidenceTraceArtifact, EvidenceTraceArtifactLoader, EvidenceTracePaths};

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceTraceRequest {
    records: Vec<AuditRecord>,
    policy: Value,
    config: Value,
    artifacts: Vec<EvidenceTraceArtifact>,
    session_id: Option<String>,
    purpose: String,
}

impl EvidenceTraceRequest {
    #[must_use]
    pub fn new(
        records: Vec<AuditRecord>,
        policy: Value,
        config: Value,
        artifacts: Vec<EvidenceTraceArtifact>,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            records,
            policy,
            config,
            artifacts,
            session_id: None,
            purpose: purpose.into(),
        }
    }

    pub fn from_paths(paths: EvidenceTracePaths) -> Result<Self, EvidenceTraceError> {
        let records = read_audit_records(&paths.audit).context(EvidenceAuditLogSnafu)?;
        let policy = EvidenceTraceArtifactLoader::read_json(&paths.policy)?;
        let config = EvidenceTraceArtifactLoader::read_json(&paths.config)?;
        let mut artifacts = vec![
            EvidenceTraceArtifactLoader::file_artifact("Audit JSONL", &paths.audit)?,
            EvidenceTraceArtifactLoader::file_artifact("Policy package", &paths.policy)?,
            EvidenceTraceArtifactLoader::file_artifact("Session config", &paths.config)?,
        ];
        if let Some(prompt) = paths.prompt.as_ref() {
            artifacts.push(EvidenceTraceArtifactLoader::file_artifact(
                "Prompt", prompt,
            )?);
        }

        Ok(Self {
            records,
            policy,
            config,
            artifacts,
            session_id: paths.session_id,
            purpose: paths.purpose,
        })
    }

    pub(crate) fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub(crate) fn policy(&self) -> &Value {
        &self.policy
    }

    pub(crate) fn config(&self) -> &Value {
        &self.config
    }

    pub(crate) fn artifacts(&self) -> &[EvidenceTraceArtifact] {
        &self.artifacts
    }

    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub(crate) fn purpose(&self) -> &str {
        &self.purpose
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceTraceSessionSummary {
    pub(crate) last_index: usize,
    pub(crate) record_count: usize,
    pub(crate) browser_count: usize,
    pub(crate) non_allow_count: usize,
}

impl EvidenceTraceSessionSummary {
    pub(crate) fn observe(&mut self, index: usize, record: &AuditRecord) {
        self.last_index = index;
        self.record_count += 1;
        if record.event.surface == ExecutionSurface::BrowserCdp {
            self.browser_count += 1;
        }
        if !matches!(record.final_decision, Decision::Allow { .. }) {
            self.non_allow_count += 1;
        }
    }
}
