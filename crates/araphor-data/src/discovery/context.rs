use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::model::{require, same};
use super::*;
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, Error, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextKindV1 {
    Runbook,
    WorkloadOwnership,
    DeploymentChange,
    ReviewedAssessment,
    ThreatReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextTrustV1 {
    Unreviewed,
    Reviewed,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryMethodV1 {
    pub id: String,
    pub revision: u64,
}

impl DiscoveryMethodV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.id.is_empty() && self.id.len() <= 128 && self.revision > 0,
            "method",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextDocumentV1 {
    pub schema_version: u32,
    pub tenant_id: [u8; 16],
    pub id: String,
    pub revision: u64,
    pub kind: DiscoveryContextKindV1,
    pub subject: AnalysisContextKeyV1,
    pub method: DiscoveryMethodV1,
    pub origin: String,
    pub valid_from_utc_ns: u64,
    pub valid_until_utc_ns: Option<u64>,
    pub sensitivity: ContextSensitivityV1,
    pub approver: Option<String>,
    pub text: String,
}

impl DiscoveryContextDocumentV1 {
    pub fn trust(&self) -> DiscoveryContextTrustV1 {
        if self.approver.is_some() {
            DiscoveryContextTrustV1::Reviewed
        } else {
            DiscoveryContextTrustV1::Unreviewed
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.method.validate()?;
        require(
            self.schema_version == DISCOVERY_SCHEMA_VERSION
                && self.tenant_id != [0; 16]
                && self.subject.tenant_id == self.tenant_id
                && self.subject.valid()
                && self.subject.owner_revision > 0
                && !self.id.is_empty()
                && self.id.len() <= 256
                && self.revision > 0
                && !self.origin.is_empty()
                && self.origin.len() <= 1024
                && !self.text.is_empty()
                && self.valid_from_utc_ns > 0
                && self
                    .valid_until_utc_ns
                    .is_none_or(|end| end > self.valid_from_utc_ns)
                && self
                    .approver
                    .as_ref()
                    .is_none_or(|id| !id.is_empty() && id.len() <= 256)
                && (self.kind != DiscoveryContextKindV1::ReviewedAssessment
                    || self.approver.is_some()),
            "context document",
        )
    }
}

impl TryFrom<&[u8]> for DiscoveryContextDocumentV1 {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let document: Self =
            serde_json::from_slice(bytes).context(crate::DiscoveryEncodingSnafu)?;
        document.validate()?;
        Ok(document)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextRevisionV1 {
    pub imported_utc_ns: u64,
    pub document: DiscoveryContextDocumentV1,
}

impl DiscoveryContextRevisionV1 {
    pub fn validate_history(&self, previous: Option<&Self>) -> Result<()> {
        self.validate()?;
        if let Some(previous) = previous {
            require(
                previous.document.tenant_id == self.document.tenant_id
                    && previous.document.id == self.document.id
                    && previous.document.subject == self.document.subject
                    && previous.document.method == self.document.method
                    && previous.document.kind == self.document.kind
                    && previous.document.origin == self.document.origin
                    && previous.imported_utc_ns <= self.imported_utc_ns
                    && previous.document.revision.checked_add(1) == Some(self.document.revision),
                "context revision history",
            )
        } else {
            require(self.document.revision == 1, "first context revision")
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.document.validate()?;
        require(self.imported_utc_ns > 0, "context import time")
    }
}

impl TryFrom<&DiscoveryContextRevisionV1> for AnalysisContextVersionV1 {
    type Error = Error;

    fn try_from(revision: &DiscoveryContextRevisionV1) -> Result<Self> {
        revision.validate()?;
        let document = &revision.document;
        Ok(Self {
            key: AnalysisContextKeyV1 {
                tenant_id: document.tenant_id,
                owner_id: "discovery-context-v1".into(),
                entity_key: document.id.as_bytes().to_vec(),
                lifetime_key: document.subject.lifetime_key.clone(),
                owner_revision: document.revision,
            },
            valid_from_utc_ns: Some(document.valid_from_utc_ns),
            valid_until_utc_ns: document.valid_until_utc_ns,
            sensitivity: document.sensitivity,
            body: serde_json::to_vec(revision).context(crate::DiscoveryEncodingSnafu)?,
        })
    }
}

impl TryFrom<&AnalysisContextVersionV1> for DiscoveryContextRevisionV1 {
    type Error = Error;

    fn try_from(context: &AnalysisContextVersionV1) -> Result<Self> {
        let revision: Self =
            serde_json::from_slice(&context.body).context(crate::DiscoveryEncodingSnafu)?;
        same(
            AnalysisContextVersionV1::try_from(&revision)? == *context,
            "context version",
        )?;
        Ok(revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextAccessV1 {
    pub tenant_id: [u8; 16],
    pub subject: AnalysisContextKeyV1,
    pub principal: String,
    pub grant_revision: u64,
    pub purpose: String,
    pub sensitivities: Vec<ContextSensitivityV1>,
    pub can_import: bool,
    pub can_review: bool,
}

impl DiscoveryContextAccessV1 {
    pub fn validate(&self) -> Result<()> {
        require(
            self.tenant_id != [0; 16]
                && self.subject.tenant_id == self.tenant_id
                && self.subject.valid()
                && self.subject.owner_revision > 0
                && !self.principal.is_empty()
                && self.principal.len() <= 256
                && self.grant_revision > 0
                && !self.purpose.is_empty()
                && self.purpose.len() <= 256
                && self.sensitivities.len() <= 3,
            "context access",
        )
    }

    pub fn permits(&self, document: &DiscoveryContextDocumentV1) -> bool {
        self.tenant_id == document.tenant_id
            && self.subject == document.subject
            && self.sensitivities.contains(&document.sensitivity)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextEvidenceV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub subject: AnalysisContextKeyV1,
    pub received_utc_ns: Option<u64>,
    pub proof_kind: DiscoveryProofKindV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextFactKindV1 {
    SourceHealth,
    PolicyProvenance,
    Inventory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextFactV1 {
    pub kind: DiscoveryContextFactKindV1,
    pub subject: AnalysisContextKeyV1,
    pub context: AnalysisContextVersionV1,
    pub recorded_utc_ns: u64,
    pub trust: DiscoveryContextTrustV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextRequestV1 {
    pub access: DiscoveryContextAccessV1,
    pub method: DiscoveryMethodV1,
    pub from_utc_ns: u64,
    pub cutoff_utc_ns: u64,
    pub question: String,
    pub records: Vec<DiscoveryContextEvidenceV1>,
    pub owner_facts: Vec<DiscoveryContextFactV1>,
    pub missing_facts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextHandleV1 {
    pub key: AnalysisContextKeyV1,
    pub document_id: String,
    pub document_revision: u64,
    pub imported_utc_ns: u64,
    pub origin: String,
    pub kind: DiscoveryContextKindV1,
    pub sensitivity: ContextSensitivityV1,
    pub trust: DiscoveryContextTrustV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextConflictV1 {
    pub kind: DiscoveryContextKindV1,
    pub document_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryContextViewV1 {
    pub selector_version: u32,
    pub access: DiscoveryContextAccessV1,
    pub method: DiscoveryMethodV1,
    pub from_utc_ns: u64,
    pub cutoff_utc_ns: u64,
    pub question: String,
    pub records: Vec<DiscoveryContextEvidenceV1>,
    pub owner_facts: Vec<DiscoveryContextFactV1>,
    pub missing_facts: Vec<String>,
    pub documents: Vec<DiscoveryContextHandleV1>,
    pub available_documents: u64,
    pub source_counts: BTreeMap<String, u64>,
    pub omissions: BTreeMap<String, u64>,
    pub conflicts: Vec<DiscoveryContextConflictV1>,
}
