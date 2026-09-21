use serde::{Deserialize, Serialize};

use super::{
    DiscoveryDigestV1, DiscoveryInputManifestV1, DiscoveryProofKindV1, DiscoveryRecordIdV1,
};
use crate::{EvidenceIdV1, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryReferenceOwnerV1 {
    Evidence,
    Inventory,
    Policy,
    Finding,
    Notification,
    Approval,
    Activation,
    Response,
    Discovery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReferenceV1 {
    pub tenant_id: EvidenceIdV1,
    pub owner: DiscoveryReferenceOwnerV1,
    pub id: String,
    pub revision: u64,
    pub digest: DiscoveryDigestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryInvestigationScopeV1 {
    pub tenant_id: EvidenceIdV1,
    pub subject: DiscoveryReferenceV1,
    pub lifetime: EvidenceIdV1,
    pub input_digest: DiscoveryDigestV1,
    pub finding: Option<DiscoveryReferenceV1>,
    pub parents: Vec<DiscoveryReferenceV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryDisclosureDestinationV1 {
    LocalOnly,
    HostedRedacted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicyV1 {
    pub principal: String,
    pub revision: u64,
    pub purpose: String,
    pub destination: DiscoveryDisclosureDestinationV1,
    pub allowed_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DiscoveryOwnerFactV1 {
    Available {
        reference: DiscoveryReferenceV1,
        recorded_utc_ns: u64,
        valid_from_utc_ns: u64,
        valid_until_utc_ns: Option<u64>,
    },
    Unsupported {
        owner: DiscoveryReferenceOwnerV1,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPacket {
    pub schema_version: u32,
    pub scope: DiscoveryInvestigationScopeV1,
    pub proof_kind: DiscoveryProofKindV1,
    pub question: String,
    pub cutoff_utc_ns: u64,
    pub disclosure: DisclosurePolicyV1,
    pub records: Vec<DiscoveryRecordIdV1>,
    pub owner_facts: Vec<DiscoveryOwnerFactV1>,
    pub missing_facts: Vec<String>,
    pub complete_coverage: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryMethodV1 {
    pub id: String,
    pub version: String,
    pub parameters_digest: DiscoveryDigestV1,
    pub client_supplied: bool,
}

impl DiscoveryMethodV1 {
    pub(super) fn validate(&self) -> Result<()> {
        require(
            !self.id.trim().is_empty()
                && self.id.len() <= 256
                && !self.version.trim().is_empty()
                && self.version.len() <= 128
                && self.parameters_digest.0 != [0; 32],
            "METHOD_SCHEMA",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryDetectionResultV1 {
    Matched,
    NotMatched,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionAssessment {
    pub scope: DiscoveryInvestigationScopeV1,
    pub method: DiscoveryMethodV1,
    pub result: DiscoveryDetectionResultV1,
    pub supporting: Vec<DiscoveryRecordIdV1>,
    pub refuting: Vec<DiscoveryRecordIdV1>,
    pub unsupported_predicates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryClaimV1 {
    pub id: String,
    pub text: String,
    pub supporting: Vec<DiscoveryRecordIdV1>,
    pub refuting: Vec<DiscoveryRecordIdV1>,
    pub missing_facts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoverySecurityDispositionV1 {
    Expected,
    Suspicious,
    Forbidden,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoverySuggestedPriorityV1 {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationAssessment {
    pub scope: DiscoveryInvestigationScopeV1,
    pub context_digest: DiscoveryDigestV1,
    pub detection_digests: Vec<DiscoveryDigestV1>,
    pub method: DiscoveryMethodV1,
    pub taxonomy_version: String,
    pub activity: String,
    pub suggested_disposition: DiscoverySecurityDispositionV1,
    pub suggested_priority: DiscoverySuggestedPriorityV1,
    pub claims: Vec<DiscoveryClaimV1>,
    pub competing_hypotheses: Vec<String>,
    pub missing_facts: Vec<String>,
    pub abstained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DiscoverySuggestionPayloadV1 {
    GatherEvidence {
        query: DiscoveryDigestV1,
    },
    AskOwner {
        question: String,
    },
    RunReviewedTest {
        fixture: DiscoveryReferenceV1,
    },
    PolicyChange {
        proposal: DiscoveryReferenceV1,
    },
    DetectionDraft {
        method: DiscoveryMethodV1,
    },
    ResponsePlan {
        plan: Option<DiscoveryReferenceV1>,
        unsupported_reason: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoverySuggestionStateV1 {
    Draft,
    Rejected,
    StructurallyValid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestion {
    pub scope: DiscoveryInvestigationScopeV1,
    pub target: DiscoveryReferenceV1,
    pub rationale_claim_ids: Vec<String>,
    pub payload: DiscoverySuggestionPayloadV1,
    pub preconditions: Vec<String>,
    pub risks: Vec<String>,
    pub expected_effect: String,
    pub tests: Vec<DiscoveryReferenceV1>,
    pub required_permission: String,
    pub state: DiscoverySuggestionStateV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryReceipt {
    pub scope: DiscoveryInvestigationScopeV1,
    pub principal: String,
    pub disclosure_revision: u64,
    pub query_digest: DiscoveryDigestV1,
    pub view_version: u32,
    pub read_revision: u64,
    pub result_digest: DiscoveryDigestV1,
    pub returned_rows: u32,
    pub returned_bytes: u32,
    pub complete_result: bool,
    pub records: Vec<DiscoveryRecordIdV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQueryRequestV1 {
    pub sql: String,
    #[serde(default)]
    pub follow: bool,
    pub cursor: Option<String>,
}

impl DiscoveryQueryRequestV1 {
    pub fn validate_shape(&self) -> Result<()> {
        require(
            !self.sql.trim().is_empty() && self.sql.len() <= 16 * 1024,
            "QUERY_SIZE",
        )?;
        require(
            self.cursor
                .as_ref()
                .is_none_or(|cursor| self.follow && !cursor.is_empty() && cursor.len() <= 4096),
            "QUERY_CURSOR",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryFollowPositionV1 {
    pub query_digest: DiscoveryDigestV1,
    pub scope_digest: DiscoveryDigestV1,
    pub disclosure_revision: u64,
    pub view_version: u32,
    pub projection_epoch: u64,
    pub last_scanned_revision: u64,
    pub expires_utc_ns: u64,
}

impl DiscoveryFollowPositionV1 {
    pub fn validate_resume(&self, current: &Self, now_utc_ns: u64) -> Result<()> {
        require(
            self.query_digest == current.query_digest
                && self.scope_digest == current.scope_digest
                && self.disclosure_revision == current.disclosure_revision
                && self.view_version == current.view_version
                && self.projection_epoch == current.projection_epoch,
            "CURSOR_INVALIDATED",
        )?;
        require(
            self.expires_utc_ns > now_utc_ns
                && self.last_scanned_revision <= current.last_scanned_revision,
            "CURSOR_EXPIRED_OR_AHEAD",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentReport {
    pub schema_version: u32,
    pub scope: DiscoveryInvestigationScopeV1,
    pub classification: ClassificationAssessment,
    pub detections: Vec<DetectionAssessment>,
    pub suggestions: Vec<Suggestion>,
    pub query_receipts: Vec<QueryReceipt>,
    pub completed_checks: Vec<String>,
    pub missing_checks: Vec<String>,
}

fn require(valid: bool, code: &'static str) -> Result<()> {
    DiscoveryInputManifestV1::require(valid, code)
}

impl ContextPacket {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= 256 * 1024, "PACKET_LIMIT")?;
        let packet: Self = serde_json::from_slice(bytes).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "PACKET_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.schema_version == 1
                && !self.scope.tenant_id.is_zero()
                && !self.scope.lifetime.is_zero()
                && !self.question.is_empty()
                && self.cutoff_utc_ns > 0
                && self.disclosure.revision > 0
                && !self.disclosure.principal.is_empty()
                && !self.disclosure.purpose.is_empty()
                && self.scope.input_digest.0 != [0; 32],
            "PACKET_SCHEMA",
        )?;
        require(
            self.records.len() <= 100
                && self.owner_facts.len() <= 100
                && self.scope.parents.len() <= 100,
            "PACKET_LIMIT",
        )?;
        for reference in std::iter::once(&self.scope.subject)
            .chain(self.scope.finding.iter())
            .chain(&self.scope.parents)
        {
            self.reference(reference)?;
        }
        require(
            self.scope
                .finding
                .as_ref()
                .is_none_or(|reference| reference.owner == DiscoveryReferenceOwnerV1::Finding),
            "FINDING_OWNER",
        )?;
        for fact in &self.owner_facts {
            match fact {
                DiscoveryOwnerFactV1::Available {
                    reference,
                    recorded_utc_ns,
                    valid_from_utc_ns,
                    valid_until_utc_ns,
                } => {
                    self.reference(reference)?;
                    require(
                        *recorded_utc_ns > 0
                            && *recorded_utc_ns <= self.cutoff_utc_ns
                            && *valid_from_utc_ns > 0
                            && *valid_from_utc_ns <= self.cutoff_utc_ns
                            && valid_until_utc_ns.is_none_or(|end| end > self.cutoff_utc_ns),
                        "OWNER_FACT_VALIDITY",
                    )?;
                }
                DiscoveryOwnerFactV1::Unsupported { reason, .. } => {
                    require(!reason.is_empty(), "UNSUPPORTED_REASON")?
                }
            }
        }
        require(
            self.records.iter().all(|record| {
                record.stream.tenant_id == self.scope.tenant_id.to_be_bytes()
                    && record.durable_cursor > 0
            }),
            "PACKET_RECORD_SCOPE",
        )?;
        serde_json::to_writer(super::model::InputByteLimit(256 * 1024), self).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "PACKET_LIMIT",
                reason: error.to_string(),
            }
            .build()
        })?;
        Ok(())
    }

    pub fn validate_evidence(&self, input: &DiscoveryInputManifestV1) -> Result<()> {
        self.validate()?;
        let derived = super::DiscoveryOwner::default().derive_recorded(input)?;
        require(
            self.scope.tenant_id == input.tenant_id
                && self.proof_kind == input.proof_kind
                && self.scope.input_digest == derived.snapshot.input_digest,
            "PACKET_INPUT",
        )?;
        require(
            !self.complete_coverage
                || derived
                    .snapshot
                    .coverage
                    .iter()
                    .all(|coverage| coverage.state == crate::CoverageStateV1::Healthy),
            "PACKET_COVERAGE",
        )?;
        for citation in &self.records {
            let record = input.records.iter().find(|record| &record.id == citation);
            require(record.is_some(), "UNKNOWN_CITATION")?;
            if let Some(record) = record {
                require(
                    u64::try_from(record.observation.ingested_utc_ns)
                        .is_ok_and(|time| time > 0 && time <= self.cutoff_utc_ns),
                    "PACKET_FUTURE_EVIDENCE",
                )?;
            }
        }
        Ok(())
    }

    pub fn validate_disclosure(&self, current: &DisclosurePolicyV1) -> Result<()> {
        self.validate()?;
        require(self.disclosure == *current, "DISCLOSURE_CHANGED")
    }

    fn known_reference(&self, reference: &DiscoveryReferenceV1) -> Result<()> {
        self.reference(reference)?;
        require(
            reference == &self.scope.subject
                || self.scope.finding.as_ref() == Some(reference)
                || self.scope.parents.contains(reference)
                || self.owner_facts.iter().any(|fact| {
                    matches!(fact,
                    DiscoveryOwnerFactV1::Available { reference: known, .. } if known == reference)
                }),
            "UNKNOWN_REFERENCE",
        )
    }

    fn reference(&self, reference: &DiscoveryReferenceV1) -> Result<()> {
        require(
            reference.tenant_id == self.scope.tenant_id
                && !reference.id.is_empty()
                && reference.id.len() <= 256
                && reference.revision > 0
                && reference.digest.0 != [0; 32],
            "REFERENCE_SCOPE",
        )
    }

    fn citations(&self, references: &[DiscoveryRecordIdV1]) -> Result<()> {
        require(
            references.len() <= 100
                && references
                    .iter()
                    .all(|record| self.records.contains(record)),
            "UNKNOWN_CITATION",
        )
    }
}

impl AssessmentReport {
    pub fn from_json(bytes: &[u8], packet: &ContextPacket) -> Result<Self> {
        require(bytes.len() <= 64 * 1024, "REPORT_LIMIT")?;
        let report: Self = serde_json::from_slice(bytes).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "REPORT_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        report.validate_against(packet)?;
        Ok(report)
    }

    pub fn validate_against(&self, packet: &ContextPacket) -> Result<()> {
        packet.validate()?;
        require(
            self.schema_version == 1
                && self.scope == packet.scope
                && self.classification.scope == packet.scope,
            "REPORT_SCOPE",
        )?;
        require(
            self.classification.context_digest == DiscoveryDigestV1::of(packet)?,
            "CONTEXT_DIGEST",
        )?;
        self.classification.method.validate()?;
        require(
            !self.classification.taxonomy_version.trim().is_empty()
                && !self.classification.activity.trim().is_empty(),
            "CLASSIFICATION_SCHEMA",
        )?;
        require(
            self.detections.len() <= 100
                && self.suggestions.len() <= 100
                && self.query_receipts.len() <= 100
                && self.classification.claims.len() <= 100,
            "REPORT_LIMIT",
        )?;
        serde_json::to_writer(super::model::InputByteLimit(64 * 1024), self).map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "REPORT_LIMIT",
                reason: error.to_string(),
            }
            .build()
        })?;
        let mut claim_ids = std::collections::BTreeSet::new();
        for claim in &self.classification.claims {
            require(
                !claim.id.is_empty() && !claim.text.is_empty() && claim_ids.insert(&claim.id),
                "CLAIM_ID",
            )?;
            packet.citations(&claim.supporting)?;
            packet.citations(&claim.refuting)?;
            require(
                claim
                    .supporting
                    .iter()
                    .all(|id| !claim.refuting.contains(id)),
                "CONTRADICTORY_CITATION",
            )?;
            require(
                !claim.supporting.is_empty()
                    || !claim.refuting.is_empty()
                    || !claim.missing_facts.is_empty(),
                "UNSUPPORTED_CLAIM",
            )?;
        }
        require(
            !self.classification.abstained
                || self.classification.suggested_disposition
                    == DiscoverySecurityDispositionV1::Unknown,
            "ABSTENTION_DISPOSITION",
        )?;
        let detection_digests = self
            .detections
            .iter()
            .map(DiscoveryDigestV1::of)
            .collect::<Result<Vec<_>>>()?;
        require(
            self.classification.detection_digests == detection_digests,
            "DETECTION_DIGESTS",
        )?;
        for detection in &self.detections {
            require(detection.scope == packet.scope, "DETECTION_SCOPE")?;
            detection.method.validate()?;
            packet.citations(&detection.supporting)?;
            packet.citations(&detection.refuting)?;
            require(
                detection
                    .supporting
                    .iter()
                    .all(|id| !detection.refuting.contains(id)),
                "CONTRADICTORY_CITATION",
            )?;
            require(
                detection.result != DiscoveryDetectionResultV1::Matched
                    || !detection.supporting.is_empty(),
                "MATCH_SUPPORT",
            )?;
            require(
                detection.result != DiscoveryDetectionResultV1::NotMatched
                    || (packet.complete_coverage
                        && packet.missing_facts.is_empty()
                        && detection.unsupported_predicates.is_empty()),
                "INCOMPLETE_NEGATIVE",
            )?;
        }
        for receipt in &self.query_receipts {
            require(
                receipt.scope == packet.scope
                    && receipt.principal == packet.disclosure.principal
                    && receipt.disclosure_revision == packet.disclosure.revision
                    && receipt.view_version == 1
                    && receipt.read_revision > 0
                    && receipt.query_digest.0 != [0; 32]
                    && receipt.result_digest.0 != [0; 32]
                    && receipt.returned_rows <= 200
                    && receipt.returned_bytes <= 1024 * 1024,
                "RECEIPT_SCOPE",
            )?;
            packet.citations(&receipt.records)?;
        }
        for suggestion in &self.suggestions {
            require(
                suggestion.scope == packet.scope
                    && !suggestion.required_permission.is_empty()
                    && !suggestion.rationale_claim_ids.is_empty()
                    && suggestion
                        .rationale_claim_ids
                        .iter()
                        .all(|id| claim_ids.contains(id)),
                "SUGGESTION_SCOPE",
            )?;
            packet.known_reference(&suggestion.target)?;
            for reference in &suggestion.tests {
                packet.known_reference(reference)?;
            }
            match &suggestion.payload {
                DiscoverySuggestionPayloadV1::RunReviewedTest { fixture } => {
                    packet.known_reference(fixture)?
                }
                DiscoverySuggestionPayloadV1::PolicyChange { proposal } => {
                    packet.known_reference(proposal)?;
                    require(
                        proposal.owner == DiscoveryReferenceOwnerV1::Discovery,
                        "PROPOSAL_OWNER",
                    )?;
                }
                DiscoverySuggestionPayloadV1::ResponsePlan {
                    plan,
                    unsupported_reason,
                } => {
                    require(
                        plan.is_some() != unsupported_reason.is_some(),
                        "RESPONSE_AVAILABILITY",
                    )?;
                    if let Some(plan) = plan {
                        packet.known_reference(plan)?;
                        require(
                            plan.owner == DiscoveryReferenceOwnerV1::Response,
                            "RESPONSE_OWNER",
                        )?;
                    }
                    require(
                        unsupported_reason
                            .as_ref()
                            .is_none_or(|reason| !reason.is_empty()),
                        "UNSUPPORTED_REASON",
                    )?;
                }
                DiscoverySuggestionPayloadV1::AskOwner { question } => {
                    require(!question.is_empty(), "OWNER_QUESTION")?
                }
                DiscoverySuggestionPayloadV1::GatherEvidence { query } => {
                    require(query.0 != [0; 32], "QUERY_DIGEST")?;
                }
                DiscoverySuggestionPayloadV1::DetectionDraft { method } => method.validate()?,
            }
        }
        Ok(())
    }
}
