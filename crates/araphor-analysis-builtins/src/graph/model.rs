use serde::{Deserialize, Serialize};

mod domain;
mod memory;
mod proof;
mod reason;
mod resolved;

pub use domain::*;
pub use proof::*;
pub use resolved::*;

use crate::discovery::{DiscoveryEffectKeyV1, DiscoveryRecordIdV1};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub commit_revision: u64,
    pub ordinal: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: DiscoveryRecordIdV1,
    pub position: Position,
    pub effect: DiscoveryEffectKeyV1,
    pub ingested_utc_ns: i64,
    pub observed_boottime_ns: u64,
    pub profile_generation_ref_id: Option<u64>,
    pub original_kernel_sequence: Option<u64>,
    pub coverage_interval_id: Vec<u8>,
    pub process_instance_id: Option<[u8; 16]>,
    pub entry_instance_id: Option<[u8; 16]>,
    pub binding_id: Option<[u8; 16]>,
    pub role_id: Option<u32>,
    pub state_id: Option<u32>,
    pub entry_rule_id: Option<u32>,
    pub proof_quality: ProofQualityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Operation {
    OpenRead,
    Read,
    MmapRead,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Physical {
    Prevented,
    PacketDropped,
    TerminationQueued,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub record: u32,
    pub key: AnalysisContextKeyV1,
    pub sensitivity: ContextSensitivityV1,
    pub value: GraphFactValueV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub window_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub record_ids: Vec<DiscoveryRecordIdV1>,
    pub facts: Vec<Fact>,
    pub package: GraphPackageCheckpointV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub record: u32,
    pub context: Option<u32>,
    pub key: GraphSubjectKeyV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum EdgeKind {
    Process,
    ExecutionSet,
    Object,
    Parent,
    Authority,
    Kubernetes,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Cause {
    Direct,
    Contextual,
    Contradicted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub record: u32,
    pub fact: Option<u32>,
    pub edge: GraphEdgeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub record: u32,
    pub context: Option<u32>,
    pub tenant_id: [u8; 16],
    pub finding_id: String,
    pub package_id: String,
    pub package_version: u64,
    pub subject_id: GraphSubjectKeyV1,
    pub state: FindingStateV1,
    pub window_start_utc_ns: i64,
    pub window_end_utc_ns: i64,
    pub evidence: Vec<DiscoveryRecordIdV1>,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub policy_provenance: Vec<PolicyObservationProvenanceV1>,
    pub effects: Vec<GraphEffectV1>,
    pub reason_code: String,
    pub severity: FindingSeverityV1,
    pub sensitivity: ContextSensitivityV1,
    pub required_action: Option<String>,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRemoval {
    pub finding_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRemoval {
    pub key: GraphSubjectKeyV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectChange {
    pub anchor: Anchor,
    pub key: GraphSubjectKeyV1,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipIdentity {
    pub from: GraphSubjectKeyV1,
    pub to: GraphSubjectKeyV1,
    pub edge_type: GraphEdgeTypeV1,
    pub package_id: String,
    pub evidence: Vec<DiscoveryRecordIdV1>,
    pub cause: GraphCauseV1,
}

impl RelationshipIdentity {
    pub fn from_keys(
        edge: &GraphEdgeKeyV1,
        subjects: &[GraphSubjectKeyV1],
        records: &[DiscoveryRecordIdV1],
    ) -> super::sdk::Result<Self> {
        let subject = |index: u32| {
            subjects
                .get(index as usize)
                .cloned()
                .ok_or_else(|| super::Computation::invalid("graph relationship subject"))
        };
        let mut evidence = edge
            .evidence
            .iter()
            .map(|&index| {
                records
                    .get(index as usize)
                    .cloned()
                    .ok_or_else(|| super::Computation::invalid("graph relationship evidence"))
            })
            .collect::<super::sdk::Result<Vec<_>>>()?;
        evidence.sort();
        evidence.dedup();
        Ok(Self {
            from: subject(edge.from)?,
            to: subject(edge.to)?,
            edge_type: edge.edge_type,
            package_id: edge.package_id.clone(),
            evidence,
            cause: edge.cause,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipRemoval {
    pub key: RelationshipIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipChange {
    pub anchor: Anchor,
    pub key: RelationshipIdentity,
    pub proof_quality: ProofQualityV1,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub first_boottime_ns: u64,
    pub last_boottime_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingChange {
    pub anchor: Anchor,
    pub prior_reason: Option<FindingReasonV1>,
    pub tenant_id: [u8; 16],
    pub finding_id: String,
    pub package_id: String,
    pub package_version: u64,
    pub subject_id: GraphSubjectKeyV1,
    pub state: FindingStateV1,
    pub window_start_utc_ns: i64,
    pub window_end_utc_ns: i64,
    pub evidence: Vec<DiscoveryRecordIdV1>,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub policy_provenance: Vec<PolicyObservationProvenanceV1>,
    pub effects: Vec<GraphEffectV1>,
    pub reason_code: String,
    pub severity: FindingSeverityV1,
    pub sensitivity: ContextSensitivityV1,
    pub required_action: Option<String>,
    pub limits: Vec<String>,
}

impl FindingChange {
    pub fn local(&self, record: u32, context: Option<u32>) -> Finding {
        Finding {
            record,
            context,
            tenant_id: self.tenant_id,
            finding_id: self.finding_id.clone(),
            package_id: self.package_id.clone(),
            package_version: self.package_version,
            subject_id: self.subject_id.clone(),
            state: self.state,
            window_start_utc_ns: self.window_start_utc_ns,
            window_end_utc_ns: self.window_end_utc_ns,
            evidence: self.evidence.clone(),
            required_coverage_interval_ids: self.required_coverage_interval_ids.clone(),
            policy_provenance: self.policy_provenance.clone(),
            effects: self.effects.clone(),
            reason_code: self.reason_code.clone(),
            severity: self.severity,
            sensitivity: self.sensitivity,
            required_action: self.required_action.clone(),
            limits: self.limits.clone(),
        }
    }

    pub fn from_local(value: Finding, anchor: Anchor) -> Self {
        Self {
            anchor,
            prior_reason: None,
            tenant_id: value.tenant_id,
            finding_id: value.finding_id,
            package_id: value.package_id,
            package_version: value.package_version,
            subject_id: value.subject_id,
            state: value.state,
            window_start_utc_ns: value.window_start_utc_ns,
            window_end_utc_ns: value.window_end_utc_ns,
            evidence: value.evidence,
            required_coverage_interval_ids: value.required_coverage_interval_ids,
            policy_provenance: value.policy_provenance,
            effects: value.effects,
            reason_code: value.reason_code,
            severity: value.severity,
            sensitivity: value.sensitivity,
            required_action: value.required_action,
            limits: value.limits,
        }
    }

    pub fn into_finding(self, reason: FindingReasonV1) -> FindingV1 {
        FindingV1 {
            tenant_id: self.tenant_id,
            finding_id: self.finding_id,
            package_id: self.package_id,
            package_version: self.package_version,
            subject_id: self.subject_id,
            state: self.state,
            window_start_utc_ns: self.window_start_utc_ns,
            window_end_utc_ns: self.window_end_utc_ns,
            evidence: self.evidence,
            required_coverage_interval_ids: self.required_coverage_interval_ids,
            policy_provenance: self.policy_provenance,
            effects: self.effects,
            reason,
            severity: self.severity,
            sensitivity: self.sensitivity,
            required_action: self.required_action,
            limits: self.limits,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactAnchor {
    pub record: DiscoveryRecordIdV1,
    pub key: AnalysisContextKeyV1,
    pub sensitivity: ContextSensitivityV1,
    pub value: GraphFactValueV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub record: DiscoveryRecordIdV1,
    pub fact: Option<FactAnchor>,
}

impl Anchor {
    pub fn from_positions(
        record: u32,
        fact: Option<u32>,
        record_ids: &[DiscoveryRecordIdV1],
        facts: &[Fact],
    ) -> super::sdk::Result<Self> {
        let record = record_ids
            .get(record as usize)
            .ok_or_else(|| super::Computation::invalid("graph finding record"))?
            .clone();
        let fact = fact
            .map(|index| -> super::sdk::Result<_> {
                let fact = facts
                    .get(index as usize)
                    .ok_or_else(|| super::Computation::invalid("graph finding context"))?;
                let record = record_ids
                    .get(fact.record as usize)
                    .ok_or_else(|| super::Computation::invalid("graph finding context record"))?
                    .clone();
                Ok(FactAnchor {
                    record,
                    key: fact.key.clone(),
                    sensitivity: fact.sensitivity,
                    value: fact.value.clone(),
                })
            })
            .transpose()?;
        Ok(Self { record, fact })
    }
}

pub(super) type FindingAnchor = Anchor;

impl Finding {
    pub fn into_finding(self, reason: FindingReasonV1) -> FindingV1 {
        FindingV1 {
            tenant_id: self.tenant_id,
            finding_id: self.finding_id,
            package_id: self.package_id,
            package_version: self.package_version,
            subject_id: self.subject_id,
            state: self.state,
            window_start_utc_ns: self.window_start_utc_ns,
            window_end_utc_ns: self.window_end_utc_ns,
            evidence: self.evidence,
            required_coverage_interval_ids: self.required_coverage_interval_ids,
            policy_provenance: self.policy_provenance,
            effects: self.effects,
            reason,
            severity: self.severity,
            sensitivity: self.sensitivity,
            required_action: self.required_action,
            limits: self.limits,
        }
    }

    pub fn from_finding(
        record: u32,
        context: Option<u32>,
        value: FindingV1,
        reason_code: String,
    ) -> Self {
        Self {
            record,
            context,
            tenant_id: value.tenant_id,
            finding_id: value.finding_id,
            package_id: value.package_id,
            package_version: value.package_version,
            subject_id: value.subject_id,
            state: value.state,
            window_start_utc_ns: value.window_start_utc_ns,
            window_end_utc_ns: value.window_end_utc_ns,
            evidence: value.evidence,
            required_coverage_interval_ids: value.required_coverage_interval_ids,
            policy_provenance: value.policy_provenance,
            effects: value.effects,
            reason_code,
            severity: value.severity,
            sensitivity: value.sensitivity,
            required_action: value.required_action,
            limits: value.limits,
        }
    }
}
