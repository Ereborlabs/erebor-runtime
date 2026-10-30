use serde::{Deserialize, Serialize};

use super::*;
use crate::discovery::DiscoveryRecordIdV1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContextSensitivityV1 {
    Public,
    Tenant,
    HostRestricted,
}

impl From<ContextSensitivityV1> for &'static str {
    fn from(value: ContextSensitivityV1) -> Self {
        match value {
            ContextSensitivityV1::Public => "public",
            ContextSensitivityV1::Tenant => "tenant",
            ContextSensitivityV1::HostRestricted => "host_restricted",
        }
    }
}

impl TryFrom<&str> for ContextSensitivityV1 {
    type Error = ();

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "public" => Ok(Self::Public),
            "tenant" => Ok(Self::Tenant),
            "host_restricted" => Ok(Self::HostRestricted),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum FindingSeverityV1 {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphCauseV1 {
    Direct,
    Contextual,
    Contradicted,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphEdgeTypeV1 {
    TaskInProcess,
    TaskInExecutionSet,
    NativeParent,
    NativeEffect,
    CredentialAuthority,
    KubernetesExpansion,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeKeyV1 {
    pub from: u32,
    pub to: u32,
    pub edge_type: GraphEdgeTypeV1,
    pub package_id: String,
    pub evidence: Vec<u32>,
    pub cause: GraphCauseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdgeV1 {
    pub key: GraphEdgeKeyV1,
    pub proof_quality: ProofQualityV1,
    pub required_coverage_interval_ids: Vec<[u8; 16]>,
    pub first_boottime_ns: u64,
    pub last_boottime_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingReasonV1 {
    UnexpectedEffect,
    AuditedRoleDeviation,
    LineageCoverageGap,
    CredentialPivot,
    ContextualCredentialPivot,
    MissingAuthorityProof,
    Contradiction,
    KubernetesProofMissing,
    OutsideAuthority,
    InMemoryOnly,
    PayloadUnobservable,
    #[serde(untagged)]
    Declared(DeclaredFindingReasonV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredFindingReasonV1 {
    pub code: String,
    pub schema: araphor_analysis_sdk::Schema,
    pub ipc: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphBranchStateV1 {
    Open,
    TerminalVerified,
    ContextualOnly,
    OutsideAuthority,
    CoverageUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBranchV1 {
    pub package_id: String,
    pub seed: GraphSubjectKeyV1,
    pub evidence: Vec<DiscoveryRecordIdV1>,
    pub state: GraphBranchStateV1,
    pub missing_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphPhysicalResultV1 {
    Prevented,
    PacketDropped,
    TerminationQueued,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEffectV1 {
    pub evidence: DiscoveryRecordIdV1,
    pub process_instance_id: Option<[u8; 16]>,
    pub entry_instance_id: Option<[u8; 16]>,
    pub binding_id: Option<[u8; 16]>,
    pub role_id: Option<u32>,
    pub state_id: Option<u32>,
    pub entry_rule_id: Option<u32>,
    pub profile_generation_ref_id: Option<u64>,
    pub original_kernel_sequence: Option<u64>,
    pub effect_family: u32,
    pub operation: u32,
    pub source_decision: u32,
    pub source_reason: u32,
    pub configured_errno: i32,
    pub kernel_result: i32,
    pub physical_result: GraphPhysicalResultV1,
    pub proof_quality: ProofQualityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingV1 {
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
    pub reason: FindingReasonV1,
    pub severity: FindingSeverityV1,
    pub sensitivity: ContextSensitivityV1,
    pub required_action: Option<String>,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphPackageStateV1 {
    Waiting,
    NativeEffect,
    CredentialObserved,
    AuthorityChannel,
    DirectPivot,
    ContextualPivot,
    Contradicted,
    CoverageInsufficient,
    KubernetesProofMissing,
    KubernetesRequest,
    KubernetesAudit,
    KubernetesObject,
    KubernetesScheduled,
    RemoteAdmission,
    #[serde(untagged)]
    Declared(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphPackageCheckpointV1 {
    pub package_id: String,
    pub package_version: u64,
    pub required_inputs: Vec<String>,
    pub state: GraphPackageStateV1,
    pub maximum_lateness_ns: u64,
    pub retention_ttl_ns: u64,
    pub clock_uncertainty_ns: Option<u64>,
    pub late_action: String,
    pub window_ns: u64,
    pub coverage_predicate: String,
    pub replay_contract_id: String,
    pub result_states: Vec<FindingStateV1>,
    pub accepted_cursor_watermark: u64,
    pub observed_boottime_watermark_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFactV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub value: GraphFactValueV1,
}

impl GraphFactV1 {
    pub fn encode_context(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec_named(self)
    }

    pub fn decode_context(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}

impl FindingV1 {
    pub const PACKAGES: [&'static str; 3] = ["HF-PROC-001", "HF-DW-001", "HF-XNODE-001"];
}
