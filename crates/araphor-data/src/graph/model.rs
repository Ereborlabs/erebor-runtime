use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, DiscoveryCoverageV1,
    DiscoveryRecordIdV1, DiscoveryRecordV1, EvidenceIntakeIdentityV1, GraphEncodingSnafu,
    GraphInvalidSnafu, ProcessorScopeV1, Result,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum FindingSeverityV1 {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphSubjectKindV1 {
    Task,
    Process,
    ExecutionSet,
    Socket,
    Artifact,
    Request,
    CredentialLease,
    KubernetesObject,
    ProviderObject,
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "authority",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum GraphSubjectAuthorityV1 {
    Native {
        node_id: String,
        node_boot_id: [u8; 16],
        label_epoch: u64,
    },
    Provider {
        authority_id: String,
    },
    Kubernetes {
        cluster_id: String,
    },
    External {
        authority_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSubjectKeyV1 {
    pub tenant_id: [u8; 16],
    pub authority: GraphSubjectAuthorityV1,
    pub kind: GraphSubjectKindV1,
    pub identity: Vec<u8>,
}

impl GraphSubjectKeyV1 {
    pub fn validate(&self) -> Result<()> {
        let valid_authority = match &self.authority {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => {
                !node_id.is_empty()
                    && node_id.len() <= 256
                    && *node_boot_id != [0; 16]
                    && *label_epoch > 0
            }
            GraphSubjectAuthorityV1::Provider { authority_id }
            | GraphSubjectAuthorityV1::External { authority_id } => {
                !authority_id.is_empty() && authority_id.len() <= 256
            }
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => {
                !cluster_id.is_empty() && cluster_id.len() <= 256
            }
        };
        if self.tenant_id == [0; 16]
            || !valid_authority
            || self.identity.is_empty()
            || self.identity.len() > 512
        {
            return GraphInvalidSnafu {
                field: "subject lifetime",
            }
            .fail();
        }
        Ok(())
    }

    pub fn native(
        source: &EvidenceIntakeIdentityV1,
        kind: GraphSubjectKindV1,
        identity: Vec<u8>,
    ) -> Self {
        Self {
            tenant_id: source.tenant_id,
            authority: GraphSubjectAuthorityV1::Native {
                node_id: source.node_id.clone(),
                node_boot_id: source.node_boot_id,
                label_epoch: source.label_epoch,
            },
            kind,
            identity,
        }
    }
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
    pub from: GraphSubjectKeyV1,
    pub to: GraphSubjectKeyV1,
    pub edge_type: GraphEdgeTypeV1,
    pub package_id: String,
    pub evidence: Vec<DiscoveryRecordIdV1>,
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphCoverageKeyV1 {
    pub source: EvidenceIntakeIdentityV1,
    pub cpu_id: u32,
    pub report_revision: u64,
    pub interval_id: [u8; 16],
    pub interval_revision: u64,
    pub state: crate::DiscoveryCoverageStateV1,
    pub gap_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRevisionV1 {
    pub evidence: Vec<DiscoveryRecordIdV1>,
    pub coverage: Vec<GraphCoverageKeyV1>,
    pub context: Vec<AnalysisContextKeyV1>,
    pub missing_ranges: Vec<(u64, u64)>,
}

impl GraphRevisionV1 {
    pub fn validate(&self, tenant: [u8; 16]) -> Result<()> {
        if self.evidence.len() > GRAPH_WINDOW_RECORDS as usize
            || self.coverage.len() > 4096
            || self.context.len() > 256
            || self.missing_ranges.len() > 256
            || self
                .missing_ranges
                .iter()
                .any(|(first, last)| *first == 0 || last < first)
            || self.evidence.windows(2).any(|pair| pair[0] >= pair[1])
            || self.coverage.windows(2).any(|pair| pair[0] >= pair[1])
            || self.context.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .evidence
                .iter()
                .any(|id| id.stream.tenant_id != tenant || id.validate().is_err())
            || self.coverage.iter().any(|key| {
                key.source.tenant_id != tenant || !key.source.valid() || key.interval_id == [0; 16]
            })
            || self
                .context
                .iter()
                .any(|key| key.tenant_id != tenant || !key.valid())
        {
            return GraphInvalidSnafu {
                field: "revision manifest",
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyProvenanceStateV1 {
    Exact,
    Missing,
    Contradicted,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyObservationProvenanceV1 {
    pub source: EvidenceIntakeIdentityV1,
    pub profile_generation_ref_id: u64,
    pub observations: Vec<DiscoveryRecordIdV1>,
    pub policy_source_revision_id: Option<String>,
    pub candidate_content_id: Option<String>,
    pub target_snapshot_digest: Option<String>,
    pub node_bound_generation_digest: Option<String>,
    pub activation_acknowledgement: Option<AnalysisContextKeyV1>,
    pub state: PolicyProvenanceStateV1,
    pub limits: Vec<String>,
}

impl PolicyObservationProvenanceV1 {
    pub fn validate(&self) -> Result<()> {
        if !self.source.valid()
            || (self.profile_generation_ref_id == 0
                && self.state != PolicyProvenanceStateV1::Missing)
            || self.observations.is_empty()
            || self.observations.len() > GRAPH_WINDOW_RECORDS as usize
            || self.observations.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .observations
                .iter()
                .any(|id| id.stream != self.source || id.validate().is_err())
            || self.limits.len() > 32
            || self
                .limits
                .iter()
                .any(|limit| limit.is_empty() || limit.len() > 128)
            || self.limits.windows(2).any(|pair| pair[0] >= pair[1])
            || [
                self.policy_source_revision_id.as_ref(),
                self.candidate_content_id.as_ref(),
                self.target_snapshot_digest.as_ref(),
                self.node_bound_generation_digest.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.is_empty() || value.len() > 256)
            || self
                .activation_acknowledgement
                .as_ref()
                .is_some_and(|key| key.tenant_id != self.source.tenant_id || !key.valid())
            || (self.state == PolicyProvenanceStateV1::Exact
                && (self.policy_source_revision_id.is_none()
                    || self.candidate_content_id.is_none()
                    || self.target_snapshot_digest.is_none()
                    || self.node_bound_generation_digest.is_none()
                    || self.activation_acknowledgement.is_none()))
        {
            return GraphInvalidSnafu {
                field: "policy provenance",
            }
            .fail();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub revision: GraphRevisionV1,
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

impl FindingV1 {
    pub fn validate(&self) -> Result<()> {
        self.subject_id.validate()?;
        self.revision.validate(self.tenant_id)?;
        if self.tenant_id == [0; 16]
            || self.subject_id.tenant_id != self.tenant_id
            || self.finding_id.is_empty()
            || self.finding_id.len() > 4096
            || !matches!(
                self.package_id.as_str(),
                "HF-PROC-001" | "HF-DW-001" | "HF-XNODE-001"
            )
            || self.package_version != 1
            || self.window_start_utc_ns > self.window_end_utc_ns
            || self.evidence.is_empty()
            || self.evidence.len() > GRAPH_WINDOW_RECORDS as usize
            || self.evidence.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .evidence
                .iter()
                .any(|id| !self.revision.evidence.contains(id))
            || self.required_coverage_interval_ids.len() > 256
            || self
                .required_coverage_interval_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.required_coverage_interval_ids.contains(&[0; 16])
            || self.policy_provenance.len() > 256
            || self.effects.len() > GRAPH_WINDOW_RECORDS as usize
            || self
                .effects
                .iter()
                .any(|effect| !self.evidence.contains(&effect.evidence))
            || self
                .required_action
                .as_ref()
                .is_some_and(|action| action.is_empty() || action.len() > 128)
            || self.limits.len() > 64
            || self
                .limits
                .iter()
                .any(|limit| limit.is_empty() || limit.len() > 128)
            || self.limits.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return GraphInvalidSnafu {
                field: "finding revision",
            }
            .fail();
        }
        for provenance in &self.policy_provenance {
            provenance.validate()?;
            if provenance.source.tenant_id != self.tenant_id {
                return GraphInvalidSnafu {
                    field: "finding provenance tenant",
                }
                .fail();
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphVersionV1 {
    pub revision: GraphRevisionV1,
    pub subjects: Vec<GraphSubjectKeyV1>,
    pub edges: Vec<GraphEdgeV1>,
    pub branches: Vec<GraphBranchV1>,
    pub facts: Vec<GraphFactV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub window_records: u64,
    pub window_bytes: usize,
    pub coverage_predicate: String,
    pub replay_contract_id: String,
    pub result_states: Vec<FindingStateV1>,
    pub accepted_cursor_watermark: u64,
    pub observed_boottime_watermark_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSnapshotV1 {
    pub schema_version: u32,
    pub scope: ProcessorScopeV1,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub input_manifest: GraphRevisionV1,
    pub graph: GraphVersionV1,
    pub findings: Vec<FindingV1>,
    pub packages: Vec<GraphPackageCheckpointV1>,
    pub missing_ranges: Vec<(u64, u64)>,
    pub input_positions: Vec<(DiscoveryRecordIdV1, crate::StorePositionV1)>,
    pub previous_result_id: Option<String>,
    pub context_notice_revision: u64,
    pub witness_deadline_utc_ns: u64,
}

impl GraphSnapshotV1 {
    pub fn validate(&self) -> Result<()> {
        self.input_manifest
            .validate(self.scope.identity.tenant_id)?;
        if self.schema_version != GRAPH_SCHEMA_VERSION
            || self.scope.processor_id != GRAPH_PROCESSOR
            || self.scope.method_version != GRAPH_SCHEMA_VERSION as u64
            || !self.scope.identity.valid()
            || self.first_cursor == 0
            || self.last_cursor < self.first_cursor
            || self.last_cursor - self.first_cursor >= GRAPH_WINDOW_RECORDS
            || self.graph.revision != self.input_manifest
            || self.missing_ranges != self.input_manifest.missing_ranges
            || self.input_positions.len() > GRAPH_WINDOW_RECORDS as usize
            || self.input_positions.iter().any(|(record, position)| {
                !self.input_manifest.evidence.contains(record) || position.commit_revision == 0
            })
            || self
                .previous_result_id
                .as_ref()
                .is_some_and(|id| id.is_empty() || id.len() > 256)
            || self.graph.subjects.len() > 2048
            || self
                .graph
                .subjects
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.graph.edges.len() > 4096
            || self
                .graph
                .edges
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || self.findings.len() > 1024
            || self
                .findings
                .windows(2)
                .any(|pair| pair[0].finding_id >= pair[1].finding_id)
            || self.packages.len() != 3
            || self.input_manifest.evidence.iter().any(|id| {
                id.stream != self.scope.identity
                    || !(self.first_cursor..=self.last_cursor).contains(&id.durable_cursor)
            })
            || self.missing_ranges.len() > 256
            || self
                .missing_ranges
                .iter()
                .any(|(first, last)| *first == 0 || last < first)
        {
            return GraphInvalidSnafu {
                field: "graph snapshot",
            }
            .fail();
        }
        for subject in &self.graph.subjects {
            subject.validate()?;
            if subject.tenant_id != self.scope.identity.tenant_id {
                return GraphInvalidSnafu {
                    field: "graph subject tenant",
                }
                .fail();
            }
        }
        for edge in &self.graph.edges {
            if !self.graph.subjects.contains(&edge.key.from)
                || !self.graph.subjects.contains(&edge.key.to)
                || edge.first_boottime_ns > edge.last_boottime_ns
                || edge
                    .key
                    .evidence
                    .iter()
                    .any(|id| !self.input_manifest.evidence.contains(id))
                || (edge.key.edge_type == GraphEdgeTypeV1::NativeParent
                    && (edge.key.from.authority != edge.key.to.authority
                        || !matches!(
                            edge.key.from.authority,
                            GraphSubjectAuthorityV1::Native { .. }
                        )))
            {
                return GraphInvalidSnafu {
                    field: "graph edge proof",
                }
                .fail();
            }
        }
        for finding in &self.findings {
            finding.validate()?;
            if finding.revision != self.input_manifest
                || finding.tenant_id != self.scope.identity.tenant_id
            {
                return GraphInvalidSnafu {
                    field: "graph finding manifest",
                }
                .fail();
            }
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for GraphSnapshotV1 {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > crate::analysis::MAX_RESULT_BYTES {
            return GraphInvalidSnafu {
                field: "graph result bytes",
            }
            .fail();
        }
        let value: Self = serde_json::from_slice(bytes).context(GraphEncodingSnafu)?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFactV1 {
    pub record_id: DiscoveryRecordIdV1,
    pub value: GraphFactValueV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphReadPathV1 {
    Read,
    Mmap,
    InheritedFd,
    IoUring,
    Memory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphContextActionV1 {
    OutsideAuthority,
    InMemory,
    PayloadUnobservable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphReadCompletionV1 {
    pub admission_record: DiscoveryRecordIdV1,
    pub owner: String,
    pub completion_id: String,
    pub task_cookie: u64,
    pub process_instance_id: [u8; 16],
    pub object_id: [u8; 16],
    pub file_description_id: String,
    pub path: GraphReadPathV1,
    pub result: i64,
    pub byte_count: u64,
    pub credential_lease_id: Option<String>,
    pub principal_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesStageProofV1 {
    pub cluster_id: String,
    pub carried_request_id: Option<String>,
    pub audit_id: Option<String>,
    pub object_uid: Option<String>,
    pub resource_version: Option<String>,
    pub owner_uid: Option<String>,
    pub pod_uid: Option<String>,
    pub node_id: Option<String>,
    pub full_container_id: Option<String>,
    pub remote_admission_id: Option<String>,
    pub proof_quality: ProofQualityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphPolicyActivationV1 {
    pub tenant_id: String,
    pub node_id: String,
    pub node_boot_id: Vec<u8>,
    pub label_epoch: u64,
    pub candidate_content_id: String,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub state: String,
    pub node_bound_generation_digest: Option<String>,
    pub profile_generation_ref_id: Option<u64>,
    pub readback_digest: Option<String>,
    pub probe_result_digest: Option<String>,
    pub reason_code: Option<String>,
    pub observed_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphFactValueV1 {
    Policy(PolicyObservationProvenanceV1),
    Activation(GraphPolicyActivationV1),
    Context {
        subject: GraphSubjectKeyV1,
        action_id: String,
        classification: GraphContextActionV1,
        proof_quality: ProofQualityV1,
    },
    Credential {
        object_id: [u8; 16],
        expected_access: bool,
        reviewed_policy_revision: String,
        completion: Option<GraphReadCompletionV1>,
        proof_quality: ProofQualityV1,
        principal_id: Option<String>,
    },
    Baseline {
        role_id: u32,
        state_id: u32,
        outside_reviewed_baseline: bool,
        reviewed_policy_revision: String,
    },
    NativeParent {
        parent: GraphSubjectKeyV1,
        child: GraphSubjectKeyV1,
        proof_quality: ProofQualityV1,
    },
    AuthorityUse {
        authority_id: String,
        process_instance_id: Option<[u8; 16]>,
        task_cookie: Option<u64>,
        credential_object_id: Option<[u8; 16]>,
        socket_object_id: Option<[u8; 16]>,
        request_id: Option<String>,
        credential_lease_id: Option<String>,
        principal_id: String,
        operation_id: String,
        outside_reviewed_behavior: bool,
        proof_quality: ProofQualityV1,
        workload_binding: Option<GraphSubjectKeyV1>,
    },
    Channel {
        task_cookie: u64,
        process_instance_id: [u8; 16],
        socket_object_id: [u8; 16],
        authority_id: String,
        carried_request_id: String,
        credential_lease_id: String,
        principal_id: String,
        operation_id: String,
        proof_quality: ProofQualityV1,
    },
    Kubernetes(KubernetesStageProofV1),
}

impl GraphFactV1 {
    pub fn validate(&self) -> Result<()> {
        self.record_id.validate()?;
        match &self.value {
            GraphFactValueV1::Activation(activation) => {
                if uuid::Uuid::parse_str(&activation.tenant_id)
                    .ok()
                    .map(|id| *id.as_bytes())
                    != Some(self.record_id.stream.tenant_id)
                    || activation.node_id.is_empty()
                    || activation.node_id.len() > 128
                    || activation.node_boot_id.len() != 16
                    || activation.node_boot_id == [0; 16]
                    || activation.label_epoch == 0
                    || activation.observed_utc_ns <= 0
                    || !matches!(
                        activation.state.as_str(),
                        "RECEIVED" | "STAGED" | "ACTIVE" | "REJECTED" | "STALE" | "UNKNOWN"
                    )
                    || [
                        &activation.candidate_content_id,
                        &activation.policy_source_revision_id,
                        &activation.target_snapshot_digest,
                    ]
                    .into_iter()
                    .any(|id| id.is_empty() || id.len() > 256)
                    || [
                        &activation.node_bound_generation_digest,
                        &activation.readback_digest,
                        &activation.probe_result_digest,
                        &activation.reason_code,
                    ]
                    .into_iter()
                    .flatten()
                    .any(|id| id.is_empty() || id.len() > 256)
                    || activation.profile_generation_ref_id == Some(0)
                {
                    return GraphInvalidSnafu {
                        field: "activation result",
                    }
                    .fail();
                }
            }
            GraphFactValueV1::Context {
                subject, action_id, ..
            } => {
                subject.validate()?;
                if subject.tenant_id != self.record_id.stream.tenant_id
                    || action_id.is_empty()
                    || action_id.len() > 256
                {
                    return GraphInvalidSnafu {
                        field: "context action",
                    }
                    .fail();
                }
            }
            GraphFactValueV1::Policy(provenance) => {
                provenance.validate()?;
                if provenance.source != self.record_id.stream
                    || !provenance.observations.contains(&self.record_id)
                {
                    return GraphInvalidSnafu {
                        field: "policy observation join",
                    }
                    .fail();
                }
            }
            GraphFactValueV1::Credential {
                object_id,
                reviewed_policy_revision,
                completion,
                principal_id,
                ..
            } => {
                if *object_id == [0; 16]
                    || reviewed_policy_revision.is_empty()
                    || reviewed_policy_revision.len() > 256
                {
                    return GraphInvalidSnafu {
                        field: "credential classification",
                    }
                    .fail();
                }
                if principal_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.len() > 256)
                {
                    return GraphInvalidSnafu {
                        field: "credential principal",
                    }
                    .fail();
                }
                if let Some(completion) = completion {
                    if [
                        &completion.owner,
                        &completion.completion_id,
                        &completion.file_description_id,
                    ]
                    .into_iter()
                    .any(|id| id.is_empty() || id.len() > 256)
                        || completion.task_cookie == 0
                        || completion.process_instance_id == [0; 16]
                        || completion.object_id != *object_id
                        || (completion.result > 0
                            && u64::try_from(completion.result).ok() != Some(completion.byte_count))
                        || completion.admission_record != self.record_id
                        || (completion.result <= 0 && completion.byte_count != 0)
                        || [&completion.credential_lease_id, &completion.principal_id]
                            .into_iter()
                            .flatten()
                            .any(|id| id.is_empty() || id.len() > 256)
                    {
                        return GraphInvalidSnafu {
                            field: "credential read completion",
                        }
                        .fail();
                    }
                }
            }
            GraphFactValueV1::Baseline {
                role_id,
                state_id,
                reviewed_policy_revision,
                ..
            } if *role_id == 0
                || *state_id == 0
                || reviewed_policy_revision.is_empty()
                || reviewed_policy_revision.len() > 256 =>
            {
                return GraphInvalidSnafu {
                    field: "reviewed role baseline",
                }
                .fail();
            }
            GraphFactValueV1::NativeParent {
                parent,
                child,
                proof_quality,
            } => {
                parent.validate()?;
                child.validate()?;
                if parent.tenant_id != self.record_id.stream.tenant_id
                    || child.tenant_id != self.record_id.stream.tenant_id
                    || parent.authority != child.authority
                    || parent.authority
                        != GraphSubjectKeyV1::native(
                            &self.record_id.stream,
                            parent.kind,
                            parent.identity.clone(),
                        )
                        .authority
                    || proof_quality.source_authority != SourceAuthorityV1::KernelDecision
                    || !matches!(
                        proof_quality.local_subject_binding,
                        LocalSubjectBindingV1::ExactTask | LocalSubjectBindingV1::ExactProcess
                    )
                {
                    return GraphInvalidSnafu {
                        field: "native parent proof",
                    }
                    .fail();
                }
            }
            GraphFactValueV1::AuthorityUse {
                authority_id,
                process_instance_id,
                task_cookie,
                credential_object_id,
                socket_object_id,
                request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                workload_binding,
                ..
            } => {
                if [authority_id, principal_id, operation_id]
                    .into_iter()
                    .any(|id| id.is_empty() || id.len() > 256)
                    || [process_instance_id, credential_object_id, socket_object_id]
                        .into_iter()
                        .any(|id| *id == Some([0; 16]))
                    || *task_cookie == Some(0)
                    || [request_id, credential_lease_id]
                        .into_iter()
                        .flatten()
                        .any(|id| id.is_empty() || id.len() > 256)
                {
                    return GraphInvalidSnafu {
                        field: "authority fact",
                    }
                    .fail();
                }
                if let Some(workload) = workload_binding {
                    workload.validate()?;
                    if workload.tenant_id != self.record_id.stream.tenant_id
                        || workload.kind != GraphSubjectKindV1::ExecutionSet
                        || workload.authority
                            != GraphSubjectKeyV1::native(
                                &self.record_id.stream,
                                workload.kind,
                                workload.identity.clone(),
                            )
                            .authority
                    {
                        return GraphInvalidSnafu {
                            field: "authority workload lifetime",
                        }
                        .fail();
                    }
                }
            }
            GraphFactValueV1::Channel {
                task_cookie,
                process_instance_id,
                socket_object_id,
                authority_id,
                carried_request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                ..
            } => {
                if *task_cookie == 0
                    || *process_instance_id == [0; 16]
                    || *socket_object_id == [0; 16]
                    || [
                        authority_id,
                        carried_request_id,
                        credential_lease_id,
                        principal_id,
                        operation_id,
                    ]
                    .into_iter()
                    .any(|id| id.is_empty() || id.len() > 256)
                {
                    return GraphInvalidSnafu {
                        field: "carried channel proof",
                    }
                    .fail();
                }
            }
            GraphFactValueV1::Kubernetes(stage)
                if stage.cluster_id.is_empty()
                    || stage.cluster_id.len() > 256
                    || [
                        &stage.audit_id,
                        &stage.object_uid,
                        &stage.resource_version,
                        &stage.owner_uid,
                        &stage.pod_uid,
                        &stage.node_id,
                        &stage.full_container_id,
                        &stage.carried_request_id,
                        &stage.remote_admission_id,
                    ]
                    .into_iter()
                    .flatten()
                    .any(|id| id.is_empty() || id.len() > 256) =>
            {
                return GraphInvalidSnafu {
                    field: "Kubernetes fact",
                }
                .fail();
            }
            _ => {}
        }
        Ok(())
    }
}

impl TryFrom<&AnalysisContextVersionV1> for GraphFactV1 {
    type Error = crate::Error;

    fn try_from(context: &AnalysisContextVersionV1) -> Result<Self> {
        if !context.key.valid() || context.key.owner_revision == 0 || context.body.len() > 32 * 1024
        {
            return GraphInvalidSnafu {
                field: "graph context version",
            }
            .fail();
        }
        let value: Self = serde_json::from_slice(&context.body).context(GraphEncodingSnafu)?;
        value.validate()?;
        if value.record_id.stream.tenant_id != context.key.tenant_id {
            return GraphInvalidSnafu {
                field: "graph context tenant",
            }
            .fail();
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct GraphReplayInputV1 {
    pub source: EvidenceIntakeIdentityV1,
    pub records: Vec<DiscoveryRecordV1>,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub coverage_keys: Vec<GraphCoverageKeyV1>,
    pub facts: Vec<AnalysisContextVersionV1>,
    pub missing_ranges: Vec<(u64, u64)>,
}

impl GraphReplayInputV1 {
    pub fn validate(&self) -> Result<()> {
        if !self.source.valid()
            || self.records.is_empty()
            || self.records.len() > GRAPH_WINDOW_RECORDS as usize
            || self.facts.len() > 256
            || self.coverage.len() > 4096
        {
            return GraphInvalidSnafu {
                field: "replay input",
            }
            .fail();
        }
        let mut ids = BTreeSet::new();
        for record in &self.records {
            record.decode()?;
            if record.id.stream != self.source || !ids.insert(&record.id) {
                return GraphInvalidSnafu {
                    field: "replay record identity",
                }
                .fail();
            }
        }
        for range in &self.coverage {
            range.validate()?;
            if range.stream != self.source {
                return GraphInvalidSnafu {
                    field: "replay coverage source",
                }
                .fail();
            }
        }
        for fact in &self.facts {
            let decoded = GraphFactV1::try_from(fact)?;
            if decoded.record_id.stream != self.source || !ids.contains(&decoded.record_id) {
                return GraphInvalidSnafu {
                    field: "replay fact source",
                }
                .fail();
            }
            if let GraphFactValueV1::Policy(policy) = &decoded.value {
                if policy.state == PolicyProvenanceStateV1::Exact {
                    let activation = policy
                        .activation_acknowledgement
                        .as_ref()
                        .and_then(|key| self.facts.iter().find(|fact| &fact.key == key))
                        .ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "unretained activation reference",
                            }
                            .build()
                        })?;
                    let activation = GraphFactV1::try_from(activation)?;
                    let GraphFactValueV1::Activation(ack) = activation.value else {
                        return GraphInvalidSnafu {
                            field: "activation reference type",
                        }
                        .fail();
                    };
                    if activation.record_id != decoded.record_id
                        || ack.node_id != policy.source.node_id
                        || ack.node_boot_id.as_slice() != policy.source.node_boot_id
                        || ack.label_epoch != policy.source.label_epoch
                        || ack.state != "ACTIVE"
                        || ack.profile_generation_ref_id != Some(policy.profile_generation_ref_id)
                        || Some(&ack.candidate_content_id) != policy.candidate_content_id.as_ref()
                        || Some(&ack.policy_source_revision_id)
                            != policy.policy_source_revision_id.as_ref()
                        || Some(&ack.target_snapshot_digest)
                            != policy.target_snapshot_digest.as_ref()
                        || ack.node_bound_generation_digest != policy.node_bound_generation_digest
                        || ack.readback_digest.is_none()
                        || ack.probe_result_digest.is_none()
                    {
                        return GraphInvalidSnafu {
                            field: "activation exact join",
                        }
                        .fail();
                    }
                }
            }
        }
        Ok(())
    }
}
