use super::proof::*;
use crate::discovery::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
pub struct AnalysisContextKeyV1 {
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub tenant_id: [u8; 16],
    pub owner_id: String,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub entity_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[schemars(with = "Vec<u8>")]
    pub lifetime_key: Vec<u8>,
    pub owner_revision: u64,
}

impl AnalysisContextKeyV1 {
    pub fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && !self.owner_id.is_empty()
            && !self.entity_key.is_empty()
            && !self.lifetime_key.is_empty()
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphSubjectKeyV1 {
    pub tenant_id: [u8; 16],
    pub authority: GraphSubjectAuthorityV1,
    pub kind: GraphSubjectKindV1,
    pub identity: Vec<u8>,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyProvenanceStateV1 {
    Exact,
    Missing,
    Contradicted,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphReadPathV1 {
    Read,
    Mmap,
    InheritedFd,
    IoUring,
    Memory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphContextActionV1 {
    OutsideAuthority,
    InMemory,
    PayloadUnobservable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
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

impl GraphSubjectKeyV1 {
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

impl GraphSubjectKeyV1 {
    pub fn matches_local(&self, task: u64, process: Option<[u8; 16]>) -> bool {
        (self.kind == GraphSubjectKindV1::Task && task > 0 && self.identity == task.to_be_bytes())
            || (self.kind == GraphSubjectKindV1::Process
                && process.is_some_and(|id| self.identity == id))
    }
}
