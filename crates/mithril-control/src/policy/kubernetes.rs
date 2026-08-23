use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{CustomResource, CustomResourceExt as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;

use super::canonical::canonical_cbor;
use super::{
    AmbiguityDispositionV1, BindingLifecycleV1, BudgetSetV1, CohortSelectionV1,
    CommonSubjectMatchV1, ContainerKindV1, DefaultPostureActionV1, DefaultPosturesV1,
    DestinationPolicyRecordV1, DetectionDispositionRuleV1, DnsPolicyModeV1, EffectFamilyDefaultV1,
    EffectFamilyV1, EntryKindV1, EntryRoleAssignmentV1, ErrnoV1, EvaluationStageV1,
    EvidenceLevelV1, FileExceptionGrantTemplateV1, FilesystemObjectTypeV1, FindingSpecV1,
    IpcRelationshipRuleV1, LabelOperatorV1, LabelRequirementV1, LocalEffectMatchV1,
    LocalObjectSelectorV1, LocalSubjectBindingV1, NetworkPolicyV1, NetworkPortRangeV1,
    NetworkProtocolV1, ObjectClassifierBindingV1, ObjectClassifierSelectorV1,
    OperationResultAuthorityV1, PathSelectorV1, PolicyDispositionV1, PolicyDocumentV1,
    PolicyMetadataV1, ProcessStateDefinitionV1, ProfileCandidateArtifactV1, ProfileModeV1,
    ProofIntegrityV1, ProofQualityPredicateV1, ProtectedUniverseV1, RemoteSubjectBindingV1,
    RoleDefinitionV1, RolloutV1, RootClassificationV1, RuleMatchV1, SeverityV1, SourceAuthorityV1,
    TemporalCoverageV1, UnknownClassifierResultV1, WorkloadSelectorV1,
};
use crate::error::{InvalidConfigurationSnafu, PolicySignatureSnafu, PolicyValidationSnafu};
use crate::Result;

pub const POLICY_API_VERSION: &str = "mithril.erebor.dev/v1alpha1";
pub const POLICY_KIND: &str = "WorkloadProtectionPolicy";
pub const EXCEPTION_KIND: &str = "WorkloadProtectionException";
pub const MAX_POLICY_STATUS_TARGETS: u32 = 65_536;
pub const MAX_POLICY_BUNDLE_CHUNK_BYTES: usize = 64 * 1_024;
pub const MAX_POLICY_BUNDLE_BYTES: usize = 16 * 1_024 * 1_024;
pub const MAX_POLICY_SCHEMA_ITEMS: u64 = 32_768;
pub const MAX_POLICY_SCHEMA_STRING_BYTES: u64 = 4_096;
pub const MAX_POLICY_SCHEMA_MAP_ENTRIES: u64 = 4_096;

// Separate digest domains prevent one valid artifact digest from naming another artifact type.
const SOURCE_REVISION_DOMAIN: &[u8] = b"MITHRIL-POLICY-SOURCE-REVISION-V1\0";
const TARGET_SNAPSHOT_DOMAIN: &[u8] = b"MITHRIL-POLICY-TARGET-SNAPSHOT-V1\0";
const CANDIDATE_DOMAIN: &[u8] = b"MITHRIL-POLICY-CANDIDATE-V1\0";
const ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"MITHRIL-POLICY-ACTIVATION-ACK-V1\0";

#[derive(CustomResource, Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "mithril.erebor.dev",
    version = "v1alpha1",
    kind = "WorkloadProtectionPolicy",
    plural = "workloadprotectionpolicies",
    namespaced,
    status = "WorkloadProtectionPolicyStatusV1",
    shortname = "wpp"
)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Defines the CRD desired state. Control creates signed node artifacts from this value.
pub struct WorkloadProtectionPolicySpec {
    pub pod_selector: KubernetesLabelSelectorV1,
    pub mode: KubernetesPolicyModeV1,
    #[schemars(length(min = 1, max = 256))]
    pub containers: Vec<ContainerPolicyMatchV1>,
    #[schemars(length(min = 1, max = 256))]
    pub roles: Vec<KubernetesRolePolicyV1>,
    #[serde(default)]
    #[schemars(length(max = 256))]
    pub exception_grants: Vec<FileExceptionGrantV1>,
}

impl WorkloadProtectionPolicySpec {
    pub fn parse(path: &std::path::Path, source: &[u8]) -> Result<Self> {
        super::source::parse_restricted_yaml(path, source)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Projects Control state for operators. This status does not authorize node activation.
pub struct WorkloadProtectionPolicyStatusV1 {
    pub observed_generation: u64,
    pub rollout: PolicyRolloutCountsV1,
    #[schemars(length(max = 8))]
    pub conditions: Vec<KubernetesConditionV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KubernetesLabelSelectorV1 {
    #[serde(default)]
    #[schemars(length(max = 256))]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default)]
    #[schemars(length(max = 256))]
    pub match_expressions: Vec<KubernetesLabelSelectorRequirementV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesLabelSelectorRequirementV1 {
    pub key: String,
    pub operator: KubernetesLabelSelectorOperatorV1,
    #[serde(default)]
    #[schemars(length(max = 256))]
    pub values: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum KubernetesLabelSelectorOperatorV1 {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KubernetesConditionV1 {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub status: KubernetesConditionStatusV1,
    pub observed_generation: u64,
    pub last_transition_time: String,
    pub reason: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum KubernetesConditionStatusV1 {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyRolloutCountsV1 {
    pub desired: u32,
    pub active: u32,
    pub updating: u32,
    pub failed: u32,
}

impl PolicyRolloutCountsV1 {
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.desired
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum KubernetesPolicyModeV1 {
    Observe,
    Protect,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContainerPolicyMatchV1 {
    #[schemars(length(min = 1, max = 64))]
    pub names: Vec<String>,
    #[schemars(length(min = 1, max = 4))]
    pub kinds: Vec<KubernetesContainerKindV1>,
    #[schemars(length(min = 1, max = 256))]
    pub images: Vec<String>,
    pub initial_role: String,
    pub external_role: String,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesContainerKindV1 {
    Init,
    Sidecar,
    Application,
    Ephemeral,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KubernetesRolePolicyV1 {
    pub name: String,
    #[schemars(length(max = 1024))]
    pub files: Vec<FileRuleV1>,
    #[schemars(length(max = 1024))]
    pub execution: Vec<ExecutionRuleV1>,
    pub network: KubernetesNetworkRulesV1,
    #[schemars(length(max = 1024))]
    pub process_control: Vec<ProcessControlRuleV1>,
    #[schemars(length(max = 1024))]
    pub unix_streams: Vec<UnixStreamRelationshipV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileRuleV1 {
    pub name: String,
    pub path: String,
    pub recursive: bool,
    #[schemars(length(min = 1, max = 16))]
    pub operations: Vec<KubernetesFileOperationV1>,
    pub action: KubernetesRuleActionV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesFileOperationV1 {
    OpenRead,
    OpenWrite,
    Read,
    Write,
    MmapRead,
    MmapWrite,
    Create,
    SetAttributes,
    Unlink,
    Link,
    Rename,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionRuleV1 {
    pub name: String,
    pub path: String,
    pub recursive: bool,
    #[schemars(length(min = 1, max = 3))]
    pub operations: Vec<KubernetesExecutionOperationV1>,
    pub action: KubernetesRuleActionV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesExecutionOperationV1 {
    Execute,
    MmapExecute,
    Mprotect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum KubernetesRuleActionV1 {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KubernetesNetworkRulesV1 {
    #[schemars(length(max = 256))]
    pub socket_controls: Vec<SocketControlRuleV1>,
    #[schemars(length(max = 1024))]
    pub destinations: Vec<AddressDestinationRuleV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SocketControlRuleV1 {
    #[schemars(length(min = 1, max = 5))]
    pub operations: Vec<KubernetesSocketControlOperationV1>,
    pub action: KubernetesRuleActionV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesSocketControlOperationV1 {
    Create,
    Listen,
    Accept,
    Shutdown,
    SetSocketOption,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AddressDestinationRuleV1 {
    pub name: String,
    #[schemars(length(min = 1, max = 4))]
    pub operations: Vec<KubernetesNetworkOperationV1>,
    #[schemars(length(min = 1, max = 2))]
    pub protocols: Vec<KubernetesNetworkProtocolV1>,
    #[schemars(length(min = 1, max = 256))]
    pub cidrs: Vec<String>,
    #[schemars(length(min = 1, max = 256))]
    pub ports: Vec<KubernetesNetworkPortRangeV1>,
    pub action: KubernetesRuleActionV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesNetworkOperationV1 {
    Connect,
    Send,
    Receive,
    Bind,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum KubernetesNetworkProtocolV1 {
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "UDP")]
    Udp,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct KubernetesNetworkPortRangeV1 {
    #[schemars(range(min = 1))]
    pub first: u16,
    #[schemars(range(min = 1))]
    pub last: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(transform = super::source::tagged_union_schema)]
#[serde(tag = "operation")]
pub enum ProcessControlRuleV1 {
    Signal {
        name: String,
        #[serde(rename = "targetRole")]
        target_role: String,
        #[schemars(length(min = 1, max = 64))]
        signals: Vec<u32>,
        action: KubernetesRuleActionV1,
    },
    Ptrace {
        name: String,
        #[serde(rename = "targetRole")]
        target_role: String,
        #[schemars(length(min = 1, max = 64))]
        requests: Vec<u32>,
        action: KubernetesRuleActionV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnixStreamRelationshipV1 {
    pub name: String,
    #[schemars(length(min = 1, max = 256))]
    pub peer_roles: Vec<String>,
    pub action: KubernetesRuleActionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileExceptionGrantV1 {
    pub name: String,
    #[schemars(length(min = 1, max = 256))]
    pub file_rules: Vec<String>,
    pub maximum_duration: String,
    #[schemars(range(min = 1))]
    pub maximum_uses: u32,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "mithril.erebor.dev",
    version = "v1alpha1",
    kind = "WorkloadProtectionException",
    plural = "workloadprotectionexceptions",
    namespaced,
    status = "WorkloadProtectionExceptionStatusV1",
    shortname = "wpe"
)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkloadProtectionExceptionSpec {
    pub policy_ref: LocalPolicyReferenceV1,
    pub grant: String,
    pub target: ExceptionTargetV1,
    pub requested_duration: String,
    #[schemars(range(min = 1))]
    pub requested_uses: u32,
}

impl WorkloadProtectionExceptionSpec {
    pub fn validate_request(&self, exception_id: &str) -> Result<()> {
        ensure!(
            !self.policy_ref.name.is_empty()
                && !self.grant.is_empty()
                && !self.target.pod.name.is_empty()
                && canonical_uuid(&self.target.pod.uid)
                && !self.target.container_name.is_empty()
                && self.requested_uses > 0,
            PolicyValidationSnafu {
                policy_id: exception_id,
                code: "CFG_KUBERNETES_EXCEPTION",
                reason: "the exception needs one policy, grant, exact Pod UID, container, and nonzero use count",
            }
        );
        self.requested_duration_ns(exception_id)?;
        Ok(())
    }

    pub fn requested_duration_ns(&self, exception_id: &str) -> Result<u64> {
        parse_duration_ns(&self.requested_duration, exception_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicyReferenceV1 {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExceptionTargetV1 {
    pub pod: ExceptionPodTargetV1,
    pub container_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionPodTargetV1 {
    pub name: String,
    pub uid: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum WorkloadProtectionExceptionStateV1 {
    Pending,
    Active,
    Consumed,
    Expired,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkloadProtectionExceptionStatusV1 {
    pub observed_generation: u64,
    pub state: WorkloadProtectionExceptionStateV1,
    #[schemars(length(max = 8))]
    pub conditions: Vec<KubernetesConditionV1>,
}

impl Default for WorkloadProtectionExceptionStatusV1 {
    fn default() -> Self {
        Self {
            observed_generation: 0,
            state: WorkloadProtectionExceptionStateV1::Pending,
            conditions: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicySourceStateV1 {
    Accepted,
    DeletionRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Binds one accepted Kubernetes object generation to canonical policy bytes.
pub struct PolicySourceRevisionV1 {
    pub schema_version: u32,
    pub tenant_id: String,
    pub cluster_uid: String,
    pub namespace_uid: String,
    pub object_uid: String,
    pub namespace_name: String,
    pub object_name: String,
    pub api_version: String,
    pub kind: String,
    pub object_generation: u64,
    pub opaque_resource_version: Vec<u8>,
    pub canonical_spec_digest: String,
    pub policy_document_digest: String,
    pub state: PolicySourceStateV1,
    pub policy_source_revision_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
/// Names all exact workload bindings for one node in an immutable snapshot.
pub struct PolicyTargetV1 {
    pub tenant_id: String,
    pub cluster_uid: String,
    pub node_id: String,
    pub workload_binding_generation_digests: Vec<String>,
    #[serde(default)]
    pub workload_targets: Vec<super::WorkloadTargetFactV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Commits the complete sorted target set before Control creates node candidates.
pub struct PolicyTargetSnapshotV1 {
    pub policy_source_revision_id: String,
    pub signed_profile_digest: String,
    pub rollout_generation: u64,
    pub targets: Vec<PolicyTargetV1>,
    pub target_snapshot_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDeliveryOperationV1 {
    Activate,
    Replace,
    RetireToRestrictiveTerminal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Carries one signed, monotonic operation for one exact node target.
pub struct PolicyDeliveryCandidateV1 {
    pub schema_version: u32,
    pub tenant_id: String,
    pub policy_source_revision_id: String,
    pub signed_profile_digest: String,
    pub target_snapshot_digest: String,
    pub exact_target: PolicyTargetV1,
    pub operation: PolicyDeliveryOperationV1,
    pub predecessor_candidate_content_id: Option<String>,
    pub distribution_sequence_epoch: u64,
    pub distribution_sequence: u64,
    pub issued_utc_ns: i64,
    pub expires_utc_ns: i64,
    pub signing_key_id: String,
    pub candidate_content_id: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyActivationStateV1 {
    Received,
    Staged,
    Active,
    Rejected,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Records a node result after mTLS session identity is added by Control.
pub struct PolicyActivationAcknowledgementV1 {
    pub acknowledgement_content_id: String,
    pub tenant_id: String,
    pub node_id: String,
    pub node_boot_id: Vec<u8>,
    pub label_epoch: u64,
    pub candidate_content_id: String,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub state: PolicyActivationStateV1,
    pub node_bound_generation_digest: Option<String>,
    pub profile_generation_ref_id: Option<u64>,
    pub readback_digest: Option<String>,
    pub probe_result_digest: Option<String>,
    pub reason_code: Option<String>,
    pub observed_utc_ns: i64,
    pub authenticated_channel_receipt_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyRolloutStatusV1 {
    Pending,
    Delivered,
    Staged,
    Active,
    Rejected,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRolloutStateV1 {
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub target: PolicyTargetV1,
    pub desired_candidate_content_id: String,
    pub state: PolicyRolloutStatusV1,
    pub latest_acknowledgement_content_id: Option<String>,
    pub transition_version: u64,
    pub updated_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Keeps the signed profile and its node-specific delivery candidate in one digest domain.
pub struct PolicyBundleV1 {
    pub schema_version: u32,
    pub candidate: PolicyDeliveryCandidateV1,
    pub profile_artifact: ProfileCandidateArtifactV1,
    pub profile_signing_public_key: Vec<u8>,
    pub bundle_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleChunkV1 {
    pub bundle_digest: String,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub chunk_sha256: String,
    pub payload: Vec<u8>,
}

pub fn policy_custom_resource_definition() -> Result<CustomResourceDefinition> {
    bounded_custom_resource_definition(WorkloadProtectionPolicy::crd(), false)
}

pub fn exception_custom_resource_definition() -> Result<CustomResourceDefinition> {
    bounded_custom_resource_definition(WorkloadProtectionException::crd(), true)
}

fn bounded_custom_resource_definition(
    mut crd: CustomResourceDefinition,
    immutable_spec: bool,
) -> Result<CustomResourceDefinition> {
    for version in &mut crd.spec.versions {
        let schema = version
            .schema
            .as_mut()
            .and_then(|validation| validation.open_api_v3_schema.as_mut())
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: "<kubernetes-crd>",
                    code: "CFG_CRD_SCHEMA",
                    reason: "the generated CRD version has no OpenAPI schema".to_owned(),
                }
                .build()
            })?;
        let mut value = serde_json::to_value(&*schema).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: "<kubernetes-crd>",
                code: "CFG_CRD_SCHEMA",
                reason: format!("the generated CRD schema cannot be encoded: {error}"),
            }
            .build()
        })?;
        // Kubernetes limits the allowed keywords at a resource root when status is enabled.
        bound_openapi_schema(&mut value, true);
        if immutable_spec {
            value
                .pointer_mut("/properties/spec")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    PolicyValidationSnafu {
                        policy_id: "<kubernetes-crd>",
                        code: "CFG_CRD_SCHEMA",
                        reason: "the exception CRD has no spec schema".to_owned(),
                    }
                    .build()
                })?
                .insert(
                    "x-kubernetes-validations".to_owned(),
                    serde_json::json!([{
                        "rule": "self == oldSelf",
                        "message": "WorkloadProtectionException spec is immutable"
                    }]),
                );
        }
        *schema = serde_json::from_value(value).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: "<kubernetes-crd>",
                code: "CFG_CRD_SCHEMA",
                reason: format!("the bounded CRD schema cannot be decoded: {error}"),
            }
            .build()
        })?;
    }
    Ok(crd)
}

pub fn canonical_policy_document_bytes(document: &PolicyDocumentV1) -> Result<Vec<u8>> {
    canonical_cbor(document.profile_id(), document)
}

pub fn canonical_policy_spec_digest(document: &PolicyDocumentV1) -> Result<String> {
    Ok(sha256(&canonical_policy_document_bytes(document)?))
}

pub fn canonical_kubernetes_policy_spec_bytes(
    spec: &WorkloadProtectionPolicySpec,
) -> Result<Vec<u8>> {
    canonical_cbor("<kubernetes-policy>", spec)
}

pub fn canonical_kubernetes_policy_spec_digest(
    spec: &WorkloadProtectionPolicySpec,
) -> Result<String> {
    Ok(sha256(&canonical_kubernetes_policy_spec_bytes(spec)?))
}

pub fn policy_custom_resource(
    name: &str,
    namespace: &str,
    spec: WorkloadProtectionPolicySpec,
) -> Result<WorkloadProtectionPolicy> {
    ensure!(
        !name.is_empty() && !namespace.is_empty(),
        PolicyValidationSnafu {
            policy_id: name,
            code: "CFG_CRD_METADATA",
            reason: "the policy resource needs a name and namespace",
        }
    );
    let mut resource = WorkloadProtectionPolicy::new(name, spec);
    resource.metadata.namespace = Some(namespace.to_owned());
    Ok(resource)
}

pub fn lower_kubernetes_policy(
    resource: &WorkloadProtectionPolicy,
    tenant_id: &str,
    cluster_uid: &str,
    namespace_uid: &str,
) -> Result<PolicyDocumentV1> {
    let object_uid = required_metadata(resource.metadata.uid.as_deref(), "object UID")?;
    let generation = resource.metadata.generation.ok_or_else(|| {
        PolicyValidationSnafu {
            policy_id: object_uid,
            code: "CFG_CRD_METADATA",
            reason: "the CRD has no object generation".to_owned(),
        }
        .build()
    })?;
    let generation = u64::try_from(generation).map_err(|_| {
        PolicyValidationSnafu {
            policy_id: object_uid,
            code: "CFG_CRD_METADATA",
            reason: "the CRD object generation must be positive".to_owned(),
        }
        .build()
    })?;
    validate_public_policy(&resource.spec, object_uid)?;
    ensure!(
        generation > 0
            && canonical_uuid(object_uid)
            && canonical_uuid(tenant_id)
            && canonical_uuid(cluster_uid)
            && canonical_uuid(namespace_uid),
        PolicyValidationSnafu {
            policy_id: object_uid,
            code: "CFG_CRD_IDENTITY",
            reason:
                "policy lowering needs canonical authenticated identities and a nonzero generation",
        }
    );

    let protected_scope_id = derived_uuid(&[
        b"MITHRIL-KUBERNETES-PROTECTED-SCOPE-V1\0",
        object_uid.as_bytes(),
    ]);
    let execution_set_id = derived_uuid(&[
        b"MITHRIL-KUBERNETES-POLICY-EXECUTION-SET-V1\0",
        object_uid.as_bytes(),
    ]);
    let label_requirements = lower_label_selector(&resource.spec.pod_selector);
    let mut workload_selectors = Vec::with_capacity(resource.spec.containers.len());
    let mut entry_role_assignments = Vec::with_capacity(resource.spec.containers.len() * 2);
    let mut role_selectors = BTreeMap::<String, BTreeSet<String>>::new();
    let mut role_entry_kinds = BTreeMap::<String, BTreeSet<EntryKindV1>>::new();
    for (index, container) in resource.spec.containers.iter().enumerate() {
        let selector_id = format!("container-{index}");
        workload_selectors.push(WorkloadSelectorV1 {
            workload_selector_id: selector_id.clone(),
            cluster_uids: vec![cluster_uid.to_owned()],
            namespace_uids: vec![namespace_uid.to_owned()],
            controller_uids: Vec::new(),
            service_account_uids: Vec::new(),
            pod_label_requirements: label_requirements.clone(),
            container_names: sorted_unique(container.names.clone()),
            container_kinds: sorted_unique(
                container
                    .kinds
                    .iter()
                    .copied()
                    .map(ContainerKindV1::from)
                    .collect(),
            ),
            // Rollout and OCI admission bind the same digest without trusting a registry name.
            image_digests: sorted_unique(
                container
                    .images
                    .iter()
                    .filter_map(|image| pinned_image_digest(image).map(str::to_owned))
                    .collect(),
            ),
        });
        for (suffix, role, entry_kind, classification, ambiguity, restricted) in [
            (
                "initial",
                &container.initial_role,
                EntryKindV1::ContainerStart,
                RootClassificationV1::ExactInitial,
                AmbiguityDispositionV1::DenyProtectedEffects,
                None,
            ),
            (
                "external",
                &container.external_role,
                EntryKindV1::ExternalRuntimeUnknown,
                RootClassificationV1::ConservativeExternalUnknown,
                AmbiguityDispositionV1::RestrictExternal,
                Some(container.external_role.clone()),
            ),
        ] {
            role_selectors
                .entry(role.clone())
                .or_default()
                .insert(selector_id.clone());
            role_entry_kinds
                .entry(role.clone())
                .or_default()
                .insert(entry_kind);
            entry_role_assignments.push(EntryRoleAssignmentV1 {
                assignment_id: format!("container-{index}-{suffix}"),
                workload_selector_ids: vec![selector_id.clone()],
                entry_kinds: vec![entry_kind],
                container_kinds: workload_selectors[index].container_kinds.clone(),
                immutable_definition_digests: Vec::new(),
                accepted_classifications: vec![classification],
                required_purpose_source_capability_id: None,
                required_administrative_exec_approval: false,
                resulting_role_id: role.clone(),
                on_missing_or_unequal_ambiguity: ambiguity,
                unknown_restricted_role_id: restricted,
            });
        }
    }
    entry_role_assignments.sort_by(|left, right| left.assignment_id.cmp(&right.assignment_id));

    let all_selector_ids = workload_selectors
        .iter()
        .map(|selector| selector.workload_selector_id.clone())
        .collect::<Vec<_>>();
    let mut path_selectors = Vec::new();
    let mut path_selector_ids = BTreeMap::<(String, bool), String>::new();
    let mut rules = Vec::new();
    let mut effect_family_defaults = Vec::new();
    let mut destination_policies = Vec::new();
    let mut ipc_relationship_rules = Vec::new();
    let mut file_rule_actions = BTreeMap::new();

    let mut roles = resource.spec.roles.clone();
    roles.sort_by(|left, right| left.name.cmp(&right.name));
    for role in &roles {
        let selectors = role_selectors
            .get(&role.name)
            .map(|values| values.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let entry_kinds = role_entry_kinds
            .get(&role.name)
            .map(|values| values.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let subject = rule_subject(
            selectors,
            protected_scope_id.clone(),
            execution_set_id.clone(),
            entry_kinds,
            role.name.clone(),
        );
        for file in &role.files {
            let selector_id = path_selector_id(
                &mut path_selectors,
                &mut path_selector_ids,
                &file.path,
                file.recursive,
            );
            let operations = sorted_unique(
                file.operations
                    .iter()
                    .copied()
                    .map(KubernetesFileOperationV1::internal_name)
                    .map(str::to_owned)
                    .collect(),
            );
            rules.push(local_rule(
                file.name.clone(),
                subject.clone(),
                EffectFamilyV1::File,
                operations,
                LocalObjectSelectorV1::PathSelectors {
                    path_selector_ids: vec![selector_id],
                },
                file.action,
            ));
            file_rule_actions.insert(file.name.clone(), (file.action, file.operations.clone()));
        }
        for execution in &role.execution {
            let selector_id = path_selector_id(
                &mut path_selectors,
                &mut path_selector_ids,
                &execution.path,
                execution.recursive,
            );
            rules.push(local_rule(
                execution.name.clone(),
                subject.clone(),
                EffectFamilyV1::Exec,
                sorted_unique(
                    execution
                        .operations
                        .iter()
                        .copied()
                        .map(KubernetesExecutionOperationV1::internal_name)
                        .map(str::to_owned)
                        .collect(),
                ),
                LocalObjectSelectorV1::PathSelectors {
                    path_selector_ids: vec![selector_id],
                },
                execution.action,
            ));
        }
        let socket_actions = role
            .network
            .socket_controls
            .iter()
            .flat_map(|rule| {
                rule.operations
                    .iter()
                    .copied()
                    .map(move |operation| (operation, rule.action))
            })
            .collect::<BTreeMap<_, _>>();
        effect_family_defaults.extend(conservative_defaults(&role.name, &socket_actions));
        for destination in &role.network.destinations {
            let mut ipv4_prefixes = destination
                .cidrs
                .iter()
                .filter(|cidr| !cidr.contains(':'))
                .cloned()
                .collect::<Vec<_>>();
            let mut ipv6_prefixes = destination
                .cidrs
                .iter()
                .filter(|cidr| cidr.contains(':'))
                .cloned()
                .collect::<Vec<_>>();
            ipv4_prefixes.sort();
            ipv6_prefixes.sort();
            destination_policies.push(DestinationPolicyRecordV1 {
                destination_policy_id: destination.name.clone(),
                protocols: sorted_unique(
                    destination
                        .protocols
                        .iter()
                        .copied()
                        .map(NetworkProtocolV1::from)
                        .collect(),
                ),
                ipv4_prefixes,
                ipv6_prefixes,
                port_ranges: sorted_unique(
                    destination
                        .ports
                        .iter()
                        .copied()
                        .map(NetworkPortRangeV1::from)
                        .collect(),
                ),
                required_network_namespace_ids: Vec::new(),
                service_identities: Vec::new(),
                final_address_required: true,
            });
            rules.push(local_rule(
                destination.name.clone(),
                subject.clone(),
                EffectFamilyV1::Network,
                sorted_unique(
                    destination
                        .operations
                        .iter()
                        .copied()
                        .map(KubernetesNetworkOperationV1::internal_name)
                        .map(str::to_owned)
                        .collect(),
                ),
                LocalObjectSelectorV1::Destinations {
                    destination_policy_ids: vec![destination.name.clone()],
                },
                destination.action,
            ));
        }
        for process_control in &role.process_control {
            let (name, target_role, operations, action) = match process_control {
                ProcessControlRuleV1::Signal {
                    name,
                    target_role,
                    signals,
                    action,
                } => (
                    name,
                    target_role,
                    signals
                        .iter()
                        .map(|signal| format!("SIGNAL_{signal}"))
                        .collect(),
                    *action,
                ),
                ProcessControlRuleV1::Ptrace {
                    name,
                    target_role,
                    requests,
                    action,
                } => (
                    name,
                    target_role,
                    requests
                        .iter()
                        .map(|request| format!("PTRACE_ACCESS_{request}"))
                        .collect(),
                    *action,
                ),
            };
            rules.push(local_rule(
                name.clone(),
                subject.clone(),
                EffectFamilyV1::Privilege,
                sorted_unique(operations),
                LocalObjectSelectorV1::SecurityObjects {
                    security_object_ids: vec!["PROCESS".to_owned()],
                    target_selector_ids: vec![target_role.clone()],
                },
                action,
            ));
        }
        for relationship in &role.unix_streams {
            ipc_relationship_rules.push(IpcRelationshipRuleV1 {
                relationship_rule_id: relationship.name.clone(),
                source_role_ids: vec![role.name.clone()],
                peer_role_ids: sorted_unique(relationship.peer_roles.clone()),
                channel_class_ids: vec!["UNIX_STREAM".to_owned()],
                operations: vec!["IPC_ACCESS".to_owned()],
                requested_disposition: relationship.action.into(),
                errno: (relationship.action == KubernetesRuleActionV1::Deny)
                    .then_some(ErrnoV1::Eacces),
            });
        }
    }
    rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    path_selectors.sort_by(|left, right| left.path_selector_id.cmp(&right.path_selector_id));
    destination_policies
        .sort_by(|left, right| left.destination_policy_id.cmp(&right.destination_policy_id));
    effect_family_defaults.sort_by(|left, right| {
        (&left.role_ids, left.effect_family, &left.operations).cmp(&(
            &right.role_ids,
            right.effect_family,
            &right.operations,
        ))
    });
    ipc_relationship_rules
        .sort_by(|left, right| left.relationship_rule_id.cmp(&right.relationship_rule_id));

    let file_exception_grants = resource
        .spec
        .exception_grants
        .iter()
        .map(|grant| {
            ensure!(
                grant.file_rules.iter().all(|rule| {
                    file_rule_actions
                        .get(rule)
                        .is_some_and(|(action, operations)| {
                            *action == KubernetesRuleActionV1::Deny
                                && operations.iter().all(|operation| {
                                    matches!(
                                        operation,
                                        KubernetesFileOperationV1::OpenRead
                                            | KubernetesFileOperationV1::OpenWrite
                                    )
                                })
                        })
                }),
                PolicyValidationSnafu {
                    policy_id: object_uid,
                    code: "CFG_EXCEPTION_GRANT",
                    reason: format!(
                        "exception grant `{}` must reference denied file-open rules",
                        grant.name
                    ),
                }
            );
            Ok(FileExceptionGrantTemplateV1 {
                grant_id: grant.name.clone(),
                denied_file_rule_ids: sorted_unique(grant.file_rules.clone()),
                maximum_duration_ns: parse_duration_ns(&grant.maximum_duration, object_uid)?,
                maximum_uses: grant.maximum_uses,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let role_definitions = roles
        .iter()
        .map(|role| RoleDefinitionV1 {
            role_id: role.name.clone(),
            maximum_native_depth: 1,
            default_process_state_id: "base".to_owned(),
            permitted_entry_kinds: role_entry_kinds
                .get(&role.name)
                .map(|values| values.iter().copied().collect())
                .unwrap_or_default(),
            description_artifact_digest: None,
        })
        .collect::<Vec<_>>();
    let role_ids = role_definitions
        .iter()
        .map(|role| role.role_id.clone())
        .collect::<Vec<_>>();
    let entry_kind_ids = role_entry_kinds
        .values()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let finding = fixed_default_finding();
    let network_policy = (!destination_policies.is_empty()).then_some(NetworkPolicyV1 {
        dns_mode: DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses,
        destination_policies,
    });

    let document = PolicyDocumentV1 {
        api_version: "mithril.erebor.dev/v1".to_owned(),
        kind: "ProtectionPolicy".to_owned(),
        metadata: PolicyMetadataV1 {
            profile_id: object_uid.to_owned(),
            profile_version: generation,
            trust_domain_id: tenant_id.to_owned(),
            valid_from_utc: "1970-01-01T00:00:00Z".to_owned(),
            valid_until_utc: None,
        },
        required_capability_ids: vec![
            "EXACT_NATIVE_IDENTITY".to_owned(),
            "LOCAL_EFFECT_OBSERVATION".to_owned(),
        ],
        protected_universe: ProtectedUniverseV1 {
            workload_selector_ids: all_selector_ids.clone(),
            protected_scope_ids: vec![protected_scope_id],
            execution_set_ids: vec![execution_set_id],
            role_ids,
            entry_kind_ids,
            object_class_ids: if path_selectors.is_empty() {
                Vec::new()
            } else {
                vec!["KUBERNETES_PATH".to_owned()]
            },
            provider_account_ids: Vec::new(),
        },
        workload_selectors,
        classifier_bindings: if path_selectors.is_empty() {
            Vec::new()
        } else {
            vec![ObjectClassifierBindingV1 {
                classifier_binding_id: "kubernetes-path".to_owned(),
                object_class_id: "KUBERNETES_PATH".to_owned(),
                // Path selectors carry the authority. This classifier only anchors the
                // internal object registry and does not add volume or content identity.
                selector: ObjectClassifierSelectorV1::FilesystemObject {
                    workload_selector_ids: all_selector_ids,
                    mount_source_class_ids: Vec::new(),
                    relative_component_bytes: Vec::new(),
                    filesystem_type_ids: Vec::new(),
                    required_object_type: FilesystemObjectTypeV1::RegularFile,
                },
                required_capability_ids: vec!["EXACT_FILE_OBJECT".to_owned()],
                unknown_result: UnknownClassifierResultV1::Deny,
            }]
        },
        path_selectors,
        network_policy,
        path_tree_deny_floors: Vec::new(),
        path_pattern_precedence: Default::default(),
        roles: role_definitions,
        entry_role_assignments,
        native_transition_rules: Vec::new(),
        state_bit_definitions: Vec::new(),
        process_state_definitions: vec![ProcessStateDefinitionV1 {
            process_state_id: "base".to_owned(),
            state_bits: Vec::new(),
        }],
        native_authority_state_rules: Vec::new(),
        ipc_relationship_rules,
        unmatched_ipc_disposition: PolicyDispositionV1::Deny,
        effect_family_defaults,
        authority_behavior_rules: Vec::new(),
        correlation_package_bindings: Vec::new(),
        default_postures: DefaultPosturesV1 {
            missing_task_identity: DefaultPostureActionV1 {
                requested_disposition: PolicyDispositionV1::Deny,
                finding: finding.clone(),
                unknown_restricted_role_id: None,
            },
            required_classifier_unknown: DefaultPostureActionV1 {
                requested_disposition: PolicyDispositionV1::Deny,
                finding: finding.clone(),
                unknown_restricted_role_id: None,
            },
            unresolved_or_external_root: DefaultPostureActionV1 {
                requested_disposition: PolicyDispositionV1::Deny,
                finding,
                unknown_restricted_role_id: resource
                    .spec
                    .containers
                    .first()
                    .map(|container| container.external_role.clone()),
            },
        },
        notification_routes: Vec::new(),
        response_bindings: Vec::new(),
        file_exception_grants,
        exceptions: Vec::new(),
        rules,
        source_coverage_health_rules: Vec::new(),
        rollout: RolloutV1 {
            rollout_generation: generation,
            desired_profile_mode: resource.spec.mode.into(),
            cohort_selection: CohortSelectionV1::AllBoundExecutionSets,
            explicit_execution_set_ids: Vec::new(),
            selector_hash_modulus: 1,
            selected_bucket_ids: vec![0],
        },
    };
    // Lowering validates the closed document before reconciliation can persist the source.
    document.validate_closed()?;
    Ok(document)
}

fn validate_public_policy(spec: &WorkloadProtectionPolicySpec, policy_id: &str) -> Result<()> {
    let role_names = spec
        .roles
        .iter()
        .map(|role| role.name.as_str())
        .collect::<BTreeSet<_>>();
    let container_roles = spec.containers.iter().flat_map(|container| {
        [
            container.initial_role.as_str(),
            container.external_role.as_str(),
        ]
    });
    ensure!(
        !spec.containers.is_empty()
            && spec.containers.len() <= 256
            && !spec.roles.is_empty()
            && spec.roles.len() <= 256
            && role_names.len() == spec.roles.len()
            && container_roles
                .clone()
                .all(|role| role_names.contains(role))
            && role_names
                .iter()
                .all(|role| container_roles.clone().any(|used| used == *role)),
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_KUBERNETES_POLICY_ROLES",
            reason: "containers and roles must be nonempty, unique, bounded, and fully referenced",
        }
    );
    for container in &spec.containers {
        ensure!(
            !container.names.is_empty()
                && !container.kinds.is_empty()
                && !container.images.is_empty()
                && all_distinct(&container.names)
                && all_distinct(&container.kinds)
                && all_distinct(&container.images)
                && container.images.iter().all(|image| pinned_image(image)),
            PolicyValidationSnafu {
                policy_id,
                code: "CFG_KUBERNETES_CONTAINER_MATCH",
                reason:
                    "each container match needs distinct names, kinds, and digest-pinned images",
            }
        );
    }
    let mut names = BTreeSet::new();
    let mut socket_actions = BTreeMap::new();
    for role in &spec.roles {
        for rule in &role.files {
            validate_path_rule(
                policy_id,
                &rule.name,
                &rule.path,
                rule.recursive,
                rule.action,
                &mut names,
            )?;
            ensure!(
                !rule.operations.is_empty() && all_distinct(&rule.operations),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_FILE_RULE",
                    reason: format!(
                        "file rule `{}` has duplicate or empty operations",
                        rule.name
                    ),
                }
            );
        }
        for rule in &role.execution {
            validate_path_rule(
                policy_id,
                &rule.name,
                &rule.path,
                rule.recursive,
                rule.action,
                &mut names,
            )?;
            ensure!(
                !rule.operations.is_empty() && all_distinct(&rule.operations),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_EXECUTION_RULE",
                    reason: format!(
                        "execution rule `{}` has duplicate or empty operations",
                        rule.name
                    ),
                }
            );
        }
        socket_actions.clear();
        for rule in &role.network.socket_controls {
            ensure!(
                !rule.operations.is_empty()
                    && all_distinct(&rule.operations)
                    && rule.operations.iter().all(|operation| {
                        socket_actions
                            .insert(*operation, rule.action)
                            .is_none_or(|old| old == rule.action)
                    }),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_SOCKET_CONTROL",
                    reason: format!(
                        "role `{}` has empty, duplicate, or conflicting socket controls",
                        role.name
                    ),
                }
            );
        }
        for rule in &role.network.destinations {
            ensure!(
                names.insert(rule.name.as_str())
                    && !rule.operations.is_empty()
                    && !rule.protocols.is_empty()
                    && !rule.cidrs.is_empty()
                    && !rule.ports.is_empty()
                    && all_distinct(&rule.operations)
                    && all_distinct(&rule.protocols)
                    && all_distinct(&rule.cidrs)
                    && all_distinct(&rule.ports),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_NETWORK_RULE",
                    reason: format!(
                        "network rule `{}` is duplicate, empty, or has duplicate values",
                        rule.name
                    ),
                }
            );
        }
        for rule in &role.process_control {
            let (name, target_role, values, action, ptrace) = match rule {
                ProcessControlRuleV1::Signal {
                    name,
                    target_role,
                    signals,
                    action,
                } => (name, target_role, signals, action, false),
                ProcessControlRuleV1::Ptrace {
                    name,
                    target_role,
                    requests,
                    action,
                } => (name, target_role, requests, action, true),
            };
            ensure!(
                names.insert(name.as_str())
                    && role_names.contains(target_role.as_str())
                    && !values.is_empty()
                    && all_distinct(values)
                    && (!ptrace || *action == KubernetesRuleActionV1::Deny),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_PROCESS_CONTROL",
                    reason: format!("process-control rule `{name}` is invalid"),
                }
            );
        }
        for rule in &role.unix_streams {
            ensure!(
                names.insert(rule.name.as_str())
                    && !rule.peer_roles.is_empty()
                    && all_distinct(&rule.peer_roles)
                    && rule
                        .peer_roles
                        .iter()
                        .all(|peer| role_names.contains(peer.as_str())),
                PolicyValidationSnafu {
                    policy_id,
                    code: "CFG_KUBERNETES_UNIX_STREAM",
                    reason: format!("Unix-stream rule `{}` is invalid", rule.name),
                }
            );
        }
    }
    let grant_names = spec
        .exception_grants
        .iter()
        .map(|grant| grant.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        grant_names.len() == spec.exception_grants.len()
            && spec.exception_grants.iter().all(|grant| {
                !grant.file_rules.is_empty()
                    && all_distinct(&grant.file_rules)
                    && grant.maximum_uses > 0
                    && parse_duration_ns(&grant.maximum_duration, policy_id).is_ok()
            }),
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_EXCEPTION_GRANT",
            reason: "exception grants must be unique, nonempty, and bounded",
        }
    );
    validate_label_selector(&spec.pod_selector, policy_id)
}

fn validate_path_rule<'a>(
    policy_id: &str,
    name: &'a str,
    path: &str,
    recursive: bool,
    action: KubernetesRuleActionV1,
    names: &mut BTreeSet<&'a str>,
) -> Result<()> {
    ensure!(
        names.insert(name)
            && super::canonical_path_components(policy_id, path).is_ok()
            && (!recursive || action == KubernetesRuleActionV1::Deny),
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_KUBERNETES_PATH_RULE",
            reason: format!(
                "path rule `{name}` is duplicate, noncanonical, or uses unqualified recursive allow"
            ),
        }
    );
    Ok(())
}

fn validate_label_selector(selector: &KubernetesLabelSelectorV1, policy_id: &str) -> Result<()> {
    ensure!(
        selector.match_labels.len() <= 256
            && selector.match_expressions.len() <= 256
            && selector.match_expressions.iter().all(|requirement| {
                !requirement.key.is_empty()
                    && match requirement.operator {
                        KubernetesLabelSelectorOperatorV1::In
                        | KubernetesLabelSelectorOperatorV1::NotIn => {
                            !requirement.values.is_empty() && all_distinct(&requirement.values)
                        }
                        KubernetesLabelSelectorOperatorV1::Exists
                        | KubernetesLabelSelectorOperatorV1::DoesNotExist => {
                            requirement.values.is_empty()
                        }
                    }
            }),
        PolicyValidationSnafu {
            policy_id,
            code: "CFG_KUBERNETES_LABEL_SELECTOR",
            reason: "podSelector is not a valid bounded Kubernetes label selector",
        }
    );
    Ok(())
}

fn lower_label_selector(selector: &KubernetesLabelSelectorV1) -> Vec<LabelRequirementV1> {
    let mut requirements = selector
        .match_labels
        .iter()
        .map(|(key, value)| LabelRequirementV1 {
            key: key.clone(),
            operator: LabelOperatorV1::In,
            values: vec![value.clone()],
        })
        .chain(
            selector
                .match_expressions
                .iter()
                .map(|requirement| LabelRequirementV1 {
                    key: requirement.key.clone(),
                    operator: requirement.operator.into(),
                    values: sorted_unique(requirement.values.clone()),
                }),
        )
        .collect::<Vec<_>>();
    requirements.sort_by(|left, right| {
        (&left.key, left.operator, &left.values).cmp(&(&right.key, right.operator, &right.values))
    });
    requirements
}

fn rule_subject(
    workload_selector_ids: Vec<String>,
    protected_scope_id: String,
    execution_set_id: String,
    entry_kind_ids: Vec<EntryKindV1>,
    role_id: String,
) -> CommonSubjectMatchV1 {
    CommonSubjectMatchV1 {
        workload_selector_ids,
        protected_scope_ids: vec![protected_scope_id],
        execution_set_ids: vec![execution_set_id],
        entry_kind_ids,
        role_ids: vec![role_id],
        required_process_state_ids: vec!["base".to_owned()],
        forbidden_process_state_ids: Vec::new(),
    }
}

fn path_selector_id(
    selectors: &mut Vec<PathSelectorV1>,
    ids: &mut BTreeMap<(String, bool), String>,
    path: &str,
    recursive: bool,
) -> String {
    let key = (path.to_owned(), recursive);
    if let Some(id) = ids.get(&key) {
        return id.clone();
    }
    let id = format!("path-{}", ids.len());
    selectors.push(if recursive {
        PathSelectorV1::recursive(&id, path, "KUBERNETES_PATH")
    } else {
        PathSelectorV1::exact(&id, path, "KUBERNETES_PATH")
    });
    ids.insert(key, id.clone());
    id
}

fn local_rule(
    rule_id: String,
    subject: CommonSubjectMatchV1,
    family: EffectFamilyV1,
    operations: Vec<String>,
    object: LocalObjectSelectorV1,
    action: KubernetesRuleActionV1,
) -> DetectionDispositionRuleV1 {
    DetectionDispositionRuleV1 {
        schema_version: 1,
        rule_id,
        enabled: true,
        priority: 0,
        evaluation_stage: EvaluationStageV1::LocalPreEffect,
        rule_match: RuleMatchV1::LocalPreEffect(LocalEffectMatchV1 {
            subject,
            effect_families: vec![family],
            operation_ids: operations,
            object,
            binding_lifecycle_states: vec![BindingLifecycleV1::Active],
            required_proof: kernel_decision_proof(),
        }),
        requested_disposition: action.into(),
        errno: (action == KubernetesRuleActionV1::Deny).then_some(ErrnoV1::Eacces),
        finding: None,
        response_binding_ids: Vec::new(),
        fallback_by_condition: Vec::new(),
        budgets: BudgetSetV1::default(),
        overrides_rule_ids: Vec::new(),
        exception_ids: Vec::new(),
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
    }
}

fn conservative_defaults(
    role_id: &str,
    socket_actions: &BTreeMap<KubernetesSocketControlOperationV1, KubernetesRuleActionV1>,
) -> Vec<EffectFamilyDefaultV1> {
    let mut defaults = vec![
        default_rule(
            role_id,
            EffectFamilyV1::File,
            &[
                "OPEN_READ",
                "OPEN_WRITE",
                "READ",
                "WRITE",
                "MMAP_READ",
                "MMAP_WRITE",
                "MPROTECT",
                "CREATE",
                "SETATTR",
                "UNLINK",
                "LINK",
                "RENAME",
            ],
            KubernetesRuleActionV1::Deny,
        ),
        default_rule(
            role_id,
            EffectFamilyV1::Exec,
            &["EXECUTE", "MMAP_EXEC", "MPROTECT"],
            KubernetesRuleActionV1::Deny,
        ),
        default_rule(
            role_id,
            EffectFamilyV1::Network,
            &["BIND", "CONNECT", "SEND", "RECEIVE"],
            KubernetesRuleActionV1::Deny,
        ),
        default_rule(
            role_id,
            EffectFamilyV1::Privilege,
            &["PTRACE", "SIGNAL"],
            KubernetesRuleActionV1::Deny,
        ),
    ];
    for operation in [
        KubernetesSocketControlOperationV1::Create,
        KubernetesSocketControlOperationV1::Listen,
        KubernetesSocketControlOperationV1::Accept,
        KubernetesSocketControlOperationV1::Shutdown,
        KubernetesSocketControlOperationV1::SetSocketOption,
    ] {
        defaults.push(default_rule(
            role_id,
            EffectFamilyV1::Network,
            &[operation.internal_name()],
            socket_actions
                .get(&operation)
                .copied()
                .unwrap_or(KubernetesRuleActionV1::Deny),
        ));
    }
    defaults
}

fn default_rule(
    role_id: &str,
    family: EffectFamilyV1,
    operations: &[&str],
    action: KubernetesRuleActionV1,
) -> EffectFamilyDefaultV1 {
    EffectFamilyDefaultV1 {
        role_ids: vec![role_id.to_owned()],
        effect_family: family,
        operations: sorted_unique(operations.iter().map(|value| (*value).to_owned()).collect()),
        requested_disposition: action.into(),
        errno: (action == KubernetesRuleActionV1::Deny).then_some(ErrnoV1::Eacces),
        finding: None,
    }
}

fn kernel_decision_proof() -> ProofQualityPredicateV1 {
    ProofQualityPredicateV1 {
        source_authority: vec![SourceAuthorityV1::KernelDecision],
        local_subject_binding: vec![LocalSubjectBindingV1::ExactTask],
        remote_subject_binding: vec![RemoteSubjectBindingV1::None],
        operation_result_authority: vec![OperationResultAuthorityV1::PreEffectDecision],
        temporal_coverage: vec![TemporalCoverageV1::Complete],
        integrity: vec![ProofIntegrityV1::LocalAttested],
    }
}

fn fixed_default_finding() -> FindingSpecV1 {
    FindingSpecV1 {
        reason_code: "KUBERNETES_POLICY_FAIL_CLOSED".to_owned(),
        severity: SeverityV1::High,
        route_ids: Vec::new(),
        evidence_level: EvidenceLevelV1::Standard,
        title_template_id: None,
    }
}

fn parse_duration_ns(value: &str, policy_id: &str) -> Result<u64> {
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix("ns") {
        (digits, 1_u64)
    } else if let Some(digits) = value.strip_suffix("us") {
        (digits, 1_000)
    } else if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1_000_000)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000_000_000)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60 * 1_000_000_000)
    } else if let Some(digits) = value.strip_suffix('h') {
        (digits, 60 * 60 * 1_000_000_000)
    } else {
        ("", 0)
    };
    let duration = digits
        .parse::<u64>()
        .ok()
        .and_then(|duration| duration.checked_mul(multiplier))
        .filter(|duration| *duration > 0)
        .ok_or_else(|| {
            PolicyValidationSnafu {
                policy_id,
                code: "CFG_DURATION",
                reason: format!("`{value}` is not a bounded nonzero duration"),
            }
            .build()
        })?;
    Ok(duration)
}

fn pinned_image(value: &str) -> bool {
    pinned_image_digest(value).is_some()
}

fn pinned_image_digest(value: &str) -> Option<&str> {
    let (name, digest) = value.rsplit_once('@')?;
    let encoded = digest.strip_prefix("sha256:")?;
    (!name.is_empty()
        && encoded.len() == 64
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(digest)
}

fn all_distinct<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

fn derived_uuid(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
}

impl From<KubernetesContainerKindV1> for ContainerKindV1 {
    fn from(value: KubernetesContainerKindV1) -> Self {
        match value {
            KubernetesContainerKindV1::Init => Self::Init,
            KubernetesContainerKindV1::Sidecar => Self::Sidecar,
            KubernetesContainerKindV1::Application => Self::Application,
            KubernetesContainerKindV1::Ephemeral => Self::Ephemeral,
        }
    }
}

impl From<KubernetesPolicyModeV1> for ProfileModeV1 {
    fn from(value: KubernetesPolicyModeV1) -> Self {
        match value {
            KubernetesPolicyModeV1::Observe => Self::Observe,
            KubernetesPolicyModeV1::Protect => Self::Protect,
        }
    }
}

impl From<KubernetesRuleActionV1> for PolicyDispositionV1 {
    fn from(value: KubernetesRuleActionV1) -> Self {
        match value {
            KubernetesRuleActionV1::Allow => Self::Allow,
            KubernetesRuleActionV1::Deny => Self::Deny,
        }
    }
}

impl From<KubernetesLabelSelectorOperatorV1> for LabelOperatorV1 {
    fn from(value: KubernetesLabelSelectorOperatorV1) -> Self {
        match value {
            KubernetesLabelSelectorOperatorV1::In => Self::In,
            KubernetesLabelSelectorOperatorV1::NotIn => Self::NotIn,
            KubernetesLabelSelectorOperatorV1::Exists => Self::Exists,
            KubernetesLabelSelectorOperatorV1::DoesNotExist => Self::DoesNotExist,
        }
    }
}

impl From<KubernetesNetworkProtocolV1> for NetworkProtocolV1 {
    fn from(value: KubernetesNetworkProtocolV1) -> Self {
        match value {
            KubernetesNetworkProtocolV1::Tcp => Self::Tcp,
            KubernetesNetworkProtocolV1::Udp => Self::Udp,
        }
    }
}

impl From<KubernetesNetworkPortRangeV1> for NetworkPortRangeV1 {
    fn from(value: KubernetesNetworkPortRangeV1) -> Self {
        Self {
            first: value.first,
            last: value.last,
        }
    }
}

impl KubernetesFileOperationV1 {
    const fn internal_name(self) -> &'static str {
        match self {
            Self::OpenRead => "OPEN_READ",
            Self::OpenWrite => "OPEN_WRITE",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::MmapRead => "MMAP_READ",
            Self::MmapWrite => "MMAP_WRITE",
            Self::Create => "CREATE",
            Self::SetAttributes => "SETATTR",
            Self::Unlink => "UNLINK",
            Self::Link => "LINK",
            Self::Rename => "RENAME",
        }
    }
}

impl KubernetesExecutionOperationV1 {
    const fn internal_name(self) -> &'static str {
        match self {
            Self::Execute => "EXECUTE",
            Self::MmapExecute => "MMAP_EXEC",
            Self::Mprotect => "MPROTECT",
        }
    }
}

impl KubernetesNetworkOperationV1 {
    const fn internal_name(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Send => "SEND",
            Self::Receive => "RECEIVE",
            Self::Bind => "BIND",
        }
    }
}

impl KubernetesSocketControlOperationV1 {
    const fn internal_name(self) -> &'static str {
        match self {
            Self::Create => "SOCKET_CREATE",
            Self::Listen => "LISTEN",
            Self::Accept => "ACCEPT",
            Self::Shutdown => "SHUTDOWN",
            Self::SetSocketOption => "SETSOCKOPT",
        }
    }
}

impl PolicySourceRevisionV1 {
    pub fn from_resource(
        resource: &WorkloadProtectionPolicy,
        policy: &PolicyDocumentV1,
        tenant_id: &str,
        cluster_uid: &str,
        namespace_uid: &str,
        state: PolicySourceStateV1,
    ) -> Result<Self> {
        let metadata = &resource.metadata;
        let object_uid = required_metadata(metadata.uid.as_deref(), "object UID")?;
        let namespace_name = required_metadata(metadata.namespace.as_deref(), "namespace")?;
        let object_name = required_metadata(metadata.name.as_deref(), "object name")?;
        let generation = metadata.generation.ok_or_else(|| {
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_CRD_METADATA",
                reason: "the CRD has no object generation".to_owned(),
            }
            .build()
        })?;
        let object_generation = u64::try_from(generation).map_err(|_| {
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_CRD_METADATA",
                reason: "the CRD object generation must be positive".to_owned(),
            }
            .build()
        })?;
        ensure!(
            object_generation > 0,
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_CRD_METADATA",
                reason: "the CRD object generation must be nonzero",
            }
        );
        // Keep resourceVersion as an opaque replay cursor. It does not enter policy authority.
        let resource_version = required_metadata(
            metadata.resource_version.as_deref(),
            "opaque resource version",
        )?;
        ensure!(
            resource_version.len() <= 1024,
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_CRD_RESOURCE_VERSION",
                reason: "the opaque resource version exceeds 1024 bytes",
            }
        );
        for (name, value) in [
            ("tenant ID", tenant_id),
            ("cluster UID", cluster_uid),
            ("namespace UID", namespace_uid),
            ("object UID", object_uid),
        ] {
            ensure!(
                canonical_uuid(value),
                PolicyValidationSnafu {
                    policy_id: policy.profile_id(),
                    code: "CFG_CRD_IDENTITY",
                    reason: format!("{name} must be a canonical UUID"),
                }
            );
        }
        let canonical_spec_digest = canonical_kubernetes_policy_spec_digest(&resource.spec)?;
        let policy_document_digest = canonical_policy_spec_digest(policy)?;
        let mut revision = Self {
            schema_version: 1,
            tenant_id: tenant_id.to_owned(),
            cluster_uid: cluster_uid.to_owned(),
            namespace_uid: namespace_uid.to_owned(),
            object_uid: object_uid.to_owned(),
            namespace_name: namespace_name.to_owned(),
            object_name: object_name.to_owned(),
            api_version: POLICY_API_VERSION.to_owned(),
            kind: POLICY_KIND.to_owned(),
            object_generation,
            opaque_resource_version: resource_version.as_bytes().to_vec(),
            policy_document_digest,
            canonical_spec_digest,
            state,
            policy_source_revision_id: String::new(),
        };
        revision.policy_source_revision_id = revision.content_id()?;
        Ok(revision)
    }

    pub fn deletion_requested(&self) -> Result<Self> {
        let mut revision = self.clone();
        revision.state = PolicySourceStateV1::DeletionRequested;
        revision.policy_source_revision_id = revision.content_id()?;
        Ok(revision)
    }

    fn content_id(&self) -> Result<String> {
        #[derive(Serialize)]
        struct SourceIdentity<'a> {
            tenant_id: &'a str,
            cluster_uid: &'a str,
            namespace_uid: &'a str,
            object_uid: &'a str,
            object_generation: u64,
            canonical_spec_digest: &'a str,
            policy_document_digest: &'a str,
            state: PolicySourceStateV1,
        }
        // Names and resourceVersion can change without changing the accepted policy identity.
        Ok(domain_digest(
            SOURCE_REVISION_DOMAIN,
            &canonical_cbor(
                &self.object_uid,
                &SourceIdentity {
                    tenant_id: &self.tenant_id,
                    cluster_uid: &self.cluster_uid,
                    namespace_uid: &self.namespace_uid,
                    object_uid: &self.object_uid,
                    object_generation: self.object_generation,
                    canonical_spec_digest: &self.canonical_spec_digest,
                    policy_document_digest: &self.policy_document_digest,
                    state: self.state,
                },
            )?,
        ))
    }
}

impl PolicyTargetSnapshotV1 {
    pub fn new(
        policy_source_revision_id: String,
        signed_profile_digest: String,
        rollout_generation: u64,
        mut targets: Vec<PolicyTargetV1>,
    ) -> Result<Self> {
        // Canonical ordering makes the same scheduler facts produce the same snapshot digest.
        targets.sort();
        ensure!(
            rollout_generation > 0
                && targets.len() <= MAX_POLICY_STATUS_TARGETS as usize
                && targets.windows(2).all(|pair| pair[0] < pair[1])
                && targets.iter().all(PolicyTargetV1::is_valid),
            PolicyValidationSnafu {
                policy_id: &policy_source_revision_id,
                code: "CFG_POLICY_TARGETS",
                reason: "the target snapshot is empty, duplicate, invalid, or exceeds its bound",
            }
        );
        let mut snapshot = Self {
            policy_source_revision_id,
            signed_profile_digest,
            rollout_generation,
            targets,
            target_snapshot_digest: String::new(),
        };
        snapshot.target_snapshot_digest = domain_digest(
            TARGET_SNAPSHOT_DOMAIN,
            &canonical_cbor(&snapshot.policy_source_revision_id, &snapshot)?,
        );
        Ok(snapshot)
    }
}

impl PolicyTargetV1 {
    fn is_valid(&self) -> bool {
        canonical_uuid(&self.tenant_id)
            && canonical_uuid(&self.cluster_uid)
            && crate::node_id_is_valid(&self.node_id)
            && !self.workload_binding_generation_digests.is_empty()
            && self.workload_binding_generation_digests.len() <= 4096
            && self
                .workload_binding_generation_digests
                .iter()
                .all(|digest| valid_sha256(digest))
            && self
                .workload_binding_generation_digests
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && (self.workload_targets.is_empty()
                || (self.workload_targets.len() <= self.workload_binding_generation_digests.len()
                    && self.workload_targets.iter().all(|target| {
                        target.kubernetes.is_some()
                            && target.node_id == self.node_id
                            && self
                                .workload_binding_generation_digests
                                .binary_search(&target.workload_binding_generation_digest)
                                .is_ok()
                            && super::workload_target_fact_digest(target).is_ok_and(|digest| {
                                digest == target.workload_binding_generation_digest
                            })
                    })
                    && self.workload_targets.windows(2).all(|pair| {
                        pair[0].workload_binding_generation_digest
                            < pair[1].workload_binding_generation_digest
                    })))
    }
}

impl PolicyDeliveryCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        tenant_id: String,
        source_revision_id: String,
        signed_profile_digest: String,
        snapshot: &PolicyTargetSnapshotV1,
        exact_target: PolicyTargetV1,
        operation: PolicyDeliveryOperationV1,
        predecessor_candidate_content_id: Option<String>,
        distribution_sequence_epoch: u64,
        distribution_sequence: u64,
        issued_utc_ns: i64,
        expires_utc_ns: i64,
        signing_key_id: String,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        ensure!(
            exact_target.tenant_id == tenant_id
                && snapshot.policy_source_revision_id == source_revision_id
                && snapshot.signed_profile_digest == signed_profile_digest
                && snapshot.targets.binary_search(&exact_target).is_ok()
                && distribution_sequence_epoch > 0
                && distribution_sequence > 0
                && issued_utc_ns < expires_utc_ns
                && !signing_key_id.is_empty(),
            PolicyValidationSnafu {
                policy_id: &source_revision_id,
                code: "CFG_POLICY_CANDIDATE",
                reason: "the target, sequence, time, or signer is invalid",
            }
        );
        let mut candidate = Self {
            schema_version: 1,
            tenant_id,
            policy_source_revision_id: source_revision_id,
            signed_profile_digest,
            target_snapshot_digest: snapshot.target_snapshot_digest.clone(),
            exact_target,
            operation,
            predecessor_candidate_content_id,
            distribution_sequence_epoch,
            distribution_sequence,
            issued_utc_ns,
            expires_utc_ns,
            signing_key_id,
            candidate_content_id: String::new(),
            signature: Vec::new(),
        };
        let unsigned = candidate.unsigned_bytes()?;
        candidate.candidate_content_id = domain_digest(CANDIDATE_DOMAIN, &unsigned);
        candidate.signature = signing_key
            .sign(&candidate.signature_input(&unsigned))
            .to_bytes()
            .to_vec();
        Ok(candidate)
    }

    pub fn verify(&self, key: &VerifyingKey, node_id: &str, now_utc_ns: i64) -> Result<()> {
        let unsigned = self.unsigned_bytes()?;
        let signature = Signature::from_slice(&self.signature).map_err(|error| {
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: error.to_string(),
            }
            .build()
        })?;
        let valid = self.schema_version == 1
            && self.exact_target.node_id == node_id
            && self.exact_target.tenant_id == self.tenant_id
            && self.distribution_sequence_epoch > 0
            && self.distribution_sequence > 0
            && now_utc_ns >= self.issued_utc_ns
            && now_utc_ns < self.expires_utc_ns
            && self.candidate_content_id == domain_digest(CANDIDATE_DOMAIN, &unsigned)
            && key
                .verify(&self.signature_input(&unsigned), &signature)
                .is_ok();
        ensure!(
            valid,
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: "candidate signature, target, sequence, digest, or validity is invalid",
            }
        );
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.candidate_content_id.clear();
        unsigned.signature.clear();
        canonical_cbor(&self.policy_source_revision_id, &unsigned)
    }

    fn signature_input(&self, unsigned: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(CANDIDATE_DOMAIN.len() + 32);
        input.extend_from_slice(CANDIDATE_DOMAIN);
        input.extend_from_slice(&Sha256::digest(unsigned));
        input
    }
}

impl PolicyActivationAcknowledgementV1 {
    pub fn finalize(mut self) -> Result<Self> {
        self.validate()?;
        self.acknowledgement_content_id.clear();
        self.acknowledgement_content_id = domain_digest(
            ACKNOWLEDGEMENT_DOMAIN,
            &canonical_cbor(&self.candidate_content_id, &self)?,
        );
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        // ACTIVE carries positive readback proof. REJECTED carries only a bounded reason.
        let active = self.state == PolicyActivationStateV1::Active;
        let rejected = self.state == PolicyActivationStateV1::Rejected;
        ensure!(
            canonical_uuid(&self.tenant_id)
                && crate::node_id_is_valid(&self.node_id)
                && self.node_boot_id.len() == 16
                && self.node_boot_id.iter().any(|byte| *byte != 0)
                && self.label_epoch > 0
                && valid_sha256(&self.candidate_content_id)
                && valid_sha256(&self.policy_source_revision_id)
                && valid_sha256(&self.target_snapshot_digest)
                && valid_sha256(&self.authenticated_channel_receipt_digest)
                && (!active
                    || (self
                        .node_bound_generation_digest
                        .as_deref()
                        .is_some_and(valid_sha256)
                        && self
                            .profile_generation_ref_id
                            .is_some_and(|value| value > 0)
                        && self.readback_digest.as_deref().is_some_and(valid_sha256)
                        && self
                            .probe_result_digest
                            .as_deref()
                            .is_some_and(valid_sha256)
                        && self.reason_code.is_none()))
                && (!rejected
                    || (self
                        .reason_code
                        .as_ref()
                        .is_some_and(|reason| !reason.is_empty())
                        && self.node_bound_generation_digest.is_none()
                        && self.profile_generation_ref_id.is_none()
                        && self.readback_digest.is_none()
                        && self.probe_result_digest.is_none())),
            PolicyValidationSnafu {
                policy_id: &self.policy_source_revision_id,
                code: "CFG_POLICY_ACKNOWLEDGEMENT",
                reason: "the acknowledgement identity or state-specific fields are invalid",
            }
        );
        Ok(())
    }
}

impl PolicyBundleV1 {
    pub fn new(
        candidate: PolicyDeliveryCandidateV1,
        profile_artifact: ProfileCandidateArtifactV1,
        profile_signing_public_key: Vec<u8>,
    ) -> Result<Self> {
        ensure!(
            profile_signing_public_key.len() == 32
                && candidate.signed_profile_digest
                    == sha256(&serde_json::to_vec(&profile_artifact).map_err(|error| {
                        PolicyValidationSnafu {
                            policy_id: &candidate.policy_source_revision_id,
                            code: "CFG_POLICY_BUNDLE",
                            reason: format!("profile artifact encoding failed: {error}"),
                        }
                        .build()
                    })?),
            PolicyValidationSnafu {
                policy_id: &candidate.policy_source_revision_id,
                code: "CFG_POLICY_BUNDLE",
                reason: "the profile artifact digest or signing key is invalid",
            }
        );
        let mut bundle = Self {
            schema_version: 1,
            candidate,
            profile_artifact,
            profile_signing_public_key,
            bundle_digest: String::new(),
        };
        bundle.bundle_digest = sha256(&bundle.unsigned_bytes()?);
        Ok(bundle)
    }

    pub fn verify(
        &self,
        trusted_candidate_key: &VerifyingKey,
        node_id: &str,
        now: i64,
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.bundle_digest == sha256(&self.unsigned_bytes()?)
                && self.candidate.signed_profile_digest
                    == sha256(
                        &serde_json::to_vec(&self.profile_artifact).map_err(|error| {
                            PolicyValidationSnafu {
                                policy_id: &self.candidate.policy_source_revision_id,
                                code: "CFG_POLICY_BUNDLE",
                                reason: format!("profile artifact encoding failed: {error}"),
                            }
                            .build()
                        })?
                    ),
            PolicyValidationSnafu {
                policy_id: &self.candidate.policy_source_revision_id,
                code: "CFG_POLICY_BUNDLE",
                reason: "the policy bundle digest is invalid",
            }
        );
        self.candidate.verify(trusted_candidate_key, node_id, now)?;
        let profile_key: [u8; 32] = self
            .profile_signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                PolicySignatureSnafu {
                    key_id: &self.candidate.signing_key_id,
                    reason: "the profile signing key is not 32 bytes".to_owned(),
                }
                .build()
            })?;
        self.profile_artifact
            .verify(&VerifyingKey::from_bytes(&profile_key).map_err(|error| {
                PolicySignatureSnafu {
                    key_id: &self.candidate.signing_key_id,
                    reason: error.to_string(),
                }
                .build()
            })?)
    }

    pub fn chunks(&self) -> Result<Vec<PolicyBundleChunkV1>> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: &self.candidate.policy_source_revision_id,
                code: "CFG_POLICY_BUNDLE",
                reason: format!("policy bundle encoding failed: {error}"),
            }
            .build()
        })?;
        ensure!(
            bytes.len() <= MAX_POLICY_BUNDLE_BYTES,
            PolicyValidationSnafu {
                policy_id: &self.candidate.policy_source_revision_id,
                code: "CFG_POLICY_BUNDLE_SIZE",
                reason: "the policy bundle exceeds its 16 MiB bound",
            }
        );
        let chunk_count = bytes.len().div_ceil(MAX_POLICY_BUNDLE_CHUNK_BYTES);
        let chunk_count = u32::try_from(chunk_count).map_err(|_| {
            PolicyValidationSnafu {
                policy_id: &self.candidate.policy_source_revision_id,
                code: "CFG_POLICY_BUNDLE_SIZE",
                reason: "the policy bundle has too many chunks".to_owned(),
            }
            .build()
        })?;
        // Chunk hashes support resumable transfer. The complete bundle digest remains authoritative.
        Ok(bytes
            .chunks(MAX_POLICY_BUNDLE_CHUNK_BYTES)
            .enumerate()
            .map(|(index, payload)| PolicyBundleChunkV1 {
                bundle_digest: self.bundle_digest.clone(),
                chunk_index: u32::try_from(index).unwrap_or(u32::MAX),
                chunk_count,
                chunk_sha256: sha256(payload),
                payload: payload.to_vec(),
            })
            .collect())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.bundle_digest.clear();
        canonical_cbor(&self.candidate.policy_source_revision_id, &unsigned)
    }
}

impl PolicyRolloutCountsV1 {
    #[must_use]
    pub fn from_states<'a>(states: impl IntoIterator<Item = &'a PolicyRolloutStateV1>) -> Self {
        let mut counts = Self::default();
        for state in states {
            counts.desired = counts.desired.saturating_add(1);
            match state.state {
                PolicyRolloutStatusV1::Pending
                | PolicyRolloutStatusV1::Delivered
                | PolicyRolloutStatusV1::Staged => {
                    counts.updating = counts.updating.saturating_add(1);
                }
                PolicyRolloutStatusV1::Active => {
                    counts.active = counts.active.saturating_add(1);
                }
                PolicyRolloutStatusV1::Rejected
                | PolicyRolloutStatusV1::Stale
                | PolicyRolloutStatusV1::Unknown => {
                    counts.failed = counts.failed.saturating_add(1);
                }
            }
        }
        counts
    }
}

pub fn target_conflicts(targets: &[PolicyTargetV1]) -> bool {
    let mut bindings = BTreeMap::<(&str, &str), BTreeSet<&str>>::new();
    for target in targets {
        for digest in &target.workload_binding_generation_digests {
            if !bindings
                .entry((&target.tenant_id, &target.cluster_uid))
                .or_default()
                .insert(digest)
            {
                return true;
            }
        }
    }
    false
}

fn required_metadata<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str> {
    value.ok_or_else(|| {
        PolicyValidationSnafu {
            policy_id: "<kubernetes-object>",
            code: "CFG_CRD_METADATA",
            reason: format!("the CRD has no {name}"),
        }
        .build()
    })
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn next_continuation_token(
    current: Option<&str>,
    next: Option<String>,
    description: &str,
) -> Result<Option<String>> {
    let next = next.filter(|token| !token.is_empty());
    // A repeated token cannot advance the snapshot and would otherwise keep the relist open.
    ensure!(
        next.is_none() || next.as_deref() != current,
        InvalidConfigurationSnafu {
            reason: format!("Kubernetes {description} list repeated a continuation token"),
        }
    );
    Ok(next)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn bound_openapi_schema(value: &mut serde_json::Value, resource_root: bool) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                bound_openapi_schema(value, false);
            }
        }
        serde_json::Value::Object(object) => {
            if object.get("nullable") == Some(&serde_json::Value::Bool(true)) {
                // Kubernetes applies enum constraints to null despite the nullable marker.
                // Control validates non-null enum values after it reads the stored object.
                object.remove("enum");
            }
            let object_type = object.get("type").and_then(serde_json::Value::as_str);
            if object_type == Some("string") {
                object
                    .entry("maxLength")
                    .or_insert(serde_json::Value::from(MAX_POLICY_SCHEMA_STRING_BYTES));
            } else if object_type == Some("array") {
                object
                    .entry("maxItems")
                    .or_insert(serde_json::Value::from(MAX_POLICY_SCHEMA_ITEMS));
            } else if object_type == Some("object") && !resource_root {
                object
                    .entry("maxProperties")
                    .or_insert(serde_json::Value::from(MAX_POLICY_SCHEMA_MAP_ENTRIES));
            }
            for nested in object.values_mut() {
                bound_openapi_schema(nested, false);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::next_continuation_token;

    #[test]
    fn continuation_token_must_advance() -> crate::Result<()> {
        assert_eq!(
            next_continuation_token(None, Some("next".to_owned()), "test resources")?,
            Some("next".to_owned())
        );
        assert_eq!(
            next_continuation_token(Some("next"), Some(String::new()), "test resources")?,
            None
        );
        assert!(
            next_continuation_token(Some("next"), Some("next".to_owned()), "test resources")
                .is_err()
        );
        Ok(())
    }
}
