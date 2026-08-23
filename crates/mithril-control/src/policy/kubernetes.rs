use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{CustomResource, CustomResourceExt as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;

use super::canonical::canonical_cbor;
use super::{PolicyDocumentV1, ProfileCandidateArtifactV1};
use crate::error::{InvalidConfigurationSnafu, PolicySignatureSnafu, PolicyValidationSnafu};
use crate::Result;

pub const POLICY_API_VERSION: &str = "mithril.erebor.dev/v1alpha1";
pub const POLICY_KIND: &str = "WorkloadProtectionProfile";
pub const SUBMITTED_SPEC_DIGEST_ANNOTATION: &str = "mithril.erebor.dev/submitted-spec-sha256";
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
    kind = "WorkloadProtectionProfile",
    plural = "workloadprotectionprofiles",
    namespaced,
    status = "WorkloadProtectionProfileStatusV1",
    shortname = "wpp"
)]
#[serde(deny_unknown_fields)]
/// Defines the CRD desired state. Control creates signed node artifacts from this value.
pub struct WorkloadProtectionProfileSpec {
    #[serde(flatten)]
    pub policy: PolicyDocumentV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
/// Projects Control state for operators. This status does not authorize node activation.
pub struct WorkloadProtectionProfileStatusV1 {
    pub observed_generation: u64,
    pub source_revision_id: Option<String>,
    pub canonical_spec_digest: Option<String>,
    pub candidate_content_id: Option<String>,
    pub rollout_counts: PolicyRolloutCountsV1,
    #[schemars(length(max = 6))]
    pub conditions: Vec<PolicyConditionV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRolloutCountsV1 {
    pub pending: u32,
    pub delivered: u32,
    pub staged: u32,
    pub active: u32,
    pub rejected: u32,
    pub stale: u32,
    pub unknown: u32,
}

impl PolicyRolloutCountsV1 {
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.pending
            .saturating_add(self.delivered)
            .saturating_add(self.staged)
            .saturating_add(self.active)
            .saturating_add(self.rejected)
            .saturating_add(self.stale)
            .saturating_add(self.unknown)
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyConditionKindV1 {
    Accepted,
    Compiled,
    Progressing,
    Available,
    Degraded,
    Retiring,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConditionV1 {
    pub condition: PolicyConditionKindV1,
    pub status: bool,
    pub reason_code: String,
    pub observed_generation: u64,
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
    let mut crd = WorkloadProtectionProfile::crd();
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

pub fn policy_custom_resource(
    name: &str,
    namespace: &str,
    document: PolicyDocumentV1,
) -> Result<WorkloadProtectionProfile> {
    ensure!(
        !name.is_empty() && !namespace.is_empty(),
        PolicyValidationSnafu {
            policy_id: document.profile_id(),
            code: "CFG_CRD_METADATA",
            reason: "the policy resource needs a name and namespace",
        }
    );
    let digest = canonical_policy_spec_digest(&document)?;
    let mut resource =
        WorkloadProtectionProfile::new(name, WorkloadProtectionProfileSpec { policy: document });
    resource.metadata.namespace = Some(namespace.to_owned());
    resource.metadata.annotations = Some(BTreeMap::from([(
        SUBMITTED_SPEC_DIGEST_ANNOTATION.to_owned(),
        digest,
    )]));
    Ok(resource)
}

impl PolicySourceRevisionV1 {
    pub fn from_resource(
        resource: &WorkloadProtectionProfile,
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
                policy_id: resource.spec.policy.profile_id(),
                code: "CFG_CRD_METADATA",
                reason: "the CRD has no object generation".to_owned(),
            }
            .build()
        })?;
        let object_generation = u64::try_from(generation).map_err(|_| {
            PolicyValidationSnafu {
                policy_id: resource.spec.policy.profile_id(),
                code: "CFG_CRD_METADATA",
                reason: "the CRD object generation must be positive".to_owned(),
            }
            .build()
        })?;
        ensure!(
            object_generation > 0,
            PolicyValidationSnafu {
                policy_id: resource.spec.policy.profile_id(),
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
                policy_id: resource.spec.policy.profile_id(),
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
                    policy_id: resource.spec.policy.profile_id(),
                    code: "CFG_CRD_IDENTITY",
                    reason: format!("{name} must be a canonical UUID"),
                }
            );
        }
        let canonical_spec_digest = canonical_policy_spec_digest(&resource.spec.policy)?;
        // The submitted digest detects API servers or clients that prune unknown source fields.
        let submitted_digest = metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SUBMITTED_SPEC_DIGEST_ANNOTATION));
        ensure!(
            submitted_digest == Some(&canonical_spec_digest),
            PolicyValidationSnafu {
                policy_id: resource.spec.policy.profile_id(),
                code: "CFG_CRD_SILENT_PRUNE",
                reason:
                    "the strict-write canonical spec digest is absent or does not match stored spec",
            }
        );
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
            policy_document_digest: canonical_spec_digest.clone(),
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
            match state.state {
                PolicyRolloutStatusV1::Pending => counts.pending += 1,
                PolicyRolloutStatusV1::Delivered => counts.delivered += 1,
                PolicyRolloutStatusV1::Staged => counts.staged += 1,
                PolicyRolloutStatusV1::Active => counts.active += 1,
                PolicyRolloutStatusV1::Rejected => counts.rejected += 1,
                PolicyRolloutStatusV1::Stale => counts.stale += 1,
                PolicyRolloutStatusV1::Unknown => counts.unknown += 1,
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
