use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{ListParams, Patch, PatchParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;
use tokio_stream::StreamExt as _;

use super::canonical::canonical_cbor;
use super::{
    kubernetes_condition, preserve_transition_times, utc_now_ns, PolicyActivationAcknowledgementV1,
    PolicyBundleV1, PolicyDesiredStateOwner, PolicyRolloutOwner, PolicySourceStateV1,
    WorkloadProtectionException, WorkloadProtectionExceptionStateV1,
    WorkloadProtectionExceptionStatusV1, WorkloadTargetFactV1, EXCEPTION_KIND, POLICY_API_VERSION,
};
use crate::error::{PolicySignatureSnafu, PolicyValidationSnafu};
use crate::Result;

const EXCEPTION_SOURCE_DOMAIN: &[u8] = b"MITHRIL-EXCEPTION-SOURCE-REVISION-V1\0";
const EXCEPTION_CANDIDATE_DOMAIN: &[u8] = b"MITHRIL-EXCEPTION-CANDIDATE-V1\0";
const EXCEPTION_ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"MITHRIL-EXCEPTION-ACKNOWLEDGEMENT-V1\0";
pub const MAX_EXCEPTION_CANDIDATE_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExceptionSourceStateV1 {
    Accepted,
    DeletionRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Binds one stored exception request to its exact base policy and grant.
pub struct ExceptionSourceRevisionV1 {
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
    pub base_policy_source_revision_id: String,
    pub grant_id: String,
    pub requested_duration_ns: u64,
    pub requested_uses: u32,
    pub state: ExceptionSourceStateV1,
    pub exception_source_revision_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExceptionDeliveryOperationV1 {
    Activate,
    Revoke,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Carries one signed runtime-state change for one active workload binding.
pub struct ExceptionDeliveryCandidateV1 {
    pub schema_version: u32,
    pub tenant_id: String,
    pub exception_source_revision_id: String,
    pub base_policy_source_revision_id: String,
    pub base_candidate_content_id: String,
    pub profile_id: String,
    pub profile_generation_ref_id: u64,
    pub grant_id: String,
    pub exception_instance_id: String,
    pub exact_target: WorkloadTargetFactV1,
    pub operation: ExceptionDeliveryOperationV1,
    pub maximum_uses: u32,
    pub valid_until_utc_ns: i64,
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
pub enum ExceptionActivationStateV1 {
    Active,
    Consumed,
    Expired,
    Revoked,
    Rejected,
    Stale,
}

impl From<ExceptionActivationStateV1> for WorkloadProtectionExceptionStateV1 {
    fn from(value: ExceptionActivationStateV1) -> Self {
        match value {
            ExceptionActivationStateV1::Active => Self::Active,
            ExceptionActivationStateV1::Consumed => Self::Consumed,
            ExceptionActivationStateV1::Expired => Self::Expired,
            ExceptionActivationStateV1::Revoked => Self::Revoked,
            ExceptionActivationStateV1::Rejected | ExceptionActivationStateV1::Stale => {
                Self::Failed
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionActivationAcknowledgementV1 {
    pub acknowledgement_content_id: String,
    pub tenant_id: String,
    pub node_id: String,
    pub node_boot_id: Vec<u8>,
    pub label_epoch: u64,
    pub candidate_content_id: String,
    pub exception_source_revision_id: String,
    pub state: ExceptionActivationStateV1,
    pub consumed_uses: u32,
    pub transition_version: u64,
    pub observed_utc_ns: i64,
    pub reason_code: Option<String>,
    pub authenticated_channel_receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRolloutStateV1 {
    pub exception_source_revision_id: String,
    pub candidate_content_id: String,
    pub node_id: String,
    pub state: WorkloadProtectionExceptionStateV1,
    pub latest_acknowledgement_content_id: Option<String>,
    pub transition_version: u64,
    pub updated_utc_ns: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExceptionReconcileResultV1 {
    pub source_revision: ExceptionSourceRevisionV1,
    pub candidate: ExceptionDeliveryCandidateV1,
    pub rollout_state: ExceptionRolloutStateV1,
    pub status: WorkloadProtectionExceptionStatusV1,
}

impl ExceptionSourceRevisionV1 {
    pub fn from_resource(
        resource: &WorkloadProtectionException,
        tenant_id: &str,
        cluster_uid: &str,
        namespace_uid: &str,
        base_policy_source_revision_id: &str,
        state: ExceptionSourceStateV1,
    ) -> Result<Self> {
        let metadata = &resource.metadata;
        let object_uid = required(metadata.uid.as_deref(), "object UID")?;
        let namespace_name = required(metadata.namespace.as_deref(), "namespace")?;
        let object_name = required(metadata.name.as_deref(), "object name")?;
        let resource_version = required(
            metadata.resource_version.as_deref(),
            "opaque resource version",
        )?;
        let object_generation = metadata
            .generation
            .and_then(|generation| u64::try_from(generation).ok())
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                invalid(
                    object_uid,
                    "the exception has no positive object generation",
                )
            })?;
        resource.spec.validate_request(object_uid)?;
        ensure!(
            [tenant_id, cluster_uid, namespace_uid, object_uid]
                .iter()
                .all(|value| canonical_uuid(value))
                && valid_sha256(base_policy_source_revision_id)
                && resource_version.len() <= 1024,
            PolicyValidationSnafu {
                policy_id: object_uid,
                code: "CFG_EXCEPTION_SOURCE",
                reason:
                    "the exception source identity, base revision, or resource version is invalid",
            }
        );
        let canonical_spec_digest = digest(&canonical_cbor(object_uid, &resource.spec)?);
        let mut revision = Self {
            schema_version: 1,
            tenant_id: tenant_id.to_owned(),
            cluster_uid: cluster_uid.to_owned(),
            namespace_uid: namespace_uid.to_owned(),
            object_uid: object_uid.to_owned(),
            namespace_name: namespace_name.to_owned(),
            object_name: object_name.to_owned(),
            api_version: POLICY_API_VERSION.to_owned(),
            kind: EXCEPTION_KIND.to_owned(),
            object_generation,
            opaque_resource_version: resource_version.as_bytes().to_vec(),
            canonical_spec_digest,
            base_policy_source_revision_id: base_policy_source_revision_id.to_owned(),
            grant_id: resource.spec.grant.clone(),
            requested_duration_ns: resource.spec.requested_duration_ns(object_uid)?,
            requested_uses: resource.spec.requested_uses,
            state,
            exception_source_revision_id: String::new(),
        };
        revision.exception_source_revision_id = revision.content_id()?;
        Ok(revision)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && canonical_uuid(&self.tenant_id)
                && canonical_uuid(&self.cluster_uid)
                && canonical_uuid(&self.namespace_uid)
                && canonical_uuid(&self.object_uid)
                && !self.namespace_name.is_empty()
                && !self.object_name.is_empty()
                && self.api_version == POLICY_API_VERSION
                && self.kind == EXCEPTION_KIND
                && self.object_generation > 0
                && !self.opaque_resource_version.is_empty()
                && self.opaque_resource_version.len() <= 1024
                && valid_sha256(&self.canonical_spec_digest)
                && valid_sha256(&self.base_policy_source_revision_id)
                && !self.grant_id.is_empty()
                && self.requested_duration_ns > 0
                && self.requested_uses > 0
                && self.exception_source_revision_id == self.content_id()?,
            PolicyValidationSnafu {
                policy_id: &self.object_uid,
                code: "CFG_EXCEPTION_SOURCE",
                reason: "the exception source identity, binding, or content digest is invalid",
            }
        );
        Ok(())
    }

    pub fn deletion_requested(&self) -> Result<Self> {
        let mut revision = self.clone();
        revision.state = ExceptionSourceStateV1::DeletionRequested;
        revision.exception_source_revision_id = revision.content_id()?;
        Ok(revision)
    }

    fn content_id(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.exception_source_revision_id.clear();
        Ok(domain_digest(
            EXCEPTION_SOURCE_DOMAIN,
            &canonical_cbor(&self.object_uid, &unsigned)?,
        ))
    }
}

impl ExceptionDeliveryCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        source: &ExceptionSourceRevisionV1,
        base_candidate_content_id: String,
        profile_id: String,
        profile_generation_ref_id: u64,
        exact_target: WorkloadTargetFactV1,
        operation: ExceptionDeliveryOperationV1,
        maximum_uses: u32,
        valid_until_utc_ns: i64,
        predecessor_candidate_content_id: Option<String>,
        distribution_sequence_epoch: u64,
        distribution_sequence: u64,
        issued_utc_ns: i64,
        expires_utc_ns: i64,
        signing_key_id: String,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        source.validate()?;
        ensure!(
            (source.state == ExceptionSourceStateV1::Accepted
                || operation == ExceptionDeliveryOperationV1::Revoke)
                && canonical_uuid(&profile_id)
                && valid_sha256(&base_candidate_content_id)
                && profile_generation_ref_id > 0
                && exact_target.kubernetes.as_ref().is_some_and(|identity| {
                    identity.profile_id == profile_id
                        && identity.policy_source_revision_id
                            == source.base_policy_source_revision_id
                        && valid_id128_hex(&identity.node_boot_id)
                })
                && super::workload_target_fact_digest(&exact_target)
                    .is_ok_and(|digest| digest == exact_target.workload_binding_generation_digest)
                && maximum_uses > 0
                && (operation == ExceptionDeliveryOperationV1::Revoke
                    || issued_utc_ns < valid_until_utc_ns)
                && issued_utc_ns < expires_utc_ns
                && distribution_sequence_epoch > 0
                && distribution_sequence > 0
                && !signing_key_id.is_empty(),
            PolicyValidationSnafu {
                policy_id: &source.exception_source_revision_id,
                code: "CFG_EXCEPTION_CANDIDATE",
                reason:
                    "the exception candidate target, authority bound, sequence, or time is invalid",
            }
        );
        let mut candidate = Self {
            schema_version: 1,
            tenant_id: source.tenant_id.clone(),
            exception_source_revision_id: source.exception_source_revision_id.clone(),
            base_policy_source_revision_id: source.base_policy_source_revision_id.clone(),
            base_candidate_content_id,
            profile_id,
            profile_generation_ref_id,
            grant_id: source.grant_id.clone(),
            exception_instance_id: source.object_uid.clone(),
            exact_target,
            operation,
            maximum_uses,
            valid_until_utc_ns,
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
        candidate.candidate_content_id = domain_digest(EXCEPTION_CANDIDATE_DOMAIN, &unsigned);
        candidate.signature = signing_key
            .sign(&candidate.signature_input(&unsigned))
            .to_bytes()
            .to_vec();
        candidate.validate_content()?;
        Ok(candidate)
    }

    pub fn validate_content(&self) -> Result<()> {
        let unsigned = self.unsigned_bytes()?;
        ensure!(
            self.schema_version == 1
                && canonical_uuid(&self.tenant_id)
                && valid_sha256(&self.exception_source_revision_id)
                && valid_sha256(&self.base_policy_source_revision_id)
                && valid_sha256(&self.base_candidate_content_id)
                && canonical_uuid(&self.profile_id)
                && self.profile_generation_ref_id > 0
                && !self.grant_id.is_empty()
                && canonical_uuid(&self.exception_instance_id)
                && self
                    .exact_target
                    .kubernetes
                    .as_ref()
                    .is_some_and(|identity| {
                        identity.profile_id == self.profile_id
                            && identity.policy_source_revision_id
                                == self.base_policy_source_revision_id
                            && valid_id128_hex(&identity.node_boot_id)
                    })
                && super::workload_target_fact_digest(&self.exact_target).is_ok_and(|digest| {
                    digest == self.exact_target.workload_binding_generation_digest
                })
                && self.maximum_uses > 0
                && (self.operation == ExceptionDeliveryOperationV1::Revoke
                    || self.issued_utc_ns < self.valid_until_utc_ns)
                && self.issued_utc_ns < self.expires_utc_ns
                && self
                    .predecessor_candidate_content_id
                    .as_deref()
                    .is_none_or(valid_sha256)
                && self.distribution_sequence_epoch > 0
                && self.distribution_sequence > 0
                && !self.signing_key_id.is_empty()
                && self.signing_key_id.len() <= 128
                && self.signature.len() == 64
                && self.candidate_content_id
                    == domain_digest(EXCEPTION_CANDIDATE_DOMAIN, &unsigned)
                && serde_json::to_vec(self)
                    .is_ok_and(|encoded| encoded.len() <= MAX_EXCEPTION_CANDIDATE_BYTES),
            PolicyValidationSnafu {
                policy_id: &self.exception_source_revision_id,
                code: "CFG_EXCEPTION_CANDIDATE",
                reason: "the exception candidate content or exact binding is invalid",
            }
        );
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey, node_id: &str, now_utc_ns: i64) -> Result<()> {
        self.validate_content()?;
        let unsigned = self.unsigned_bytes()?;
        let signature = Signature::from_slice(&self.signature).map_err(|error| {
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: error.to_string(),
            }
            .build()
        })?;
        let valid = self.exact_target.node_id == node_id
            && self.issued_utc_ns <= now_utc_ns
            && now_utc_ns < self.expires_utc_ns
            && key
                .verify(&self.signature_input(&unsigned), &signature)
                .is_ok();
        ensure!(
            valid,
            PolicySignatureSnafu {
                key_id: &self.signing_key_id,
                reason: "exception signature, target, sequence, digest, or validity is invalid",
            }
        );
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.candidate_content_id.clear();
        unsigned.signature.clear();
        canonical_cbor(&self.exception_source_revision_id, &unsigned)
    }

    fn signature_input(&self, unsigned: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(EXCEPTION_CANDIDATE_DOMAIN.len() + 32);
        input.extend_from_slice(EXCEPTION_CANDIDATE_DOMAIN);
        input.extend_from_slice(&Sha256::digest(unsigned));
        input
    }
}

impl ExceptionActivationAcknowledgementV1 {
    pub fn finalize(mut self) -> Result<Self> {
        self.validate()?;
        self.acknowledgement_content_id.clear();
        self.acknowledgement_content_id = self.content_id()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        let rejected = matches!(
            self.state,
            ExceptionActivationStateV1::Rejected | ExceptionActivationStateV1::Stale
        );
        ensure!(
            canonical_uuid(&self.tenant_id)
                && crate::node_id_is_valid(&self.node_id)
                && self.node_boot_id.len() == 16
                && self.node_boot_id.iter().any(|byte| *byte != 0)
                && self.label_epoch > 0
                && valid_sha256(&self.candidate_content_id)
                && valid_sha256(&self.exception_source_revision_id)
                && self.transition_version > 0
                && self.observed_utc_ns > 0
                && valid_sha256(&self.authenticated_channel_receipt_digest)
                && (!rejected
                    || self
                        .reason_code
                        .as_ref()
                        .is_some_and(|reason| !reason.is_empty()))
                && (rejected || self.reason_code.is_none())
                && (self.acknowledgement_content_id.is_empty()
                    || self.acknowledgement_content_id == self.content_id()?),
            PolicyValidationSnafu {
                policy_id: &self.exception_source_revision_id,
                code: "CFG_EXCEPTION_ACKNOWLEDGEMENT",
                reason:
                    "the exception acknowledgement identity, state, or channel proof is invalid",
            }
        );
        Ok(())
    }

    fn content_id(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.acknowledgement_content_id.clear();
        Ok(domain_digest(
            EXCEPTION_ACKNOWLEDGEMENT_DOMAIN,
            &canonical_cbor(&self.candidate_content_id, &unsigned)?,
        ))
    }
}

impl PolicyDesiredStateOwner {
    pub fn reconcile_exception(
        &self,
        resource: &WorkloadProtectionException,
        namespace_uid: &str,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<ExceptionReconcileResultV1> {
        let state = if resource.metadata.deletion_timestamp.is_some() {
            ExceptionSourceStateV1::DeletionRequested
        } else {
            ExceptionSourceStateV1::Accepted
        };
        self.reconcile_exception_observation(resource, namespace_uid, inventory, now_utc_ns, state)
    }

    pub(super) fn reconcile_exception_observation(
        &self,
        resource: &WorkloadProtectionException,
        namespace_uid: &str,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
        state: ExceptionSourceStateV1,
    ) -> Result<ExceptionReconcileResultV1> {
        let _reconcile_guard = self.reconcile_lock.lock().map_err(|_| {
            invalid(
                resource.metadata.uid.as_deref().unwrap_or("<exception>"),
                "the policy reconcile owner lock is poisoned",
            )
        })?;
        let object_uid = required(resource.metadata.uid.as_deref(), "object UID")?;
        let object_name = required(resource.metadata.name.as_deref(), "object name")?;
        let current = self.store.latest_exception_source(
            &self.config.tenant_id,
            namespace_uid,
            object_name,
        )?;
        // Deletion uses the durable base generation. A changed or absent live policy
        // cannot widen it.
        let base_source = match state {
            ExceptionSourceStateV1::Accepted => self
                .store
                .latest_source(
                    &self.config.tenant_id,
                    namespace_uid,
                    &resource.spec.policy_ref.name,
                )?
                .filter(|source| source.state == PolicySourceStateV1::Accepted)
                .ok_or_else(|| {
                    invalid(
                        object_uid,
                        "the exception does not reference an accepted policy in its namespace",
                    )
                })?,
            ExceptionSourceStateV1::DeletionRequested => current
                .as_ref()
                .filter(|source| source.object_uid == object_uid)
                .and_then(|source| {
                    self.store
                        .source_revision(&source.base_policy_source_revision_id)
                        .transpose()
                })
                .transpose()?
                .ok_or_else(|| {
                    invalid(
                        object_uid,
                        "the deleted exception has no durable base-policy generation",
                    )
                })?,
        };
        let source = ExceptionSourceRevisionV1::from_resource(
            resource,
            &self.config.tenant_id,
            &self.config.cluster_uid,
            namespace_uid,
            &base_source.policy_source_revision_id,
            state,
        )?;
        if current.as_ref().is_some_and(|current| current == &source) {
            return self.stored_exception_result(&source, now_utc_ns);
        }
        if state == ExceptionSourceStateV1::DeletionRequested {
            return self.reconcile_exception_revocation(source, now_utc_ns);
        }
        // Only API-derived scheduler facts can resolve the requested Pod and container.
        let mut targets = inventory.iter().filter(|target| {
            target.cluster_uid == self.config.cluster_uid
                && target.namespace_uid == namespace_uid
                && target.pod_uid == resource.spec.target.pod.uid
                && target.container_name == resource.spec.target.container_name
                && target.kubernetes.as_ref().is_some_and(|identity| {
                    identity.namespace_name == source.namespace_name
                        && identity.pod_name == resource.spec.target.pod.name
                        && identity.policy_source_revision_id
                            == base_source.policy_source_revision_id
                })
        });
        let target = targets.next().cloned().ok_or_else(|| {
            invalid(
                object_uid,
                "the exception target is not one exact protected container",
            )
        })?;
        ensure!(
            targets.next().is_none(),
            PolicyValidationSnafu {
                policy_id: object_uid,
                code: "CFG_EXCEPTION_TARGET",
                reason: "the exception target resolves to more than one container",
            }
        );
        // The exception cannot precede active base-policy readback for this exact binding.
        let (base_bundle, base_acknowledgement) = self
            .store
            .active_policy_for_workload(
                &base_source.policy_source_revision_id,
                &target.workload_binding_generation_digest,
            )?
            .ok_or_else(|| {
                invalid(
                    object_uid,
                    "the exception target has no active acknowledged base policy",
                )
            })?;
        let (candidate, rollout_state) = self.rollout.create_exception(
            &source,
            &base_bundle,
            Some(&base_acknowledgement),
            target,
            None,
            now_utc_ns,
        )?;
        self.store.record_exception_desired(
            source.clone(),
            candidate.clone(),
            rollout_state.clone(),
        )?;
        Ok(ExceptionReconcileResultV1 {
            source_revision: source.clone(),
            candidate,
            rollout_state: rollout_state.clone(),
            status: exception_status(&source, &rollout_state, now_utc_ns),
        })
    }

    pub fn retire_missing_exceptions(
        &self,
        seen_object_uids: &std::collections::BTreeSet<String>,
        now_utc_ns: i64,
    ) -> Result<Vec<ExceptionReconcileResultV1>> {
        let _reconcile_guard = self.reconcile_lock.lock().map_err(|_| {
            invalid(
                "<exception-relist>",
                "the policy reconcile owner lock is poisoned",
            )
        })?;
        self.store
            .latest_live_exception_sources()?
            .into_iter()
            .filter(|source| !seen_object_uids.contains(&source.object_uid))
            .map(|source| {
                self.reconcile_exception_revocation(source.deletion_requested()?, now_utc_ns)
            })
            .collect()
    }

    fn reconcile_exception_revocation(
        &self,
        source: ExceptionSourceRevisionV1,
        now_utc_ns: i64,
    ) -> Result<ExceptionReconcileResultV1> {
        // Revocation keeps the original target and names its activation as the predecessor.
        let previous = self
            .store
            .latest_exception_candidate_for_object(&source.object_uid)?
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the deleted exception has no activation candidate to revoke",
                )
            })?;
        let bundle = self
            .store
            .bundle_for_candidate(
                &previous.exact_target.node_id,
                &previous.base_candidate_content_id,
            )?
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the exception base-policy bundle is unavailable",
                )
            })?;
        let (candidate, rollout_state) = self.rollout.create_exception(
            &source,
            &bundle,
            None,
            previous.exact_target.clone(),
            Some(&previous),
            now_utc_ns,
        )?;
        self.store.record_exception_desired(
            source.clone(),
            candidate.clone(),
            rollout_state.clone(),
        )?;
        Ok(ExceptionReconcileResultV1 {
            source_revision: source.clone(),
            candidate,
            rollout_state: rollout_state.clone(),
            status: exception_status(&source, &rollout_state, now_utc_ns),
        })
    }

    fn stored_exception_result(
        &self,
        source: &ExceptionSourceRevisionV1,
        now_utc_ns: i64,
    ) -> Result<ExceptionReconcileResultV1> {
        let candidate = self
            .store
            .latest_exception_candidate_for_object(&source.object_uid)?
            .filter(|candidate| {
                candidate.exception_source_revision_id == source.exception_source_revision_id
            })
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the stored exception source has no delivery candidate",
                )
            })?;
        let rollout_state = self
            .store
            .exception_rollout_state(
                &candidate.candidate_content_id,
                &candidate.exact_target.node_id,
            )?
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the stored exception candidate has no rollout state",
                )
            })?;
        Ok(ExceptionReconcileResultV1 {
            source_revision: source.clone(),
            candidate,
            rollout_state: rollout_state.clone(),
            status: exception_status(source, &rollout_state, now_utc_ns),
        })
    }
}

impl PolicyRolloutOwner {
    fn create_exception(
        &self,
        source: &ExceptionSourceRevisionV1,
        base_bundle: &PolicyBundleV1,
        base_acknowledgement: Option<&PolicyActivationAcknowledgementV1>,
        target: WorkloadTargetFactV1,
        predecessor: Option<&ExceptionDeliveryCandidateV1>,
        now_utc_ns: i64,
    ) -> Result<(ExceptionDeliveryCandidateV1, ExceptionRolloutStateV1)> {
        let profile_generation_ref_id = predecessor
            .map(|previous| previous.profile_generation_ref_id)
            .or_else(|| base_acknowledgement.and_then(|ack| ack.profile_generation_ref_id))
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the active base-policy acknowledgement has no generation reference",
                )
            })?;
        let operation = if source.state == ExceptionSourceStateV1::DeletionRequested {
            ExceptionDeliveryOperationV1::Revoke
        } else {
            ExceptionDeliveryOperationV1::Activate
        };
        // Revocation preserves the original budget. It cannot create a new validity window.
        let (maximum_uses, valid_until_utc_ns) = predecessor.map_or_else(
            || {
                let duration = i64::try_from(source.requested_duration_ns).map_err(|_| {
                    invalid(
                        &source.object_uid,
                        "the requested exception duration exceeds the signed time range",
                    )
                })?;
                let valid_until = now_utc_ns.checked_add(duration).ok_or_else(|| {
                    invalid(
                        &source.object_uid,
                        "the requested exception validity exceeds the signed time range",
                    )
                })?;
                Ok((source.requested_uses, valid_until))
            },
            |previous| Ok((previous.maximum_uses, previous.valid_until_utc_ns)),
        )?;
        let delivery_expires_utc_ns = now_utc_ns
            .checked_add(self.candidate_validity_ns)
            .ok_or_else(|| {
                invalid(
                    &source.object_uid,
                    "the exception delivery validity exceeds the signed time range",
                )
            })?;
        // An activation remains deliverable for its complete bounded authority window.
        let expires_utc_ns = if operation == ExceptionDeliveryOperationV1::Activate {
            delivery_expires_utc_ns.max(valid_until_utc_ns)
        } else {
            delivery_expires_utc_ns
        };
        let sequence = self.store.next_exception_distribution_sequence(
            &target.node_id,
            &source.object_uid,
            self.distribution_sequence_epoch,
        )?;
        let candidate = ExceptionDeliveryCandidateV1::sign(
            source,
            base_bundle.candidate.candidate_content_id.clone(),
            base_bundle
                .profile_artifact
                .policy_document
                .metadata
                .profile_id
                .clone(),
            profile_generation_ref_id,
            target,
            operation,
            maximum_uses,
            valid_until_utc_ns,
            predecessor.map(|previous| previous.candidate_content_id.clone()),
            self.distribution_sequence_epoch,
            sequence,
            now_utc_ns,
            expires_utc_ns,
            self.signing_key_id.to_string(),
            &self.signing_key,
        )?;
        let rollout = ExceptionRolloutStateV1 {
            exception_source_revision_id: source.exception_source_revision_id.clone(),
            candidate_content_id: candidate.candidate_content_id.clone(),
            node_id: candidate.exact_target.node_id.clone(),
            state: WorkloadProtectionExceptionStateV1::Pending,
            latest_acknowledgement_content_id: None,
            transition_version: 0,
            updated_utc_ns: now_utc_ns,
        };
        Ok((candidate, rollout))
    }

    pub fn acknowledge_exception(
        &self,
        acknowledgement: ExceptionActivationAcknowledgementV1,
    ) -> Result<ExceptionRolloutStateV1> {
        let current = self
            .store
            .exception_rollout_state(
                &acknowledgement.candidate_content_id,
                &acknowledgement.node_id,
            )?
            .ok_or_else(|| {
                invalid(
                    &acknowledgement.exception_source_revision_id,
                    "the exception acknowledgement has no current rollout",
                )
            })?;
        let transition_version = current.transition_version.checked_add(1).ok_or_else(|| {
            invalid(
                &acknowledgement.exception_source_revision_id,
                "the exception rollout transition version is exhausted",
            )
        })?;
        ensure!(
            acknowledgement.transition_version == transition_version,
            PolicyValidationSnafu {
                policy_id: &acknowledgement.exception_source_revision_id,
                code: "CFG_EXCEPTION_ACKNOWLEDGEMENT",
                reason: "the exception acknowledgement transition is stale",
            }
        );
        let next = ExceptionRolloutStateV1 {
            exception_source_revision_id: current.exception_source_revision_id,
            candidate_content_id: current.candidate_content_id,
            node_id: current.node_id,
            state: acknowledgement.state.into(),
            latest_acknowledgement_content_id: Some(
                acknowledgement.acknowledgement_content_id.clone(),
            ),
            transition_version,
            updated_utc_ns: acknowledgement.observed_utc_ns,
        };
        self.store
            .acknowledge_exception(acknowledgement, next.clone())?;
        Ok(next)
    }
}

fn exception_status(
    source: &ExceptionSourceRevisionV1,
    rollout: &ExceptionRolloutStateV1,
    now_utc_ns: i64,
) -> WorkloadProtectionExceptionStatusV1 {
    let terminal = matches!(
        rollout.state,
        WorkloadProtectionExceptionStateV1::Consumed
            | WorkloadProtectionExceptionStateV1::Expired
            | WorkloadProtectionExceptionStateV1::Revoked
            | WorkloadProtectionExceptionStateV1::Failed
    );
    WorkloadProtectionExceptionStatusV1 {
        observed_generation: source.object_generation,
        state: rollout.state,
        conditions: vec![
            kubernetes_condition(
                "Accepted",
                true,
                source.object_generation,
                "RequestAccepted",
                "Control accepted and bounded the exception request.",
                now_utc_ns,
            ),
            kubernetes_condition(
                "Terminal",
                terminal,
                source.object_generation,
                "RuntimeStateObserved",
                "Control projects the latest authenticated node state.",
                now_utc_ns,
            ),
        ],
    }
}

pub(super) async fn reconcile_exception_cluster(
    client: Client,
    owner: PolicyDesiredStateOwner,
    control: crate::ControlPlane,
) {
    let api = Api::<WorkloadProtectionException>::all(client.clone());
    let namespaces = Api::<Namespace>::all(client);
    loop {
        owner.record_watch_state("exceptions/*", false);
        let Some(resource_version) =
            relist_exception_cluster(&api, &namespaces, &owner, &control).await
        else {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        let Ok(stream) = api
            .watch(&WatchParams::default().timeout(240), &resource_version)
            .await
        else {
            owner.record_watch_failure();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        owner.record_watch_state("exceptions/*", true);
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(WatchEvent::Added(resource) | WatchEvent::Modified(resource)) => {
                    reconcile_exception_resource(
                        &api,
                        &namespaces,
                        &owner,
                        &control,
                        resource,
                        false,
                    )
                    .await;
                }
                Ok(WatchEvent::Deleted(resource)) => {
                    reconcile_exception_resource(
                        &api,
                        &namespaces,
                        &owner,
                        &control,
                        resource,
                        true,
                    )
                    .await;
                }
                Ok(WatchEvent::Bookmark(_)) => {}
                Ok(WatchEvent::Error(_)) | Err(_) => {
                    owner.record_watch_failure();
                    break;
                }
            }
        }
    }
}

async fn relist_exception_cluster(
    api: &Api<WorkloadProtectionException>,
    namespaces: &Api<Namespace>,
    owner: &PolicyDesiredStateOwner,
    control: &crate::ControlPlane,
) -> Option<String> {
    let mut continuation = None::<String>;
    let mut resource_version = None::<String>;
    let mut seen_object_uids = BTreeSet::new();
    loop {
        let mut params = ListParams::default().limit(500);
        if let Some(token) = &continuation {
            params = params.continue_token(token);
        }
        let page = match api.list(&params).await {
            Ok(page) => page,
            Err(_) => {
                owner.record_relist(false);
                return None;
            }
        };
        for resource in page.items {
            if let Some(object_uid) = &resource.metadata.uid {
                seen_object_uids.insert(object_uid.clone());
            }
            reconcile_exception_resource(api, namespaces, owner, control, resource, false).await;
        }
        resource_version = page.metadata.resource_version.or(resource_version);
        continuation = match super::kubernetes::next_continuation_token(
            continuation.as_deref(),
            page.metadata.continue_,
            "WorkloadProtectionException",
        ) {
            Ok(continuation) => continuation,
            Err(_) => {
                owner.record_relist(false);
                return None;
            }
        };
        if continuation.is_none() {
            break;
        }
    }
    let resource_version = resource_version.filter(|value| !value.is_empty());
    // Absence is authoritative only after every list page completed under one API cursor.
    let complete = resource_version.is_some()
        && owner
            .retire_missing_exceptions(&seen_object_uids, utc_now_ns())
            .is_ok();
    owner.record_relist(complete);
    complete.then_some(resource_version).flatten()
}

async fn reconcile_exception_resource(
    api: &Api<WorkloadProtectionException>,
    namespaces: &Api<Namespace>,
    owner: &PolicyDesiredStateOwner,
    control: &crate::ControlPlane,
    resource: WorkloadProtectionException,
    deleted: bool,
) {
    let Some(name) = resource.metadata.name.clone() else {
        return;
    };
    let generation = resource
        .metadata
        .generation
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_default();
    let Some(namespace_name) = resource.metadata.namespace.as_deref() else {
        return;
    };
    let namespace_uid = match namespaces.get(namespace_name).await {
        Ok(namespace) => namespace.metadata.uid,
        Err(_) => None,
    };
    let source_state = if deleted || resource.metadata.deletion_timestamp.is_some() {
        ExceptionSourceStateV1::DeletionRequested
    } else {
        ExceptionSourceStateV1::Accepted
    };
    let mut status = owner
        .reconcile_exception_observation(
            &resource,
            namespace_uid.as_deref().unwrap_or_default(),
            &control.kubernetes_workload_inventory(),
            utc_now_ns(),
            source_state,
        )
        .map_or_else(
            |_| rejected_exception_status(generation),
            |result| result.status,
        );
    if let Some(previous) = resource.status.as_ref() {
        preserve_transition_times(&mut status.conditions, &previous.conditions);
        if previous == &status {
            return;
        }
    }
    let patch = Patch::Merge(serde_json::json!({"status": status}));
    if api
        .patch_status(&name, &PatchParams::default(), &patch)
        .await
        .is_err()
    {
        owner.record_watch_failure();
    }
}

fn rejected_exception_status(generation: u64) -> WorkloadProtectionExceptionStatusV1 {
    WorkloadProtectionExceptionStatusV1 {
        observed_generation: generation,
        state: WorkloadProtectionExceptionStateV1::Failed,
        conditions: vec![kubernetes_condition(
            "Accepted",
            false,
            generation,
            "ReconcileRejected",
            "Control rejected the stored exception request.",
            utc_now_ns(),
        )],
    }
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    value.filter(|value| !value.is_empty()).ok_or_else(|| {
        invalid(
            "<kubernetes-exception>",
            &format!("the exception has no {field}"),
        )
    })
}

fn invalid(policy_id: &str, reason: &str) -> crate::Error {
    PolicyValidationSnafu {
        policy_id,
        code: "CFG_KUBERNETES_EXCEPTION",
        reason: reason.to_owned(),
    }
    .build()
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

fn valid_id128_hex(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
