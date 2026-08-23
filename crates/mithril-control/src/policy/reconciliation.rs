use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{ListParams, Patch, PatchParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use tokio_stream::StreamExt as _;

use super::{
    CohortSelectionV1, ContainerKindV1, LabelOperatorV1, PolicyActivationAcknowledgementV1,
    PolicyActivationStateV1, PolicyBundleV1, PolicyConditionKindV1, PolicyConditionV1,
    PolicyDeliveryCandidateV1, PolicyDeliveryOperationV1, PolicyDocumentV1, PolicyRolloutCountsV1,
    PolicyRolloutStateV1, PolicyRolloutStatusV1, PolicySourceRevisionV1, PolicySourceStateV1,
    PolicyTargetSnapshotV1, PolicyTargetV1, ProfileCandidateArtifactV1, ProfileSealRequestV1,
    WorkloadProtectionProfile, WorkloadProtectionProfileStatusV1,
};
use crate::error::{IoSnafu, PolicySignatureSnafu, PolicyValidationSnafu};
use crate::{ControlStore, PolicyCompiler, Result};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
/// Captures the exact workload and scheduler facts that can enter a target snapshot.
pub struct WorkloadTargetFactV1 {
    pub node_id: String,
    pub workload_binding_generation_digest: String,
    pub execution_set_id: String,
    pub cluster_uid: String,
    pub namespace_uid: String,
    pub controller_uid: String,
    pub service_account_uid: String,
    pub pod_uid: String,
    pub container_id: String,
    pub container_name: String,
    pub container_kind: ContainerKindV1,
    pub image_digest: String,
    pub pod_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub kubernetes: Option<KubernetesWorkloadIdentityV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesWorkloadIdentityV1 {
    pub namespace_name: String,
    pub profile_id: String,
    pub policy_source_revision_id: String,
    pub binding_id: String,
    pub protected_scope_id: String,
    pub workload_selector_id: String,
    pub kubernetes_node_name: String,
    pub kubernetes_node_uid: String,
    pub node_boot_id: String,
    pub label_epoch: u64,
}

pub fn workload_target_fact_digest(target: &WorkloadTargetFactV1) -> Result<String> {
    // Exclude the digest field so that the remaining immutable facts define its value.
    let mut identity = target.clone();
    identity.workload_binding_generation_digest.clear();
    serde_json::to_vec(&identity)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            PolicyValidationSnafu {
                policy_id: target
                    .kubernetes
                    .as_ref()
                    .map_or("<workload-target>", |identity| identity.profile_id.as_str()),
                code: "CFG_POLICY_TARGET_FACT",
                reason: format!("the workload target cannot be encoded: {error}"),
            }
            .build()
        })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignerConfigV1 {
    pub signing_key_id: String,
    pub signing_key_path: PathBuf,
    pub seal_request_path: PathBuf,
    pub distribution_sequence_epoch: u64,
    pub candidate_validity_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDesiredStateConfigV1 {
    pub tenant_id: String,
    pub cluster_uid: String,
    pub signer: PolicySignerConfigV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyReconcileResultV1 {
    pub source_revision: PolicySourceRevisionV1,
    pub target_snapshot: PolicyTargetSnapshotV1,
    pub bundles: Vec<PolicyBundleV1>,
    pub rollout_states: Vec<PolicyRolloutStateV1>,
    pub status: WorkloadProtectionProfileStatusV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyReconcileHealthV1 {
    pub configured_namespaces: u64,
    pub watched_namespaces: u64,
    pub reconcile_in_flight: u64,
    pub successful_reconciles: u64,
    pub rejected_reconciles: u64,
    pub successful_compiles: u64,
    pub failed_compiles: u64,
    pub successful_relists: u64,
    pub failed_relists: u64,
    pub watch_failures: u64,
}

#[derive(Clone)]
/// Owns accepted desired state, compilation, conflict checks, and reconciliation status.
pub struct PolicyDesiredStateOwner {
    config: Arc<PolicyDesiredStateConfigV1>,
    store: ControlStore,
    compiler: Arc<PolicyCompiler>,
    signing_key: Arc<SigningKey>,
    seal_request: Arc<ProfileSealRequestV1>,
    state: Arc<Mutex<DesiredStateMemory>>,
    rollout: PolicyRolloutOwner,
}

#[derive(Default)]
struct DesiredStateMemory {
    reconciled: BTreeMap<String, PolicyReconcileResultV1>,
    watched_namespaces: BTreeSet<String>,
    reconcile_in_flight: u64,
    successful_reconciles: u64,
    rejected_reconciles: u64,
    successful_compiles: u64,
    failed_compiles: u64,
    successful_relists: u64,
    failed_relists: u64,
    watch_failures: u64,
}

#[derive(Clone)]
/// Owns immutable target snapshots, node candidates, and acknowledgement transitions.
pub struct PolicyRolloutOwner {
    store: ControlStore,
    signing_key: Arc<SigningKey>,
    signing_key_id: Arc<str>,
    distribution_sequence_epoch: u64,
    candidate_validity_ns: i64,
}

impl PolicyDesiredStateConfigV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            canonical_uuid(&self.tenant_id)
                && canonical_uuid(&self.cluster_uid)
                && !self.signer.signing_key_id.is_empty()
                && self.signer.signing_key_path.is_absolute()
                && self.signer.seal_request_path.is_absolute()
                && self.signer.distribution_sequence_epoch > 0
                && self.signer.candidate_validity_ns > 0,
            PolicyValidationSnafu {
                policy_id: "<kubernetes-control>",
                code: "CFG_KUBERNETES_CONTROL",
                reason: "Kubernetes policy control needs trusted identities, signer paths, and nonzero sequence bounds",
            }
        );
        Ok(())
    }
}

impl PolicyDesiredStateOwner {
    pub fn open(config: PolicyDesiredStateConfigV1, store: ControlStore) -> Result<Self> {
        config.validate()?;
        let signing_key = read_signing_key(&config.signer.signing_key_path)?;
        let seal_request: ProfileSealRequestV1 = read_json(&config.signer.seal_request_path)?;
        ensure!(
            seal_request.signing_key_id == config.signer.signing_key_id
                && seal_request.sequence_epoch > 0,
            PolicyValidationSnafu {
                policy_id: "<kubernetes-control>",
                code: "CFG_POLICY_SIGNER",
                reason: "the seal request does not match the configured policy signer",
            }
        );
        Ok(Self::new(config, store, signing_key, seal_request))
    }

    #[must_use]
    pub fn new(
        config: PolicyDesiredStateConfigV1,
        store: ControlStore,
        signing_key: SigningKey,
        seal_request: ProfileSealRequestV1,
    ) -> Self {
        let signing_key = Arc::new(signing_key);
        let rollout = PolicyRolloutOwner {
            store: store.clone(),
            signing_key: signing_key.clone(),
            signing_key_id: Arc::from(config.signer.signing_key_id.as_str()),
            distribution_sequence_epoch: config.signer.distribution_sequence_epoch,
            candidate_validity_ns: config.signer.candidate_validity_ns,
        };
        Self {
            config: Arc::new(config),
            store,
            compiler: Arc::new(PolicyCompiler),
            signing_key,
            seal_request: Arc::new(seal_request),
            state: Arc::new(Mutex::new(DesiredStateMemory::default())),
            rollout,
        }
    }

    pub fn reconcile(
        &self,
        resource: &WorkloadProtectionProfile,
        namespace_uid: &str,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<PolicyReconcileResultV1> {
        let state = if resource.metadata.deletion_timestamp.is_some() {
            PolicySourceStateV1::DeletionRequested
        } else {
            PolicySourceStateV1::Accepted
        };
        self.reconcile_observation(resource, namespace_uid, inventory, now_utc_ns, state)
    }

    fn reconcile_observation(
        &self,
        resource: &WorkloadProtectionProfile,
        namespace_uid: &str,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
        state: PolicySourceStateV1,
    ) -> Result<PolicyReconcileResultV1> {
        self.track_reconcile(|| {
            let source = PolicySourceRevisionV1::from_resource(
                resource,
                &self.config.tenant_id,
                &self.config.cluster_uid,
                namespace_uid,
                state,
            )?;
            self.reconcile_inner(source, &resource.spec.policy, inventory, now_utc_ns)
        })
    }

    fn reconcile_source(
        &self,
        source: PolicySourceRevisionV1,
        policy: &PolicyDocumentV1,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<PolicyReconcileResultV1> {
        self.track_reconcile(|| self.reconcile_inner(source, policy, inventory, now_utc_ns))
    }

    fn track_reconcile<T>(&self, reconcile: impl FnOnce() -> Result<T>) -> Result<T> {
        {
            let mut state = self.state()?;
            state.reconcile_in_flight = state.reconcile_in_flight.saturating_add(1);
        }
        let result = reconcile();
        {
            let mut state = self.state()?;
            state.reconcile_in_flight = state.reconcile_in_flight.saturating_sub(1);
            if result.is_ok() {
                state.successful_reconciles = state.successful_reconciles.saturating_add(1);
            } else {
                state.rejected_reconciles = state.rejected_reconciles.saturating_add(1);
            }
        }
        result
    }

    fn reconcile_inner(
        &self,
        source: PolicySourceRevisionV1,
        policy: &PolicyDocumentV1,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<PolicyReconcileResultV1> {
        ensure!(
            canonical_uuid(&source.namespace_uid)
                && policy
                    .workload_selectors
                    .iter()
                    .all(|selector| {
                        selector.cluster_uids.iter().all(|uid| uid == &self.config.cluster_uid)
                            && selector
                                .namespace_uids
                                .iter()
                                .all(|uid| uid == &source.namespace_uid)
                    }),
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_CROSS_TENANT_SELECTOR",
                reason: "the policy has a cluster or namespace selector outside its authenticated tenant scope",
            }
        );
        // Persist desired state before compilation so restart recovery sees every accepted input.
        self.store
            .accept_source_revision(source.clone(), policy.clone())?;
        let mut targets = resolve_targets(
            policy,
            inventory,
            &self.config.tenant_id,
            &self.config.cluster_uid,
        )?;
        self.claim(&source, policy, &targets)?;

        if source.state == PolicySourceStateV1::DeletionRequested {
            // Retirement follows the last delivered targets, not the now-empty live inventory.
            targets = self
                .store
                .latest_bundles_for_object(&source.object_uid)?
                .into_iter()
                .map(|bundle| bundle.candidate.exact_target)
                .collect();
            targets.sort();
            targets.dedup();
        }

        // Reuse the immutable artifact on restart. A source revision gets one issuer sequence.
        let artifact = if let Some(artifact) = self
            .store
            .compiled_artifact(&source.policy_source_revision_id)?
        {
            artifact
        } else {
            let compiled = match self.compiler.compile(policy) {
                Ok(compiled) => {
                    let mut state = self.state()?;
                    state.successful_compiles = state.successful_compiles.saturating_add(1);
                    compiled
                }
                Err(error) => {
                    let mut state = self.state()?;
                    state.failed_compiles = state.failed_compiles.saturating_add(1);
                    return Err(error);
                }
            };
            let mut seal_request = (*self.seal_request).clone();
            seal_request.issuer_sequence = self.store.next_policy_issuer_sequence(
                &seal_request.signing_key_id,
                seal_request.sequence_epoch,
                seal_request.issuer_sequence,
            )?;
            let artifact = ProfileCandidateArtifactV1::sign(
                policy,
                compiled,
                seal_request,
                &self.signing_key,
            )?;
            self.store
                .record_compiled_artifact(&source.policy_source_revision_id, artifact.clone())?;
            artifact
        };
        let artifact_bytes = serde_json::to_vec(&artifact).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_POLICY_ARTIFACT",
                reason: format!("the signed profile artifact cannot be encoded: {error}"),
            }
            .build()
        })?;
        let signed_profile_digest = sha256(&artifact_bytes);
        let snapshot = PolicyTargetSnapshotV1::new(
            source.policy_source_revision_id.clone(),
            signed_profile_digest,
            policy.rollout.rollout_generation,
            targets,
        )?;
        // An identical snapshot reuses its candidates and does not consume new replay sequence.
        let (bundles, rollout_states) = if self
            .store
            .latest_snapshot_for_source(&source.policy_source_revision_id)?
            .as_ref()
            == Some(&snapshot)
        {
            (
                self.store
                    .bundles_for_snapshot(&snapshot.target_snapshot_digest)?,
                self.store
                    .rollout_states_for_snapshot(&snapshot.target_snapshot_digest)?,
            )
        } else {
            self.rollout.create(
                &source,
                snapshot.clone(),
                artifact,
                self.signing_key.verifying_key().to_bytes().to_vec(),
                now_utc_ns,
            )?
        };
        let status = status_for(
            &source,
            bundles
                .first()
                .map(|bundle| bundle.candidate.candidate_content_id.clone()),
            &rollout_states,
            None,
        );
        let result = PolicyReconcileResultV1 {
            source_revision: source,
            target_snapshot: snapshot,
            bundles,
            rollout_states,
            status,
        };
        self.state()?.reconciled.insert(
            result.source_revision.policy_source_revision_id.clone(),
            result.clone(),
        );
        Ok(result)
    }

    /// Retires live sources that are absent from one complete API snapshot.
    /// The caller must not use UIDs from a partial list.
    pub fn retire_missing_sources(
        &self,
        seen_object_uids: &BTreeSet<String>,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<Vec<PolicyReconcileResultV1>> {
        self.store
            .latest_live_sources()?
            .into_iter()
            .filter(|(source, _)| !seen_object_uids.contains(&source.object_uid))
            .map(|(source, policy)| {
                self.reconcile_source(source.deletion_requested()?, &policy, inventory, now_utc_ns)
            })
            .collect()
    }

    #[must_use]
    pub fn store(&self) -> ControlStore {
        self.store.clone()
    }

    pub fn live_policies_in_namespace(
        &self,
        namespace: &str,
    ) -> Result<Vec<(PolicySourceRevisionV1, PolicyDocumentV1, bool)>> {
        let policies = self
            .store
            .latest_live_sources()?
            .into_iter()
            .filter(|(source, _)| source.namespace_name == namespace)
            .map(|(source, policy)| {
                let compiled = self
                    .store
                    .compiled_artifact(&source.policy_source_revision_id)?
                    .is_some();
                Ok((source, policy, compiled))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(policies)
    }

    #[must_use]
    pub fn cluster_uid(&self) -> &str {
        &self.config.cluster_uid
    }

    #[must_use]
    pub fn rollout_owner(&self) -> PolicyRolloutOwner {
        self.rollout.clone()
    }

    #[must_use]
    pub fn signer_identity(&self) -> (&str, String, u64) {
        (
            &self.config.signer.signing_key_id,
            hex::encode(self.signing_key.verifying_key().to_bytes()),
            self.seal_request.sequence_epoch,
        )
    }

    pub fn health(&self) -> Result<PolicyReconcileHealthV1> {
        let state = self.state()?;
        Ok(PolicyReconcileHealthV1 {
            configured_namespaces: 1,
            watched_namespaces: count(state.watched_namespaces.len()),
            reconcile_in_flight: state.reconcile_in_flight,
            successful_reconciles: state.successful_reconciles,
            rejected_reconciles: state.rejected_reconciles,
            successful_compiles: state.successful_compiles,
            failed_compiles: state.failed_compiles,
            successful_relists: state.successful_relists,
            failed_relists: state.failed_relists,
            watch_failures: state.watch_failures,
        })
    }

    fn record_relist(&self, succeeded: bool) {
        if let Ok(mut state) = self.state.lock() {
            if succeeded {
                state.successful_relists = state.successful_relists.saturating_add(1);
            } else {
                state.failed_relists = state.failed_relists.saturating_add(1);
            }
        }
    }

    fn record_watch_state(&self, namespace: &str, connected: bool) {
        if let Ok(mut state) = self.state.lock() {
            if connected {
                state.watched_namespaces.insert(namespace.to_owned());
            } else {
                state.watched_namespaces.remove(namespace);
            }
        }
    }

    fn record_watch_failure(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.watch_failures = state.watch_failures.saturating_add(1);
        }
    }

    pub async fn run_kubernetes(self, control: crate::ControlPlane) {
        // Source watch and bound-workload inventory share this desired-state owner.
        loop {
            let Ok(client) = Client::try_default().await else {
                self.record_watch_failure();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            };
            tokio::join!(
                reconcile_cluster(client.clone(), self.clone(), control.clone()),
                super::KubernetesWorkloadInventoryOwner::new(
                    client,
                    self.clone(),
                    control.clone(),
                )
                .run(),
            );
        }
    }

    fn claim(
        &self,
        source: &PolicySourceRevisionV1,
        policy: &PolicyDocumentV1,
        targets: &[PolicyTargetV1],
    ) -> Result<()> {
        let profile_key = (
            source.tenant_id.clone(),
            policy.metadata.trust_domain_id.clone(),
            policy.metadata.profile_id.clone(),
        );
        let target_bindings = targets
            .iter()
            .flat_map(|target| target.workload_binding_generation_digests.iter())
            .collect::<BTreeSet<_>>();
        // Reject competing owners. Version 1 has no priority or deny-wins rule.
        for (owner, owner_policy) in self.store.latest_live_sources()? {
            if owner.object_uid == source.object_uid {
                continue;
            }
            ensure!(
                (
                    owner.tenant_id.clone(),
                    owner_policy.metadata.trust_domain_id.clone(),
                    owner_policy.metadata.profile_id.clone(),
                ) != profile_key,
                PolicyValidationSnafu {
                    policy_id: policy.profile_id(),
                    code: "CFG_DUPLICATE_PROFILE_OWNER",
                    reason: "another live CRD owns this tenant, trust-domain, and profile ID",
                }
            );
            if let Some(snapshot) = self
                .store
                .latest_snapshot_for_source(&owner.policy_source_revision_id)?
            {
                ensure!(
                    snapshot
                        .targets
                        .iter()
                        .flat_map(|target| { target.workload_binding_generation_digests.iter() })
                        .all(|binding| !target_bindings.contains(binding)),
                    PolicyValidationSnafu {
                        policy_id: policy.profile_id(),
                        code: "CFG_OVERLAPPING_WORKLOAD_OWNER",
                        reason: "another live CRD selects this exact workload binding",
                    }
                );
            }
        }
        ensure!(
            !source.policy_source_revision_id.is_empty(),
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_POLICY_SOURCE_REVISION",
                reason: "the source revision has no content identity",
            }
        );
        Ok(())
    }

    fn state(&self) -> Result<MutexGuard<'_, DesiredStateMemory>> {
        self.state.lock().map_err(|_| {
            PolicyValidationSnafu {
                policy_id: "<kubernetes-control>",
                code: "CFG_POLICY_STATE",
                reason: "the desired-state owner lock is poisoned".to_owned(),
            }
            .build()
        })
    }
}

impl PolicyRolloutOwner {
    fn create(
        &self,
        source: &PolicySourceRevisionV1,
        snapshot: PolicyTargetSnapshotV1,
        artifact: ProfileCandidateArtifactV1,
        public_key: Vec<u8>,
        now_utc_ns: i64,
    ) -> Result<(Vec<PolicyBundleV1>, Vec<PolicyRolloutStateV1>)> {
        let mut bundles = Vec::with_capacity(snapshot.targets.len());
        let mut rollout_states = Vec::with_capacity(snapshot.targets.len());
        for target in &snapshot.targets {
            // Distribution ordering is per node and profile, separate from issuer ordering.
            let sequence = self.store.next_distribution_sequence(
                &target.node_id,
                &source.tenant_id,
                &artifact.policy_document.metadata.trust_domain_id,
                &artifact.policy_document.metadata.profile_id,
                self.distribution_sequence_epoch,
            )?;
            // The predecessor forms one explicit node-local replacement chain.
            let predecessor = self
                .store
                .latest_bundle_for_profile_node(
                    &target.node_id,
                    &source.tenant_id,
                    &artifact.policy_document.metadata.trust_domain_id,
                    &artifact.policy_document.metadata.profile_id,
                )?
                .map(|bundle| bundle.candidate.candidate_content_id);
            let operation = if source.state == PolicySourceStateV1::DeletionRequested {
                PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
            } else if predecessor.is_some() {
                PolicyDeliveryOperationV1::Replace
            } else {
                PolicyDeliveryOperationV1::Activate
            };
            let candidate = PolicyDeliveryCandidateV1::sign(
                source.tenant_id.clone(),
                source.policy_source_revision_id.clone(),
                snapshot.signed_profile_digest.clone(),
                &snapshot,
                target.clone(),
                operation,
                predecessor,
                self.distribution_sequence_epoch,
                sequence,
                now_utc_ns,
                now_utc_ns.saturating_add(self.candidate_validity_ns),
                self.signing_key_id.to_string(),
                &self.signing_key,
            )?;
            let candidate_id = candidate.candidate_content_id.clone();
            bundles.push(PolicyBundleV1::new(
                candidate,
                artifact.clone(),
                public_key.clone(),
            )?);
            rollout_states.push(PolicyRolloutStateV1 {
                policy_source_revision_id: source.policy_source_revision_id.clone(),
                target_snapshot_digest: snapshot.target_snapshot_digest.clone(),
                target: target.clone(),
                desired_candidate_content_id: candidate_id,
                state: PolicyRolloutStatusV1::Pending,
                latest_acknowledgement_content_id: None,
                transition_version: 0,
                updated_utc_ns: now_utc_ns,
            });
        }
        self.store
            .create_rollout(snapshot, bundles.clone(), rollout_states.clone())?;
        Ok((bundles, rollout_states))
    }

    pub fn acknowledge(
        &self,
        acknowledgement: PolicyActivationAcknowledgementV1,
    ) -> Result<PolicyRolloutStateV1> {
        let current = self
            .store
            .rollout_state(
                &acknowledgement.candidate_content_id,
                &acknowledgement.node_id,
            )?
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: &acknowledgement.policy_source_revision_id,
                    code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                    reason: "the node acknowledgement does not name a current rollout target"
                        .to_owned(),
                }
                .build()
            })?;
        // A delayed acknowledgement cannot advance a candidate after a later rollout wins.
        ensure!(
            acknowledgement.policy_source_revision_id == current.policy_source_revision_id
                && acknowledgement.target_snapshot_digest == current.target_snapshot_digest
                && acknowledgement.tenant_id == current.target.tenant_id,
            PolicyValidationSnafu {
                policy_id: &acknowledgement.policy_source_revision_id,
                code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                reason: "the acknowledgement source, snapshot, or tenant is stale",
            }
        );
        let bundle = self
            .store
            .bundle_for_candidate(
                &acknowledgement.node_id,
                &acknowledgement.candidate_content_id,
            )?
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: &acknowledgement.policy_source_revision_id,
                    code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                    reason: "the acknowledgement candidate has no immutable bundle".to_owned(),
                }
                .build()
            })?;
        let document = &bundle.profile_artifact.policy_document;
        let latest = self.store.latest_bundle_for_profile_node(
            &acknowledgement.node_id,
            &acknowledgement.tenant_id,
            &document.metadata.trust_domain_id,
            &document.metadata.profile_id,
        )?;
        ensure!(
            latest.as_ref().is_some_and(|latest| {
                latest.candidate.candidate_content_id == acknowledgement.candidate_content_id
            }),
            PolicyValidationSnafu {
                policy_id: &acknowledgement.policy_source_revision_id,
                code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                reason: "a later candidate already owns this profile and node target",
            }
        );
        let state = match acknowledgement.state {
            PolicyActivationStateV1::Received => PolicyRolloutStatusV1::Delivered,
            PolicyActivationStateV1::Staged => PolicyRolloutStatusV1::Staged,
            PolicyActivationStateV1::Active => PolicyRolloutStatusV1::Active,
            PolicyActivationStateV1::Rejected => PolicyRolloutStatusV1::Rejected,
            PolicyActivationStateV1::Stale => PolicyRolloutStatusV1::Stale,
            PolicyActivationStateV1::Unknown => PolicyRolloutStatusV1::Unknown,
        };
        let next = PolicyRolloutStateV1 {
            state,
            latest_acknowledgement_content_id: Some(
                acknowledgement.acknowledgement_content_id.clone(),
            ),
            transition_version: current.transition_version.saturating_add(1),
            updated_utc_ns: acknowledgement.observed_utc_ns,
            ..current
        };
        self.store
            .acknowledge_policy(acknowledgement, next.clone())?;
        Ok(next)
    }
}

async fn reconcile_cluster(
    client: Client,
    owner: PolicyDesiredStateOwner,
    control: crate::ControlPlane,
) {
    let api = Api::<WorkloadProtectionProfile>::all(client.clone());
    let namespaces = Api::<Namespace>::all(client);
    // Each watch starts from a complete relist cursor and restarts after any stream error.
    loop {
        owner.record_watch_state("*", false);
        let Some(resource_version) = relist_cluster(&api, &namespaces, &owner, &control).await
        else {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        let watch = api
            .watch(&WatchParams::default().timeout(240), &resource_version)
            .await;
        let Ok(stream) = watch else {
            owner.record_watch_failure();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        owner.record_watch_state("*", true);
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(WatchEvent::Added(resource) | WatchEvent::Modified(resource)) => {
                    reconcile_resource(&api, &namespaces, &owner, &control, resource, false).await;
                }
                Ok(WatchEvent::Deleted(resource)) => {
                    reconcile_resource(&api, &namespaces, &owner, &control, resource, true).await;
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

async fn relist_cluster(
    api: &Api<WorkloadProtectionProfile>,
    namespaces: &Api<Namespace>,
    owner: &PolicyDesiredStateOwner,
    control: &crate::ControlPlane,
) -> Option<String> {
    let mut continuation = None::<String>;
    let mut resource_version = None::<String>;
    // Collect UIDs across every page. Only a complete set can prove deletion by absence.
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
            reconcile_resource(api, namespaces, owner, control, resource, false).await;
        }
        resource_version = page.metadata.resource_version.or(resource_version);
        continuation = page.metadata.continue_;
        if continuation.as_ref().is_none_or(String::is_empty) {
            break;
        }
    }
    let resource_version = resource_version.filter(|value| !value.is_empty());
    // Retire missing sources before the watch begins, or discard the snapshot as incomplete.
    let complete = resource_version.is_some()
        && owner
            .retire_missing_sources(
                &seen_object_uids,
                &control.workload_inventory(),
                utc_now_ns(),
            )
            .is_ok();
    owner.record_relist(complete);
    if complete {
        resource_version
    } else {
        None
    }
}

async fn reconcile_resource(
    api: &Api<WorkloadProtectionProfile>,
    namespaces: &Api<Namespace>,
    owner: &PolicyDesiredStateOwner,
    control: &crate::ControlPlane,
    resource: WorkloadProtectionProfile,
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
        PolicySourceStateV1::DeletionRequested
    } else {
        PolicySourceStateV1::Accepted
    };
    // Reconciliation failure changes only status; it does not replace the last valid rollout.
    let status = owner
        .reconcile_observation(
            &resource,
            namespace_uid.as_deref().unwrap_or_default(),
            &control.workload_inventory(),
            utc_now_ns(),
            source_state,
        )
        .map_or_else(|_| rejected_status(generation), |result| result.status);
    let patch = Patch::Merge(serde_json::json!({"status": status}));
    let _result = api
        .patch_status(&name, &PatchParams::default(), &patch)
        .await;
}

fn rejected_status(generation: u64) -> WorkloadProtectionProfileStatusV1 {
    let condition = |condition| PolicyConditionV1 {
        condition,
        status: false,
        reason_code: "RECONCILE_REJECTED".to_owned(),
        observed_generation: generation,
    };
    WorkloadProtectionProfileStatusV1 {
        observed_generation: generation,
        source_revision_id: None,
        canonical_spec_digest: None,
        candidate_content_id: None,
        rollout_counts: PolicyRolloutCountsV1::default(),
        conditions: [
            PolicyConditionKindV1::Accepted,
            PolicyConditionKindV1::Compiled,
            PolicyConditionKindV1::Progressing,
            PolicyConditionKindV1::Available,
            PolicyConditionKindV1::Degraded,
            PolicyConditionKindV1::Retiring,
        ]
        .map(condition)
        .to_vec(),
    }
}

fn utc_now_ns() -> i64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

fn resolve_targets(
    policy: &PolicyDocumentV1,
    inventory: &[WorkloadTargetFactV1],
    tenant_id: &str,
    cluster_uid: &str,
) -> Result<Vec<PolicyTargetV1>> {
    let selector_ids = policy
        .workload_selectors
        .iter()
        .map(|selector| selector.workload_selector_id.as_str())
        .collect::<BTreeSet<_>>();
    // Group exact bindings by node so each signed candidate has one delivery destination.
    let mut selected = BTreeMap::<String, BTreeMap<String, WorkloadTargetFactV1>>::new();
    for fact in inventory {
        let matches_selector = policy.workload_selectors.iter().any(|selector| {
            selector_ids.contains(selector.workload_selector_id.as_str())
                && selector.cluster_uids.contains(&fact.cluster_uid)
                && selector.namespace_uids.contains(&fact.namespace_uid)
                && matches_optional(&selector.controller_uids, &fact.controller_uid)
                && matches_optional(&selector.service_account_uids, &fact.service_account_uid)
                && matches_optional(&selector.container_names, &fact.container_name)
                && (selector.container_kinds.is_empty()
                    || selector.container_kinds.contains(&fact.container_kind))
                && matches_optional(&selector.image_digests, &fact.image_digest)
                && selector.pod_label_requirements.iter().all(|requirement| {
                    let value = fact.pod_labels.get(&requirement.key);
                    match requirement.operator {
                        LabelOperatorV1::In => {
                            value.is_some_and(|value| requirement.values.contains(value))
                        }
                        LabelOperatorV1::NotIn => {
                            value.is_some_and(|value| !requirement.values.contains(value))
                        }
                        LabelOperatorV1::Exists => value.is_some(),
                        LabelOperatorV1::DoesNotExist => value.is_none(),
                    }
                })
        });
        let profile_matches = fact.kubernetes.as_ref().is_none_or(|identity| {
            identity.profile_id == policy.profile_id()
                && !identity.policy_source_revision_id.is_empty()
        });
        if matches_selector && profile_matches && selected_by_rollout(policy, fact) {
            ensure!(
                fact.cluster_uid == cluster_uid
                    && crate::node_id_is_valid(&fact.node_id)
                    && valid_sha256(&fact.workload_binding_generation_digest),
                PolicyValidationSnafu {
                    policy_id: policy.profile_id(),
                    code: "CFG_POLICY_TARGET_FACT",
                    reason: "a selected workload target has an invalid cluster, node, or digest",
                }
            );
            selected.entry(fact.node_id.clone()).or_default().insert(
                fact.workload_binding_generation_digest.clone(),
                fact.clone(),
            );
        }
    }
    let targets = selected
        .into_iter()
        .map(|(node_id, bindings)| {
            let workload_binding_generation_digests = bindings.keys().cloned().collect();
            let workload_targets = bindings
                .into_values()
                .filter(|target| target.kubernetes.is_some())
                .collect();
            PolicyTargetV1 {
                tenant_id: tenant_id.to_owned(),
                cluster_uid: cluster_uid.to_owned(),
                node_id,
                workload_binding_generation_digests,
                workload_targets,
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        targets
            .iter()
            .map(|target| target.workload_binding_generation_digests.len())
            .sum::<usize>()
            <= 65_536,
        PolicyValidationSnafu {
            policy_id: policy.profile_id(),
            code: "CFG_POLICY_TARGETS",
            reason: "the policy target snapshot exceeds the aggregate target bound",
        }
    );
    Ok(targets)
}

fn selected_by_rollout(policy: &PolicyDocumentV1, fact: &WorkloadTargetFactV1) -> bool {
    match policy.rollout.cohort_selection {
        CohortSelectionV1::AllBoundExecutionSets => true,
        CohortSelectionV1::ExplicitExecutionSets => policy
            .rollout
            .explicit_execution_set_ids
            .contains(&fact.execution_set_id),
        CohortSelectionV1::HashedExecutionSetBinding => {
            // Stable policy and workload identities make cohort selection deterministic.
            let mut digest = Sha256::new();
            digest.update(policy.metadata.profile_id.as_bytes());
            digest.update(policy.metadata.profile_version.to_be_bytes());
            digest.update(policy.rollout.rollout_generation.to_be_bytes());
            digest.update(fact.execution_set_id.as_bytes());
            digest.update(fact.workload_binding_generation_digest.as_bytes());
            let value = u32::from_be_bytes(digest.finalize()[..4].try_into().unwrap_or_default());
            let bucket = value % policy.rollout.selector_hash_modulus;
            policy
                .rollout
                .selected_bucket_ids
                .binary_search(&bucket)
                .is_ok()
        }
    }
}

fn status_for(
    source: &PolicySourceRevisionV1,
    candidate_content_id: Option<String>,
    states: &[PolicyRolloutStateV1],
    degraded_reason: Option<&str>,
) -> WorkloadProtectionProfileStatusV1 {
    // Status summarizes durable per-target state. It never grants rollout authority.
    let counts = PolicyRolloutCountsV1::from_states(states);
    let retiring = source.state == PolicySourceStateV1::DeletionRequested;
    let available = counts.total() > 0 && counts.active == counts.total();
    let degraded =
        degraded_reason.is_some() || counts.rejected > 0 || counts.stale > 0 || counts.unknown > 0;
    let progressing = !available && !retiring;
    let condition = |condition, status, reason_code: &str| PolicyConditionV1 {
        condition,
        status,
        reason_code: reason_code.to_owned(),
        observed_generation: source.object_generation,
    };
    WorkloadProtectionProfileStatusV1 {
        observed_generation: source.object_generation,
        source_revision_id: Some(source.policy_source_revision_id.clone()),
        canonical_spec_digest: Some(source.canonical_spec_digest.clone()),
        candidate_content_id,
        rollout_counts: counts,
        conditions: vec![
            condition(PolicyConditionKindV1::Accepted, true, "SOURCE_ACCEPTED"),
            condition(PolicyConditionKindV1::Compiled, true, "POLICY_COMPILED"),
            condition(
                PolicyConditionKindV1::Progressing,
                progressing,
                "ROLLOUT_PENDING",
            ),
            condition(
                PolicyConditionKindV1::Available,
                available,
                "ALL_TARGETS_ACTIVE",
            ),
            condition(
                PolicyConditionKindV1::Degraded,
                degraded,
                degraded_reason.unwrap_or("NO_DEGRADED_TARGET"),
            ),
            condition(
                PolicyConditionKindV1::Retiring,
                retiring,
                "DELETION_REQUESTED",
            ),
        ],
    }
}

fn matches_optional(values: &[String], fact: &str) -> bool {
    values.is_empty() || values.iter().any(|value| value == fact)
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

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: error.to_string(),
        }
        .build()
    })?;
    let decoded = hex::decode(text.trim()).map_err(|error| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: error.to_string(),
        }
        .build()
    })?;
    let key: [u8; 32] = decoded.try_into().map_err(|_: Vec<u8>| {
        PolicySignatureSnafu {
            key_id: path.display().to_string(),
            reason: "the signing key must contain 32 lowercase-hex bytes".to_owned(),
        }
        .build()
    })?;
    Ok(SigningKey::from_bytes(&key))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    serde_json::from_slice(&bytes).context(crate::error::JsonSnafu { path })
}
