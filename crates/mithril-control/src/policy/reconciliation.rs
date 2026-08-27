use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use erebor_telemetry::{info, warn};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{ListParams, Patch, PatchParams, WatchEvent, WatchParams};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use tokio_stream::StreamExt as _;

use super::{
    CohortSelectionV1, ContainerKindV1, ErrnoV1, EvaluationStageV1, LabelOperatorV1,
    PolicyActivationAcknowledgementV1, PolicyActivationStateV1, PolicyBundleV1,
    PolicyDeliveryCandidateV1, PolicyDeliveryOperationV1, PolicyDispositionV1, PolicyDocumentV1,
    PolicyRolloutCountsV1, PolicyRolloutStateV1, PolicyRolloutStatusV1, PolicySourceRevisionV1,
    PolicySourceStateV1, PolicyTargetSnapshotV1, PolicyTargetV1, ProfileCandidateArtifactV1,
    ProfileSealRequestV1, WorkloadProtectionPolicy, WorkloadProtectionPolicyStatusV1,
};
use crate::error::{IoSnafu, PolicySignatureSnafu, PolicyValidationSnafu};
use crate::{ControlStore, PolicyCompiler, Result};

const RECONCILE_WRITER_LIMIT: u64 = 1;
const DESIRED_STATE_WATCH_COUNT: u64 = 2;

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
    #[serde(default)]
    pub pod_name: String,
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
    pub retirement_bundles: Vec<PolicyBundleV1>,
    pub retirement_rollout_states: Vec<PolicyRolloutStateV1>,
    pub status: WorkloadProtectionPolicyStatusV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAcknowledgementResultV1 {
    pub rollout_state: PolicyRolloutStateV1,
    pub terminal_chain_closure_authorized: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyReconcileHealthV1 {
    pub reconcile_queue_limit: u64,
    pub configured_watches: u64,
    pub connected_watches: u64,
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
    pub(super) config: Arc<PolicyDesiredStateConfigV1>,
    pub(super) store: ControlStore,
    compiler: Arc<PolicyCompiler>,
    signing_key: Arc<SigningKey>,
    seal_request: Arc<ProfileSealRequestV1>,
    state: Arc<Mutex<DesiredStateMemory>>,
    // One guard owns the multi-commit reconcile transaction across watch and admission callers.
    pub(super) reconcile_lock: Arc<Mutex<()>>,
    pub(super) rollout: PolicyRolloutOwner,
}

#[derive(Default)]
struct DesiredStateMemory {
    reconciled: BTreeMap<String, PolicyReconcileResultV1>,
    connected_watches: BTreeSet<String>,
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
    pub(super) store: ControlStore,
    pub(super) signing_key: Arc<SigningKey>,
    pub(super) signing_key_id: Arc<str>,
    pub(super) distribution_sequence_epoch: u64,
    pub(super) candidate_validity_ns: i64,
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
            reconcile_lock: Arc::new(Mutex::new(())),
            rollout,
        }
    }

    pub fn reconcile(
        &self,
        resource: &WorkloadProtectionPolicy,
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

    pub(super) fn reconcile_observation(
        &self,
        resource: &WorkloadProtectionPolicy,
        namespace_uid: &str,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
        state: PolicySourceStateV1,
    ) -> Result<PolicyReconcileResultV1> {
        self.track_reconcile(|| {
            let retained = if state == PolicySourceStateV1::DeletionRequested {
                match (
                    resource.metadata.name.as_deref(),
                    resource.metadata.uid.as_deref(),
                ) {
                    (Some(object_name), Some(object_uid)) => {
                        if let Some(source) = self.store.latest_source(
                            &self.config.tenant_id,
                            namespace_uid,
                            object_name,
                        )? {
                            if source.object_uid == object_uid {
                                self.store
                                    .policy_document(&source.policy_source_revision_id)?
                                    .map(|policy| (source, policy))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            };
            // Deletion retires the last compiled revision, even if a later API update was invalid.
            let (source, policy) = if let Some((source, policy)) = retained {
                (source.deletion_requested()?, policy)
            } else {
                let policy = super::lower_kubernetes_policy(
                    resource,
                    &self.config.tenant_id,
                    &self.config.cluster_uid,
                    namespace_uid,
                )?;
                let source = PolicySourceRevisionV1::from_resource(
                    resource,
                    &policy,
                    &self.config.tenant_id,
                    &self.config.cluster_uid,
                    namespace_uid,
                    state,
                )?;
                (source, policy)
            };
            self.reconcile_inner(source, &policy, inventory, now_utc_ns)
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

    fn compile_artifact_after(
        &self,
        document: &PolicyDocumentV1,
        predecessor: Option<&ProfileCandidateArtifactV1>,
    ) -> Result<ProfileCandidateArtifactV1> {
        let compiled = match self.compiler.compile(document) {
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
        let durable_next = self.store.next_policy_issuer_sequence(
            &seal_request.signing_key_id,
            seal_request.sequence_epoch,
            seal_request.issuer_sequence,
        )?;
        seal_request.issuer_sequence = predecessor.map_or(Ok(durable_next), |artifact| {
            artifact
                .header
                .issuer_sequence
                .checked_add(1)
                .map(|next| durable_next.max(next))
                .ok_or_else(|| {
                    PolicyValidationSnafu {
                        policy_id: document.profile_id(),
                        code: "CFG_POLICY_ISSUER_SEQUENCE",
                        reason: "the policy-issuer sequence is exhausted".to_owned(),
                    }
                    .build()
                })
        })?;
        ProfileCandidateArtifactV1::sign(document, compiled, seal_request, &self.signing_key)
    }

    fn reconcile_inner(
        &self,
        source: PolicySourceRevisionV1,
        policy: &PolicyDocumentV1,
        inventory: &[WorkloadTargetFactV1],
        now_utc_ns: i64,
    ) -> Result<PolicyReconcileResultV1> {
        let _reconcile_guard = self.reconcile_lock.lock().map_err(|_| {
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_RECONCILE_LOCK",
                reason: "the policy reconcile owner lock is poisoned".to_owned(),
            }
            .build()
        })?;
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
        let mut targets = resolve_targets(
            &source,
            policy,
            inventory,
            &self.config.tenant_id,
            &self.config.cluster_uid,
        )?;
        self.claim(&source, policy, &targets)?;

        if source.state == PolicySourceStateV1::DeletionRequested {
            targets.clear();
        }

        let artifact_document = policy.clone();
        // Reuse the immutable artifact on restart.
        let artifact = if let Some(artifact) = self
            .store
            .compiled_artifact(&source.policy_source_revision_id)?
            .filter(|artifact| artifact.policy_document == artifact_document)
        {
            artifact
        } else {
            self.compile_artifact_after(&artifact_document, None)?
        };
        // Promote the source and its signed artifact in one durable transaction.
        self.store.accept_compiled_source_revision(
            source.clone(),
            policy.clone(),
            artifact.clone(),
        )?;
        if source.state == PolicySourceStateV1::Accepted {
            return self
                .reconcile_accepted_target_set(source, policy, targets, artifact, now_utc_ns);
        }
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
        let status = status_for(&source, &rollout_states, None, now_utc_ns);
        let result = PolicyReconcileResultV1 {
            source_revision: source,
            target_snapshot: snapshot,
            bundles,
            rollout_states,
            retirement_bundles: Vec::new(),
            retirement_rollout_states: Vec::new(),
            status,
        };
        self.state()?.reconciled.insert(
            result.source_revision.policy_source_revision_id.clone(),
            result.clone(),
        );
        Ok(result)
    }

    fn reconcile_accepted_target_set(
        &self,
        source: PolicySourceRevisionV1,
        policy: &PolicyDocumentV1,
        targets: Vec<PolicyTargetV1>,
        stored_artifact: ProfileCandidateArtifactV1,
        now_utc_ns: i64,
    ) -> Result<PolicyReconcileResultV1> {
        let previous_snapshot = self
            .store
            .latest_snapshot_for_source(&source.policy_source_revision_id)?;
        let targets_changed = previous_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.targets != targets);
        // A target-only replacement needs a newer signed artifact for node anti-rollback.
        let refreshed_active_artifact = (targets_changed && !targets.is_empty())
            .then(|| self.compile_artifact_after(policy, None))
            .transpose()?;
        let active_artifact = refreshed_active_artifact
            .as_ref()
            .unwrap_or(&stored_artifact);
        let active_digest = sha256(&serde_json::to_vec(active_artifact).map_err(|error| {
            PolicyValidationSnafu {
                policy_id: policy.profile_id(),
                code: "CFG_POLICY_ARTIFACT",
                reason: format!("the signed profile artifact cannot be encoded: {error}"),
            }
            .build()
        })?);
        let desired_snapshot = PolicyTargetSnapshotV1::new(
            source.policy_source_revision_id.clone(),
            active_digest,
            policy.rollout.rollout_generation,
            targets,
        )?;
        let desired_is_current = previous_snapshot.as_ref() == Some(&desired_snapshot);
        let (desired_bundles, desired_states) = if desired_is_current {
            (
                self.store
                    .bundles_for_snapshot(&desired_snapshot.target_snapshot_digest)?,
                self.store
                    .rollout_states_for_snapshot(&desired_snapshot.target_snapshot_digest)?,
            )
        } else {
            self.rollout.build(
                &source,
                &desired_snapshot,
                active_artifact,
                &self.signing_key.verifying_key().to_bytes(),
                now_utc_ns,
            )?
        };

        if !desired_is_current {
            self.store.reconcile_target_set(
                desired_snapshot.clone(),
                desired_bundles.clone(),
                desired_states.clone(),
                refreshed_active_artifact,
            )?;
        }

        let status = status_for(&source, &desired_states, None, now_utc_ns);
        let result = PolicyReconcileResultV1 {
            source_revision: source,
            target_snapshot: desired_snapshot,
            bundles: desired_bundles,
            rollout_states: desired_states,
            retirement_bundles: Vec::new(),
            retirement_rollout_states: Vec::new(),
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
    pub fn tenant_id(&self) -> &str {
        &self.config.tenant_id
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
            // One writer serializes policy and exception store transitions.
            reconcile_queue_limit: RECONCILE_WRITER_LIMIT,
            configured_watches: DESIRED_STATE_WATCH_COUNT,
            connected_watches: count(state.connected_watches.len()),
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

    pub(super) fn record_relist(&self, succeeded: bool) {
        if let Ok(mut state) = self.state.lock() {
            if succeeded {
                state.successful_relists = state.successful_relists.saturating_add(1);
            } else {
                state.failed_relists = state.failed_relists.saturating_add(1);
            }
        }
    }

    pub(super) fn record_watch_state(&self, watch: &str, connected: bool) {
        if let Ok(mut state) = self.state.lock() {
            if connected {
                state.connected_watches.insert(watch.to_owned());
            } else {
                state.connected_watches.remove(watch);
            }
        }
    }

    pub(super) fn record_watch_failure(&self) {
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
                super::reconcile_exception_cluster(
                    client.clone(),
                    self.clone(),
                    control.clone(),
                ),
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
        let result = self.build(source, &snapshot, &artifact, &public_key, now_utc_ns)?;
        self.store
            .create_rollout(snapshot, result.0.clone(), result.1.clone())?;
        Ok(result)
    }

    fn build(
        &self,
        source: &PolicySourceRevisionV1,
        snapshot: &PolicyTargetSnapshotV1,
        artifact: &ProfileCandidateArtifactV1,
        public_key: &[u8],
        now_utc_ns: i64,
    ) -> Result<(Vec<PolicyBundleV1>, Vec<PolicyRolloutStateV1>)> {
        let mut bundles = Vec::with_capacity(snapshot.targets.len());
        let mut rollout_states = Vec::with_capacity(snapshot.targets.len());
        let valid_until_utc_ns = now_utc_ns
            .checked_add(self.candidate_validity_ns)
            .ok_or_else(|| {
                PolicyValidationSnafu {
                    policy_id: &source.policy_source_revision_id,
                    code: "CFG_POLICY_CANDIDATE_VALIDITY",
                    reason: "the candidate validity interval exceeds the signed time range"
                        .to_owned(),
                }
                .build()
            })?;
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
                .latest_open_bundle_for_profile_node(
                    &target.node_id,
                    &source.tenant_id,
                    &artifact.policy_document.metadata.trust_domain_id,
                    &artifact.policy_document.metadata.profile_id,
                )?
                .map(|bundle| bundle.candidate.candidate_content_id);
            let operation = if predecessor.is_some() {
                PolicyDeliveryOperationV1::Replace
            } else {
                PolicyDeliveryOperationV1::Activate
            };
            let candidate = PolicyDeliveryCandidateV1::sign(
                source.tenant_id.clone(),
                source.policy_source_revision_id.clone(),
                snapshot.signed_profile_digest.clone(),
                snapshot,
                target.clone(),
                operation,
                predecessor,
                self.distribution_sequence_epoch,
                sequence,
                now_utc_ns,
                valid_until_utc_ns,
                self.signing_key_id.to_string(),
                &self.signing_key,
            )?;
            let candidate_id = candidate.candidate_content_id.clone();
            bundles.push(PolicyBundleV1::new(
                candidate,
                artifact.clone(),
                public_key.to_vec(),
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
        Ok((bundles, rollout_states))
    }

    pub fn acknowledge(
        &self,
        acknowledgement: PolicyActivationAcknowledgementV1,
    ) -> Result<PolicyAcknowledgementResultV1> {
        ensure!(
            self.store.current_node_session_matches(
                &acknowledgement.node_id,
                &acknowledgement.node_boot_id,
                acknowledgement.label_epoch,
            )?,
            PolicyValidationSnafu {
                policy_id: &acknowledgement.policy_source_revision_id,
                code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                reason: "the acknowledgement physical node session is stale",
            }
        );
        if let Some((rollout_state, terminal_chain_closure_authorized)) =
            self.store.policy_acknowledgement_result(&acknowledgement)?
        {
            // A retry after response loss returns the exact durable closure decision.
            return Ok(PolicyAcknowledgementResultV1 {
                rollout_state,
                terminal_chain_closure_authorized,
            });
        }
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
        let _bundle = self
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
        // A delayed ACK stays valid while this candidate is in the unsettled desired chain.
        ensure!(
            self.store.candidate_is_current_or_unsettled_predecessor(
                &acknowledgement.node_id,
                &acknowledgement.candidate_content_id,
            )?,
            PolicyValidationSnafu {
                policy_id: &acknowledgement.policy_source_revision_id,
                code: "CFG_STALE_POLICY_ACKNOWLEDGEMENT",
                reason: "an active successor already owns this profile and node target",
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
        let transition_version = current.transition_version.checked_add(1).ok_or_else(|| {
            PolicyValidationSnafu {
                policy_id: &acknowledgement.policy_source_revision_id,
                code: "CFG_POLICY_TRANSITION_EXHAUSTED",
                reason: "the rollout transition version is exhausted".to_owned(),
            }
            .build()
        })?;
        let next = PolicyRolloutStateV1 {
            state,
            latest_acknowledgement_content_id: Some(
                acknowledgement.acknowledgement_content_id.clone(),
            ),
            transition_version,
            updated_utc_ns: acknowledgement.observed_utc_ns,
            ..current
        };
        let (rollout_state, terminal_chain_closure_authorized) =
            self.store.acknowledge_policy(acknowledgement, next)?;
        Ok(PolicyAcknowledgementResultV1 {
            rollout_state,
            terminal_chain_closure_authorized,
        })
    }
}

async fn reconcile_cluster(
    client: Client,
    owner: PolicyDesiredStateOwner,
    control: crate::ControlPlane,
) {
    let api = Api::<WorkloadProtectionPolicy>::all(client.clone());
    let namespaces = Api::<Namespace>::all(client.clone());
    // Each watch starts from a complete relist cursor and restarts after any stream error.
    loop {
        owner.record_watch_state("policies/*", false);
        let Some(resource_version) =
            relist_cluster(&client, &api, &namespaces, &owner, &control).await
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
        owner.record_watch_state("policies/*", true);
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(WatchEvent::Added(resource) | WatchEvent::Modified(resource)) => {
                    reconcile_resource(&client, &namespaces, &owner, &control, resource, false)
                        .await;
                }
                Ok(WatchEvent::Deleted(resource)) => {
                    reconcile_resource(&client, &namespaces, &owner, &control, resource, true)
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

async fn relist_cluster(
    client: &Client,
    api: &Api<WorkloadProtectionPolicy>,
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
            reconcile_resource(client, namespaces, owner, control, resource, false).await;
        }
        resource_version = page.metadata.resource_version.or(resource_version);
        continuation = match super::kubernetes::next_continuation_token(
            continuation.as_deref(),
            page.metadata.continue_,
            "WorkloadProtectionPolicy",
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
    // Retire missing sources before the watch begins, or discard the snapshot as incomplete.
    let complete = resource_version.is_some()
        && owner
            .retire_missing_sources(
                &seen_object_uids,
                &control.kubernetes_workload_inventory(),
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
    client: &Client,
    namespaces: &Api<Namespace>,
    owner: &PolicyDesiredStateOwner,
    control: &crate::ControlPlane,
    resource: WorkloadProtectionPolicy,
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
    let mut status = match owner.reconcile_observation(
        &resource,
        namespace_uid.as_deref().unwrap_or_default(),
        &control.kubernetes_workload_inventory(),
        utc_now_ns(),
        source_state,
    ) {
        Ok(result) => result.status,
        Err(error) => {
            warn!(
                "rejected workload protection policy reconciliation",
                error = %error,
                namespace = %namespace_name,
                policy = %name,
                generation = %generation
            );
            rejected_status(generation)
        }
    };
    if let Some(previous) = resource.status.as_ref() {
        preserve_transition_times(&mut status.conditions, &previous.conditions);
        if previous == &status {
            return;
        }
    }
    info!(
        "changed workload protection policy status",
        namespace = %namespace_name,
        policy = %name,
        generation = %generation,
        desired_targets = %status.rollout.desired,
        active_targets = %status.rollout.active
    );
    if patch_policy_status(client, namespace_name, &name, &status)
        .await
        .is_err()
    {
        owner.record_watch_failure();
    }
}

async fn patch_policy_status(
    client: &Client,
    namespace: &str,
    name: &str,
    status: &WorkloadProtectionPolicyStatusV1,
) -> std::result::Result<(), kube::Error> {
    let api = Api::<WorkloadProtectionPolicy>::namespaced(client.clone(), namespace);
    let patch = Patch::Merge(serde_json::json!({"status": status}));
    api.patch_status(name, &PatchParams::default(), &patch)
        .await
        .map(|_| ())
}

fn rejected_status(generation: u64) -> WorkloadProtectionPolicyStatusV1 {
    WorkloadProtectionPolicyStatusV1 {
        observed_generation: generation,
        rollout: PolicyRolloutCountsV1::default(),
        conditions: vec![kubernetes_condition(
            "Accepted",
            false,
            generation,
            "ReconcileRejected",
            "Control rejected the stored policy source.",
            utc_now_ns(),
        )],
    }
}

pub(super) fn utc_now_ns() -> i64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

pub(super) fn preserve_transition_times(
    next: &mut [super::KubernetesConditionV1],
    previous: &[super::KubernetesConditionV1],
) {
    for condition in next {
        if let Some(prior) = previous.iter().find(|prior| {
            prior.condition_type == condition.condition_type
                && prior.status == condition.status
                && prior.observed_generation == condition.observed_generation
                && prior.reason == condition.reason
                && prior.message == condition.message
        }) {
            condition.last_transition_time = prior.last_transition_time.clone();
        }
    }
}

/// Rebuilds terminal policy bytes for legacy WAL validation only.
pub(crate) fn restrictive_terminal_document(policy: &PolicyDocumentV1) -> PolicyDocumentV1 {
    let mut terminal = policy.clone();
    terminal.file_exception_grants.clear();
    terminal.exceptions.clear();
    for floor in &mut terminal.path_tree_deny_floors {
        floor.requested_disposition = PolicyDispositionV1::Deny;
        floor.exception_ids.clear();
    }
    for transition in &mut terminal.native_transition_rules {
        transition.requested_disposition = PolicyDispositionV1::Deny;
        transition.errno = Some(ErrnoV1::Eperm);
    }
    for relationship in &mut terminal.ipc_relationship_rules {
        relationship.requested_disposition = PolicyDispositionV1::Deny;
        relationship.errno = Some(ErrnoV1::Eperm);
    }
    terminal.unmatched_ipc_disposition = PolicyDispositionV1::Deny;
    for default in &mut terminal.effect_family_defaults {
        default.requested_disposition = PolicyDispositionV1::Deny;
        default.errno = Some(ErrnoV1::Eperm);
    }
    for posture in [
        &mut terminal.default_postures.missing_task_identity,
        &mut terminal.default_postures.required_classifier_unknown,
        &mut terminal.default_postures.unresolved_or_external_root,
    ] {
        posture.requested_disposition = PolicyDispositionV1::Deny;
    }
    for rule in &mut terminal.rules {
        rule.exception_ids.clear();
        rule.response_binding_ids.clear();
        match rule.evaluation_stage {
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => {
                rule.requested_disposition = PolicyDispositionV1::Reject;
                rule.errno = None;
            }
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => {
                rule.requested_disposition = PolicyDispositionV1::Deny;
                rule.errno = Some(ErrnoV1::Eperm);
            }
            EvaluationStageV1::PostEffect => {
                // A terminal profile does not need post-effect audit cells after prevention closes.
                rule.enabled = false;
                rule.requested_disposition = PolicyDispositionV1::Alert;
                rule.errno = None;
            }
        }
        for fallback in &mut rule.fallback_by_condition {
            match rule.evaluation_stage {
                EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => {
                    fallback.requested_disposition = PolicyDispositionV1::Reject;
                    fallback.errno = None;
                }
                EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => {
                    fallback.requested_disposition = PolicyDispositionV1::Deny;
                    fallback.errno = Some(ErrnoV1::Eperm);
                }
                EvaluationStageV1::PostEffect => {}
            }
        }
    }
    terminal
}

fn resolve_targets(
    source: &PolicySourceRevisionV1,
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
        let has_current_kubernetes_provenance = fact.kubernetes.as_ref().is_some_and(|identity| {
            identity.namespace_name == source.namespace_name
                && !identity.pod_name.is_empty()
                && identity.profile_id == policy.profile_id()
                // A live Pod keeps the source revision that admission bound. Later policy
                // generations still target that same API-observed Pod and profile.
                && valid_sha256(&identity.policy_source_revision_id)
                && canonical_uuid(&identity.binding_id)
                && policy
                    .protected_universe
                    .protected_scope_ids
                    .contains(&identity.protected_scope_id)
                && selector_ids.contains(identity.workload_selector_id.as_str())
                && !identity.kubernetes_node_name.is_empty()
                && canonical_uuid(&identity.kubernetes_node_uid)
                && identity.node_boot_id.len() == 32
                && identity
                    .node_boot_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && identity.label_epoch > 0
                && fact.cluster_uid == source.cluster_uid
                && fact.namespace_uid == source.namespace_uid
                && workload_target_fact_digest(fact)
                    .is_ok_and(|digest| digest == fact.workload_binding_generation_digest)
        });
        if matches_selector
            && has_current_kubernetes_provenance
            && selected_by_rollout(policy, fact)
        {
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
    states: &[PolicyRolloutStateV1],
    degraded_reason: Option<&str>,
    now_utc_ns: i64,
) -> WorkloadProtectionPolicyStatusV1 {
    // Status summarizes durable per-target state. It never grants rollout authority.
    let counts = PolicyRolloutCountsV1::from_states(states);
    let retiring = source.state == PolicySourceStateV1::DeletionRequested;
    let available = counts.active == counts.total() && (!retiring || counts.total() > 0);
    let degraded = degraded_reason.is_some() || counts.failed > 0;
    let progressing = !available && !retiring;
    let condition = |condition, status, reason, message| {
        kubernetes_condition(
            condition,
            status,
            source.object_generation,
            reason,
            message,
            now_utc_ns,
        )
    };
    WorkloadProtectionPolicyStatusV1 {
        observed_generation: source.object_generation,
        rollout: counts,
        conditions: vec![
            condition(
                "Accepted",
                true,
                "SourceAccepted",
                "Control accepted the stored policy source.",
            ),
            condition(
                "Compiled",
                true,
                "PolicyCompiled",
                "Control compiled and signed the policy source.",
            ),
            condition(
                "Progressing",
                progressing,
                "RolloutPending",
                "One or more current or retiring targets have not reached the desired state.",
            ),
            condition(
                "Available",
                available,
                "AllTargetsActive",
                "All current targets are active and no retirement is pending.",
            ),
            condition(
                "Degraded",
                degraded,
                degraded_reason.unwrap_or("NoDegradedTarget"),
                "One or more current or retiring targets rejected or lost the desired state.",
            ),
            condition(
                "Retiring",
                retiring,
                "DeletionRequested",
                "Control is replacing the deleted policy with restrictive state.",
            ),
        ],
    }
}

pub(super) fn kubernetes_condition(
    condition_type: &str,
    status: bool,
    observed_generation: u64,
    reason: &str,
    message: &str,
    now_utc_ns: i64,
) -> super::KubernetesConditionV1 {
    let timestamp = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_utc_ns))
        .ok()
        .and_then(|time| {
            time.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
    super::KubernetesConditionV1 {
        condition_type: condition_type.to_owned(),
        status: if status {
            super::KubernetesConditionStatusV1::True
        } else {
            super::KubernetesConditionStatusV1::False
        },
        observed_generation,
        last_transition_time: timestamp,
        reason: reason.to_owned(),
        message: message.to_owned(),
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, HeaderValue, Request, Response, StatusCode};
    use kube::client::Body as KubeBody;
    use kube::Client;
    use serde_json::json;
    use tokio::sync::Mutex;
    use tower::service_fn;

    use super::{
        kubernetes_condition, patch_policy_status, preserve_transition_times, rejected_status,
    };

    #[tokio::test]
    async fn rejected_policy_status_uses_its_namespace_subresource(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let service_requests = requests.clone();
        let service = service_fn(move |request: Request<KubeBody>| {
            let service_requests = service_requests.clone();
            async move {
                service_requests
                    .lock()
                    .await
                    .push(request.uri().to_string());
                let value = json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "NotFound",
                    "code": 404
                });
                let mut response = Response::new(Body::from(value.to_string()));
                *response.status_mut() = StatusCode::NOT_FOUND;
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        let client = Client::new(service, "default");

        assert!(
            patch_policy_status(&client, "tenant-a", "policy-a", &rejected_status(7))
                .await
                .is_err()
        );
        assert_eq!(
            requests.lock().await.as_slice(),
            ["/apis/mithril.erebor.dev/v1alpha1/namespaces/tenant-a/workloadprotectionpolicies/policy-a/status?"]
        );
        Ok(())
    }

    #[test]
    fn unchanged_condition_keeps_its_transition_time() {
        let previous = vec![kubernetes_condition(
            "Accepted",
            true,
            4,
            "SourceAccepted",
            "Control accepted the stored policy source.",
            1_800_000_000_000_000_000,
        )];
        let mut next = vec![kubernetes_condition(
            "Accepted",
            true,
            4,
            "SourceAccepted",
            "Control accepted the stored policy source.",
            1_800_000_001_000_000_000,
        )];

        preserve_transition_times(&mut next, &previous);

        assert_eq!(next, previous);
    }
}
