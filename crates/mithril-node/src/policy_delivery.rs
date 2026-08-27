use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::EXCEPTION_USE_RECEIPT_CAPACITY;
use erebor_interceptor_abi::{
    ExceptionBindingStateV1, ExceptionHandleBindingKeyV1, ExceptionHandleBindingV1,
    ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateKindV1, ExceptionRuntimeStateV1,
};
use mithril_control::{
    CapabilityRecord, EntryKindV1, ExceptionActivationAcknowledgement, ExceptionActivationStateV1,
    ExceptionDeliveryCandidateV1, ExceptionDeliveryOperationV1, ExceptionInventory,
    PolicyAcknowledgementAccepted, PolicyActivationAcknowledgement, PolicyBundleV1, PolicyChunk,
    PolicyDeliveryOperationV1, PolicyInventory, MAX_EXCEPTION_CANDIDATE_BYTES,
    MAX_POLICY_BUNDLE_BYTES, MAX_POLICY_BUNDLE_CHUNK_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use crate::error::{
    ControlProtocolSnafu, IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu, PolicySnafu,
};
use crate::{NodeConfig, PolicyCandidateConfig, Result, TrustCache, WorkloadBindingConfig};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
// This file is the durable recovery and anti-replay state for node policy delivery.
struct PolicyDeliveryStateV1 {
    active_candidate_content_id: Option<String>,
    active_bundle_digest: Option<String>,
    active_profiles: BTreeMap<String, ActivePolicyRecordV1>,
    #[serde(default)]
    // This index keeps a retired base bundle available for later exception revocation.
    policy_candidate_bundles: BTreeMap<String, String>,
    pending_activation: Option<PendingPolicyRecordV1>,
    issuer_high_water: BTreeMap<String, SequenceV1>,
    distribution_high_water: BTreeMap<String, SequenceV1>,
    control_acknowledged_candidate_content_id: Option<String>,
    #[serde(default)]
    #[serde(alias = "terminal_cleanup_authorization")]
    inventory_retirement: Option<InventoryPolicyRetirementV1>,
    #[serde(default)]
    // One durable record per Kubernetes exception UID owns replay and ACK progress.
    exception_records: BTreeMap<String, ExceptionDeliveryRecordV1>,
    #[serde(default)]
    exception_distribution_high_water: BTreeMap<String, SequenceV1>,
}

const MAX_ACTIVE_POLICY_PROFILES: usize = 256;
const MAX_INSPECTED_POLICY_TARGETS: usize = 256;

pub(crate) struct RuntimeBindingRollbackV1 {
    previous: PolicyDeliveryStateV1,
    profile_id: String,
    authority_binding_id: String,
    runtime_binding_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SequenceV1 {
    epoch: u64,
    sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivePolicyRecordV1 {
    tenant_id: String,
    candidate_content_id: String,
    policy_source_revision_id: String,
    target_snapshot_digest: String,
    bundle_digest: String,
    artifact_file: String,
    public_key_file: String,
    profile_generation_ref_id: u64,
    #[serde(default)]
    staged_utc_ns: i64,
    binding_ids: Vec<String>,
    #[serde(default)]
    scheduled_bindings: Vec<WorkloadBindingConfig>,
    node_bound_generation_digest: String,
    readback_digest: String,
    probe_result_digest: String,
    observed_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
// Pending state is durable before kernel activation and becomes active after readback proof.
struct PendingPolicyRecordV1 {
    #[serde(default)]
    tenant_id: String,
    candidate_content_id: String,
    #[serde(default)]
    policy_source_revision_id: String,
    #[serde(default)]
    target_snapshot_digest: String,
    bundle_digest: String,
    profile_id: String,
    artifact_file: String,
    public_key_file: String,
    bundle_file: String,
    profile_generation_ref_id: u64,
    #[serde(default)]
    staged_utc_ns: i64,
    binding_ids: Vec<String>,
    #[serde(default)]
    scheduled_bindings: Vec<WorkloadBindingConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryPolicyRetirementV1 {
    pub candidate_content_id: String,
    pub profile_id: String,
    pub bundle_digest: String,
    pub profile_generation_ref_id: u64,
    pub binding_ids: Vec<String>,
    #[serde(default, rename = "control_commit_index")]
    legacy_control_commit_index: u64,
    #[serde(default)]
    delivery_state_retired: bool,
}

pub(crate) struct StartupAuthorityAbsenceV1 {
    pub policy_authority_absent: bool,
    pub exception_authority_absent: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LocalExceptionStateV1 {
    Pending,
    Active,
    Consumed,
    Expired,
    Revoked,
    Rejected,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingExceptionPhysicalV1 {
    Absent,
    Active { consumed_uses: u32 },
    Consumed { consumed_uses: u32 },
    Expired { consumed_uses: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExceptionDeliveryRecordV1 {
    #[serde(default)]
    tenant_id: String,
    candidate_content_id: String,
    #[serde(default)]
    exception_source_revision_id: String,
    candidate_file: String,
    operation: ExceptionDeliveryOperationV1,
    #[serde(default)]
    profile_generation_ref_id: u64,
    #[serde(default)]
    grant_handle: u32,
    #[serde(default)]
    valid_until_utc_ns: i64,
    state: LocalExceptionStateV1,
    consumed_uses: u32,
    transition_version: u64,
    observed_utc_ns: i64,
    control_acknowledged: bool,
    #[serde(default = "default_true")]
    report_to_control: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferStateV1 {
    candidate_content_id: String,
    bundle_digest: String,
    bundle_bytes: u64,
    chunk_count: u32,
    chunk_digests: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyDeliveryStatusV1 {
    pub active_candidate_content_id: Option<String>,
    pub active_profile_ids: Vec<String>,
    pub active_target_count: usize,
    pub active_targets_truncated: bool,
    pub active_targets: Vec<PolicyDeliveryTargetStatusV1>,
    pub scheduled_binding_count: usize,
    pub runtime_binding_count: usize,
    pub activation_pending: bool,
    pub control_acknowledged: bool,
    pub pending_exception_count: usize,
    pub active_exception_count: usize,
    pub terminal_exception_count: usize,
    pub consumed_exception_count: usize,
    pub expired_exception_count: usize,
    pub revoked_exception_count: usize,
    pub exception_ack_pending_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Projects one signed Kubernetes target and its current runtime lifetime.
pub struct PolicyDeliveryTargetStatusV1 {
    pub profile_id: String,
    pub candidate_content_id: String,
    // These fields distinguish a fresh root from a replayed predecessor chain.
    pub operation: PolicyDeliveryOperationV1,
    pub predecessor_candidate_content_id: Option<String>,
    pub policy_source_revision_id: String,
    pub workload_binding_generation_digest: String,
    pub node_id: String,
    pub kubernetes_node_name: String,
    pub kubernetes_node_uid: String,
    pub node_boot_id: String,
    pub label_epoch: u64,
    pub namespace_name: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub image_digest: String,
    pub runtime_container_id: Option<String>,
    pub runtime_binding_id: Option<String>,
    pub container_generation: Option<u64>,
}

pub(crate) struct PreparedPolicyActivationV1 {
    pub config: NodeConfig,
    pub profile_id: String,
    pub binding_ids: Vec<String>,
    pub profile_generation_ref_id: u64,
    staged_utc_ns: i64,
}

pub(crate) struct PolicyActivationProofV1 {
    pub node_bound_generation_digest: String,
    pub readback_digest: String,
    pub probe_result_digest: String,
    pub observed_utc_ns: i64,
}

pub(crate) struct PreparedExceptionDeliveryV1 {
    pub candidate: ExceptionDeliveryCandidateV1,
    pub grant_handle: u32,
}

pub(crate) enum PolicyTransferActionV1 {
    Inventory {
        active_candidate_content_id: Option<String>,
        durable_bundle_digests: Vec<String>,
    },
    Fetch {
        candidate_content_id: String,
        bundle_digest: String,
        chunk_index: u32,
    },
    Ready(Box<PolicyBundleV1>),
}

pub(crate) struct NodePolicyDeliveryOwner {
    root: PathBuf,
    state_path: PathBuf,
    transfer_path: PathBuf,
    state: PolicyDeliveryStateV1,
    session_inventory: Option<PolicyInventory>,
}

impl NodePolicyDeliveryOwner {
    pub(crate) fn load(state_directory: &Path) -> Result<Self> {
        let root = state_directory.join("policy-delivery-v1");
        let state_path = root.join("state.json");
        let transfer_path = root.join("transfer.json");
        fs::create_dir_all(root.join("bundles")).context(IoSnafu { path: &root })?;
        fs::create_dir_all(root.join("transfers")).context(IoSnafu { path: &root })?;
        fs::create_dir_all(root.join("exceptions")).context(IoSnafu { path: &root })?;
        let state = match fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context(JsonSnafu { path: &state_path })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PolicyDeliveryStateV1::default()
            }
            Err(source) => {
                return Err(crate::Error::Io {
                    path: state_path,
                    source,
                    location: snafu::Location::default(),
                });
            }
        };
        let mut owner = Self {
            root,
            state_path,
            transfer_path,
            state,
            session_inventory: None,
        };
        owner.hydrate_exception_ack_identities()?;
        // Invalid recovery state blocks policy delivery instead of dropping replay history.
        owner.validate_state()?;
        Ok(owner)
    }

    fn hydrate_exception_ack_identities(&mut self) -> Result<()> {
        // Pending legacy identity is filled only after the candidate passes current verification.
        let legacy = self
            .state
            .exception_records
            .iter()
            .filter(|(_, record)| {
                record.state != LocalExceptionStateV1::Pending
                    && (record.tenant_id.is_empty()
                        || record.exception_source_revision_id.is_empty())
            })
            .map(|(instance_id, record)| (instance_id.clone(), record.clone()))
            .collect::<Vec<_>>();
        let mut changed = false;
        for (instance_id, record) in legacy {
            let candidate = self.read_exception_candidate(&record)?;
            let stored =
                self.state
                    .exception_records
                    .get_mut(&instance_id)
                    .context(IdentityStateSnafu {
                        reason: "the legacy exception record disappeared during recovery",
                    })?;
            stored.tenant_id = candidate.tenant_id;
            stored.exception_source_revision_id = candidate.exception_source_revision_id;
            changed = true;
        }
        if changed {
            self.persist_state()?;
        }
        Ok(())
    }

    fn status(&self) -> PolicyDeliveryStatusV1 {
        let bindings = self
            .state
            .active_profiles
            .values()
            .flat_map(|profile| &profile.scheduled_bindings)
            .collect::<Vec<_>>();
        // A scheduled identity is a signed placeholder. Runtime admission
        // replaces it with the physical container identity before start.
        PolicyDeliveryStatusV1 {
            active_candidate_content_id: self.state.active_candidate_content_id.clone(),
            active_profile_ids: self.state.active_profiles.keys().cloned().collect(),
            active_target_count: 0,
            active_targets_truncated: false,
            active_targets: Vec::new(),
            scheduled_binding_count: bindings
                .iter()
                .filter(|binding| binding.container_id.starts_with("scheduled:"))
                .count(),
            runtime_binding_count: bindings
                .iter()
                .filter(|binding| !binding.container_id.starts_with("scheduled:"))
                .count(),
            activation_pending: self.state.pending_activation.is_some(),
            control_acknowledged: self.state.active_candidate_content_id.is_some()
                && self.state.active_candidate_content_id
                    == self.state.control_acknowledged_candidate_content_id,
            pending_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Pending)
                .count(),
            active_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Active)
                .count(),
            // Terminal records stay durable so deletion and recreation cannot refund uses.
            terminal_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| {
                    matches!(
                        record.state,
                        LocalExceptionStateV1::Consumed
                            | LocalExceptionStateV1::Expired
                            | LocalExceptionStateV1::Revoked
                            | LocalExceptionStateV1::Rejected
                            | LocalExceptionStateV1::Stale
                    )
                })
                .count(),
            consumed_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Consumed)
                .count(),
            expired_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Expired)
                .count(),
            revoked_exception_count: self
                .state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Revoked)
                .count(),
            exception_ack_pending_count: self
                .state
                .exception_records
                .values()
                .filter(|record| {
                    record.state != LocalExceptionStateV1::Pending
                        && !record.control_acknowledged
                        && record.report_to_control
                })
                .count(),
        }
    }

    fn inspection_status(&self) -> Result<PolicyDeliveryStatusV1> {
        let mut status = self.status();
        let mut targets = Vec::new();
        for (profile_id, record) in &self.state.active_profiles {
            let bundle_path = self
                .root
                .join("bundles")
                .join(&record.bundle_digest)
                .join("bundle.json");
            let bundle = self.read_bundle(&bundle_path)?;
            let canonical_bundle = PolicyBundleV1::new(
                bundle.candidate.clone(),
                bundle.profile_artifact.clone(),
                bundle.profile_signing_public_key.clone(),
            )
            .context(PolicySnafu)?;
            ensure!(
                canonical_bundle == bundle
                    && bundle.bundle_digest == record.bundle_digest
                    && bundle.candidate.candidate_content_id == record.candidate_content_id
                    && bundle.candidate.policy_source_revision_id
                        == record.policy_source_revision_id
                    && bundle.profile_artifact.header.profile_id == *profile_id,
                IdentityStateSnafu {
                    reason: "the active policy record differs from its signed bundle",
                }
            );
            for target in &bundle.candidate.exact_target.workload_targets {
                let identity = target.kubernetes.as_ref().context(IdentityStateSnafu {
                    reason: "an inspected scheduled target has no Kubernetes identity",
                })?;
                let binding = record
                    .scheduled_bindings
                    .iter()
                    .find(|binding| {
                        binding.scheduled_target_digest.as_deref()
                            == Some(target.workload_binding_generation_digest.as_str())
                    })
                    .context(IdentityStateSnafu {
                        reason: "an inspected scheduled target has no node binding",
                    })?;
                let runtime_bound = !binding.container_id.starts_with("scheduled:");
                targets.push(PolicyDeliveryTargetStatusV1 {
                    profile_id: profile_id.clone(),
                    candidate_content_id: record.candidate_content_id.clone(),
                    operation: bundle.candidate.operation,
                    predecessor_candidate_content_id: bundle
                        .candidate
                        .predecessor_candidate_content_id
                        .clone(),
                    policy_source_revision_id: record.policy_source_revision_id.clone(),
                    workload_binding_generation_digest: target
                        .workload_binding_generation_digest
                        .clone(),
                    node_id: target.node_id.clone(),
                    kubernetes_node_name: identity.kubernetes_node_name.clone(),
                    kubernetes_node_uid: identity.kubernetes_node_uid.clone(),
                    node_boot_id: identity.node_boot_id.clone(),
                    label_epoch: identity.label_epoch,
                    namespace_name: identity.namespace_name.clone(),
                    pod_name: identity.pod_name.clone(),
                    pod_uid: target.pod_uid.clone(),
                    container_name: target.container_name.clone(),
                    image_digest: target.image_digest.clone(),
                    runtime_container_id: runtime_bound.then(|| binding.container_id.clone()),
                    runtime_binding_id: runtime_bound.then(|| binding.binding_id.clone()),
                    container_generation: runtime_bound.then_some(binding.container_generation),
                });
            }
        }
        targets.sort_by(|left, right| {
            (
                &left.profile_id,
                &left.candidate_content_id,
                &left.workload_binding_generation_digest,
            )
                .cmp(&(
                    &right.profile_id,
                    &right.candidate_content_id,
                    &right.workload_binding_generation_digest,
                ))
        });
        status.active_target_count = targets.len();
        status.active_targets_truncated = targets.len() > MAX_INSPECTED_POLICY_TARGETS;
        targets.truncate(MAX_INSPECTED_POLICY_TARGETS);
        status.active_targets = targets;
        Ok(status)
    }

    #[cfg(test)]
    pub(crate) fn restore_config(
        &mut self,
        config: &mut NodeConfig,
        trust: &TrustCache,
    ) -> Result<()> {
        self.restore_config_inner(config, trust, None)
    }

    pub(crate) fn restore_config_for_session(
        &mut self,
        config: &mut NodeConfig,
        trust: &TrustCache,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<()> {
        self.restore_config_inner(config, trust, Some((node_boot_id, label_epoch)))
    }

    fn restore_config_inner(
        &mut self,
        config: &mut NodeConfig,
        trust: &TrustCache,
        session: Option<(&[u8], u64)>,
    ) -> Result<()> {
        self.omit_inventory_retirement_from_config(config)?;
        // Rebuild dynamic config only from durable bundles that still pass current trust checks.
        let active_profiles = self.state.active_profiles.clone();
        for (profile_id, record) in &active_profiles {
            let artifact_path = self.checked_bundle_file(&record.artifact_file)?;
            let public_key_path = self.checked_bundle_file(&record.public_key_file)?;
            ensure!(
                artifact_path.is_file() && public_key_path.is_file(),
                IdentityStateSnafu {
                    reason: "the active policy cache has a missing artifact or public key",
                }
            );
            let bundle_path = self
                .root
                .join("bundles")
                .join(&record.bundle_digest)
                .join("bundle.json");
            let bundle = self.read_bundle(&bundle_path)?;
            let trusted_key = trust.policy_signing_key(
                &bundle.candidate.signing_key_id,
                bundle.profile_artifact.header.sequence_epoch,
            )?;
            bundle
                .verify(
                    &trusted_key,
                    &config.node_id,
                    if record.staged_utc_ns == 0 {
                        bundle.candidate.issued_utc_ns
                    } else {
                        record.staged_utc_ns
                    },
                )
                .context(PolicySnafu)?;
            if self
                .state
                .inventory_retirement
                .as_ref()
                .is_some_and(|cleanup| cleanup.profile_id == *profile_id)
            {
                continue;
            }
            let scheduled_session = scheduled_session_state(&bundle, config, session)?;
            if scheduled_session == Some(false) {
                ensure!(
                    scheduled_record_is_exclusive(&record.binding_ids, &record.scheduled_bindings,),
                    IdentityStateSnafu {
                        reason: "an old-session active policy mixes scheduled and static ownership",
                    }
                );
                continue;
            }
            self.replace_profile_candidate(config, profile_id, artifact_path, public_key_path)?;
            // Scheduled authority does not survive a node boot or label-epoch change.
            if scheduled_session == Some(true) {
                config
                    .workload_bindings
                    .extend(record.scheduled_bindings.clone());
                materialize_scheduled_bindings(
                    &bundle,
                    config,
                    record.profile_generation_ref_id,
                    session,
                )?;
            }
            let binding_ids = record.binding_ids.iter().collect::<BTreeSet<_>>();
            for binding in &mut config.workload_bindings {
                if binding.profile_id == *profile_id && binding_ids.contains(&binding.binding_id) {
                    binding.active_profile_generation_ref_id = record.profile_generation_ref_id;
                }
            }
        }
        if let Some(pending) = self.state.pending_activation.clone() {
            let recovered: Result<(PathBuf, PathBuf, PolicyBundleV1)> = (|| {
                let artifact_path = self.checked_bundle_file(&pending.artifact_file)?;
                let public_key_path = self.checked_bundle_file(&pending.public_key_file)?;
                let bundle_path = self.checked_bundle_file(&pending.bundle_file)?;
                ensure!(
                    artifact_path.is_file() && public_key_path.is_file() && bundle_path.is_file(),
                    IdentityStateSnafu {
                        reason: "the pending policy cache has a missing artifact, key, or bundle",
                    }
                );
                let bundle = self.read_bundle(&bundle_path)?;
                Ok((artifact_path, public_key_path, bundle))
            })();
            let (artifact_path, public_key_path, bundle) = recovered?;
            self.verify_pending_bundle(&pending, &bundle, trust, config)?;
            self.hydrate_pending_policy_ack_identity(&pending, &bundle)?;
            let scheduled_session = scheduled_session_state(&bundle, config, session)?;
            if scheduled_session == Some(false) {
                ensure!(
                    scheduled_record_is_exclusive(
                        &pending.binding_ids,
                        &pending.scheduled_bindings,
                    ),
                    IdentityStateSnafu {
                        reason:
                            "an old-session pending policy mixes scheduled and static ownership",
                    }
                );
                // Keep durable ownership until post-host readback proves old authority absent.
                return Ok(());
            }
            // The pending successor owns this profile during crash recovery.
            self.replace_profile_candidate(
                config,
                &pending.profile_id,
                artifact_path,
                public_key_path,
            )?;
            if scheduled_session == Some(true) {
                config
                    .workload_bindings
                    .extend(pending.scheduled_bindings.clone());
                materialize_scheduled_bindings(
                    &bundle,
                    config,
                    pending.profile_generation_ref_id,
                    session,
                )?;
            }
            let binding_ids = pending.binding_ids.iter().collect::<BTreeSet<_>>();
            for binding in &mut config.workload_bindings {
                if binding.profile_id == pending.profile_id
                    && binding_ids.contains(&binding.binding_id)
                {
                    binding.active_profile_generation_ref_id = pending.profile_generation_ref_id;
                }
            }
        }
        Ok(())
    }

    fn replace_profile_candidate(
        &self,
        config: &mut NodeConfig,
        profile_id: &str,
        artifact_path: PathBuf,
        public_key_path: PathBuf,
    ) -> Result<()> {
        let previous = if let Some(record) = self.state.active_profiles.get(profile_id) {
            Some((
                self.checked_bundle_file(&record.artifact_file)?,
                self.checked_bundle_file(&record.public_key_file)?,
            ))
        } else {
            None
        };
        for candidate in &config.policy_candidates {
            for (artifact, public_key) in previous
                .iter()
                .map(|(artifact, public_key)| (artifact, public_key))
                .chain(std::iter::once((&artifact_path, &public_key_path)))
            {
                ensure!(
                    (candidate.artifact_path == *artifact)
                        == (candidate.public_key_path == *public_key),
                    IdentityStateSnafu {
                        reason: "a cached policy candidate has a partial bundle identity",
                    }
                );
            }
        }
        config.policy_candidates.retain(|candidate| {
            let is_previous = previous.as_ref().is_some_and(|(artifact, public_key)| {
                candidate.artifact_path == *artifact && candidate.public_key_path == *public_key
            });
            let is_replacement = candidate.artifact_path == artifact_path
                && candidate.public_key_path == public_key_path;
            !is_previous && !is_replacement
        });
        config.policy_candidates.push(PolicyCandidateConfig {
            artifact_path,
            public_key_path,
            rollback_authorization_path: None,
            rollback_public_key_path: None,
        });
        Ok(())
    }

    pub(crate) fn inventory_retirement(&self) -> Option<InventoryPolicyRetirementV1> {
        self.state.inventory_retirement.clone()
    }

    pub(crate) fn startup_authority_absence(
        &self,
        host: &erebor_interceptor::KernelHost,
        config: &NodeConfig,
    ) -> Result<StartupAuthorityAbsenceV1> {
        let node_id = crate::policy::stable_node_id(&config.node_id)?;
        let mut exception_physical_present = false;
        for (instance_id, record) in &self.state.exception_records {
            if matches!(
                record.state,
                LocalExceptionStateV1::Rejected | LocalExceptionStateV1::Stale
            ) {
                continue;
            }
            let runtime_key = ExceptionRuntimeStateKeyV1 {
                node_id,
                exception_instance_id: crate::policy::parse_id(
                    "exception_instance_id",
                    instance_id,
                )?,
            };
            let binding_key = ExceptionHandleBindingKeyV1 {
                profile_generation_ref_id: record.profile_generation_ref_id,
                exception_numeric_handle: record.grant_handle,
                reserved: 0,
            };
            exception_physical_present |= host
                .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                .context(InterceptorSnafu)?
                .is_some()
                || host
                    .lookup_map("exception_handle_bindings", binding_key.as_bytes())
                    .context(InterceptorSnafu)?
                    .is_some();
        }
        Ok(self.startup_authority_absence_from_readback(exception_physical_present))
    }

    fn startup_authority_absence_from_readback(
        &self,
        exception_physical_present: bool,
    ) -> StartupAuthorityAbsenceV1 {
        StartupAuthorityAbsenceV1 {
            policy_authority_absent: self.state.active_profiles.is_empty()
                && self.state.pending_activation.is_none()
                && self.state.inventory_retirement.is_none(),
            exception_authority_absent: !exception_physical_present
                && self.state.exception_records.values().all(|record| {
                    !matches!(
                        record.state,
                        LocalExceptionStateV1::Pending | LocalExceptionStateV1::Active
                    )
                }),
        }
    }

    pub(crate) fn omit_inventory_retirement_from_config(
        &self,
        config: &mut NodeConfig,
    ) -> Result<()> {
        let Some(cleanup) = self.state.inventory_retirement.as_ref() else {
            return Ok(());
        };
        let directory = self.root.join("bundles").join(&cleanup.bundle_digest);
        let artifact = directory.join("profile-artifact.json");
        let public_key = directory.join("profile-public-key.hex");
        ensure!(
            config.policy_candidates.iter().all(|candidate| {
                (candidate.artifact_path == artifact) == (candidate.public_key_path == public_key)
            }),
            IdentityStateSnafu {
                reason: "stale policy retirement found a partial policy cache identity",
            }
        );
        config.policy_candidates.retain(|candidate| {
            candidate.artifact_path != artifact && candidate.public_key_path != public_key
        });
        let binding_ids = cleanup.binding_ids.iter().collect::<BTreeSet<_>>();
        ensure!(
            config.workload_bindings.iter().all(|binding| {
                !binding_ids.contains(&binding.binding_id)
                    || (binding.profile_id == cleanup.profile_id
                        && binding.active_profile_generation_ref_id
                            == cleanup.profile_generation_ref_id)
            }),
            IdentityStateSnafu {
                reason: "stale policy retirement binding identity names another profile generation",
            }
        );
        config.workload_bindings.retain(|binding| {
            !(binding.profile_id == cleanup.profile_id
                && binding.active_profile_generation_ref_id == cleanup.profile_generation_ref_id
                && binding_ids.contains(&binding.binding_id))
        });
        Ok(())
    }

    pub(crate) fn active_candidate_content_id(&self) -> Option<&str> {
        self.state.active_candidate_content_id.as_deref()
    }

    pub(crate) fn durable_bundle_digests(&self) -> Vec<String> {
        self.state
            .active_profiles
            .values()
            .map(|record| record.bundle_digest.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn unacknowledged_exception_candidate_ids(&self) -> Vec<String> {
        self.state
            .exception_records
            .values()
            .filter(|record| !record.control_acknowledged && record.report_to_control)
            .map(|record| record.candidate_content_id.clone())
            .collect()
    }

    pub(crate) fn reconcile_exception_candidate(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<Option<PreparedExceptionDeliveryV1>> {
        let now_utc_ns = crate::policy::current_utc_ns()?;
        if let Some(pending) = self.reconcile_pending_exception(
            host,
            trust,
            config,
            node_boot_id,
            label_epoch,
            now_utc_ns,
        )? {
            // Recovery completes local work before the node asks Control for newer authority.
            return Ok(Some(pending));
        }
        if self.pending_exception_acknowledgement()?.is_some() {
            return Ok(None);
        }
        Ok(None)
    }

    pub(crate) fn exception_inventory_candidate_ids(&self) -> Vec<String> {
        self.unacknowledged_exception_candidate_ids()
    }

    pub(crate) fn accept_exception_inventory(
        &mut self,
        inventory: ExceptionInventory,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<Option<PreparedExceptionDeliveryV1>> {
        let now_utc_ns = crate::policy::current_utc_ns()?;
        self.accept_exception_inventory_at(
            inventory,
            trust,
            config,
            node_boot_id,
            label_epoch,
            now_utc_ns,
        )
    }

    fn accept_exception_inventory_at(
        &mut self,
        inventory: ExceptionInventory,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
        now_utc_ns: i64,
    ) -> Result<Option<PreparedExceptionDeliveryV1>> {
        if !inventory.candidate_available {
            return Ok(None);
        }
        ensure!(
            is_sha256(&inventory.candidate_content_id)
                && matches!(inventory.operation.as_str(), "ACTIVATE" | "REVOKE")
                && !inventory.candidate_json.is_empty()
                && inventory.candidate_json.len() <= MAX_EXCEPTION_CANDIDATE_BYTES,
            ControlProtocolSnafu {
                reason: "Control delivered invalid exception inventory",
            }
        );
        let candidate: ExceptionDeliveryCandidateV1 =
            serde_json::from_slice(&inventory.candidate_json).context(JsonSnafu {
                path: self.root.join("exceptions/inventory.json"),
            })?;
        ensure!(
            candidate.candidate_content_id == inventory.candidate_content_id
                && exception_operation_name(candidate.operation) == inventory.operation,
            ControlProtocolSnafu {
                reason: "the exception candidate differs from its inventory identity",
            }
        );
        let prepared = self.prepare_exception_delivery(
            candidate,
            trust,
            config,
            node_boot_id,
            label_epoch,
            now_utc_ns,
        )?;
        self.stage_exception_delivery(&prepared, &inventory.candidate_json, now_utc_ns)?;
        if prepared.candidate.operation == ExceptionDeliveryOperationV1::Activate
            && prepared.candidate.valid_until_utc_ns <= now_utc_ns
        {
            self.commit_exception_result(
                &prepared.candidate,
                ExceptionActivationStateV1::Expired,
                0,
                now_utc_ns,
            )?;
            return Ok(None);
        }
        Ok(Some(prepared))
    }

    fn stage_exception_delivery(
        &mut self,
        prepared: &PreparedExceptionDeliveryV1,
        candidate_json: &[u8],
        now_utc_ns: i64,
    ) -> Result<()> {
        ensure!(
            self.state
                .exception_records
                .contains_key(&prepared.candidate.exception_instance_id)
                || self.state.exception_records.len()
                    < usize::try_from(EXCEPTION_USE_RECEIPT_CAPACITY).unwrap_or(usize::MAX),
            IdentityStateSnafu {
                reason: "the durable exception record capacity is exhausted",
            }
        );
        let path = self
            .root
            .join("exceptions")
            .join(format!("{}.json", prepared.candidate.candidate_content_id));
        ensure!(
            candidate_json.len() <= MAX_EXCEPTION_CANDIDATE_BYTES
                && serde_json::from_slice::<ExceptionDeliveryCandidateV1>(candidate_json)
                    .is_ok_and(|candidate| candidate == prepared.candidate),
            ControlProtocolSnafu {
                reason: "the staged exception bytes differ from the verified candidate",
            }
        );
        write_atomic(&path, candidate_json)?;
        let instance_id = prepared.candidate.exception_instance_id.clone();
        let consumed_uses = self
            .state
            .exception_records
            .get(&instance_id)
            .filter(|_| prepared.candidate.operation == ExceptionDeliveryOperationV1::Revoke)
            .map_or(0, |record| record.consumed_uses);
        self.state.exception_records.insert(
            instance_id.clone(),
            ExceptionDeliveryRecordV1 {
                tenant_id: prepared.candidate.tenant_id.clone(),
                candidate_content_id: prepared.candidate.candidate_content_id.clone(),
                exception_source_revision_id: prepared
                    .candidate
                    .exception_source_revision_id
                    .clone(),
                candidate_file: self.relative_bundle_file(&path)?,
                operation: prepared.candidate.operation,
                profile_generation_ref_id: prepared.candidate.profile_generation_ref_id,
                grant_handle: prepared.grant_handle,
                valid_until_utc_ns: prepared.candidate.valid_until_utc_ns,
                state: LocalExceptionStateV1::Pending,
                consumed_uses,
                transition_version: 0,
                observed_utc_ns: now_utc_ns,
                control_acknowledged: false,
                report_to_control: true,
            },
        );
        self.state.exception_distribution_high_water.insert(
            instance_id,
            SequenceV1 {
                epoch: prepared.candidate.distribution_sequence_epoch,
                sequence: prepared.candidate.distribution_sequence,
            },
        );
        // Persist receipt before kernel activation so restart resumes this exact candidate.
        self.persist_state()
    }

    pub(crate) fn reconcile_pending_exception(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
        now_utc_ns: i64,
    ) -> Result<Option<PreparedExceptionDeliveryV1>> {
        self.reconcile_pending_exception_with_readback(
            trust,
            config,
            (node_boot_id, label_epoch),
            now_utc_ns,
            |instance_id, record, candidate| {
                Self::observe_pending_exception(host, config, instance_id, record, candidate)
            },
        )
    }

    fn reconcile_pending_exception_with_readback<F>(
        &mut self,
        trust: &TrustCache,
        config: &NodeConfig,
        session: (&[u8], u64),
        now_utc_ns: i64,
        readback: F,
    ) -> Result<Option<PreparedExceptionDeliveryV1>>
    where
        F: FnOnce(
            &str,
            &ExceptionDeliveryRecordV1,
            &ExceptionDeliveryCandidateV1,
        ) -> Result<PendingExceptionPhysicalV1>,
    {
        let Some((instance_id, candidate, prepared)) =
            self.verified_pending_exception(trust, config, session.0, session.1)?
        else {
            return Ok(None);
        };
        let record = self
            .state
            .exception_records
            .get(&instance_id)
            .context(IdentityStateSnafu {
                reason: "the verified pending exception disappeared during recovery",
            })?
            .clone();
        let physical = readback(&instance_id, &record, &candidate)?;
        self.resolve_pending_exception(&instance_id, &candidate, prepared, physical, now_utc_ns)
    }

    fn verified_pending_exception(
        &mut self,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<
        Option<(
            String,
            ExceptionDeliveryCandidateV1,
            PreparedExceptionDeliveryV1,
        )>,
    > {
        let Some((instance_id, record)) = self
            .state
            .exception_records
            .iter()
            .find(|(_, record)| record.state == LocalExceptionStateV1::Pending)
            .map(|(instance_id, record)| (instance_id.clone(), record.clone()))
        else {
            return Ok(None);
        };
        let candidate = self.read_exception_candidate(&record)?;
        let prepared = self.prepare_exception_delivery(
            candidate.clone(),
            trust,
            config,
            node_boot_id,
            label_epoch,
            record.observed_utc_ns,
        )?;
        self.restore_exception_recovery_identity(&instance_id, &candidate, &prepared)?;
        Ok(Some((instance_id, candidate, prepared)))
    }

    fn restore_exception_recovery_identity(
        &mut self,
        instance_id: &str,
        candidate: &ExceptionDeliveryCandidateV1,
        prepared: &PreparedExceptionDeliveryV1,
    ) -> Result<()> {
        let record =
            self.state
                .exception_records
                .get_mut(instance_id)
                .context(IdentityStateSnafu {
                    reason: "the pending exception record disappeared during recovery",
                })?;
        let complete = record.tenant_id == candidate.tenant_id
            && record.exception_source_revision_id == candidate.exception_source_revision_id
            && record.profile_generation_ref_id == candidate.profile_generation_ref_id
            && record.grant_handle == prepared.grant_handle
            && record.valid_until_utc_ns == candidate.valid_until_utc_ns;
        if complete {
            return Ok(());
        }
        ensure!(
            record.tenant_id.is_empty()
                && record.exception_source_revision_id.is_empty()
                && record.profile_generation_ref_id == 0
                && record.grant_handle == 0
                && record.valid_until_utc_ns == 0,
            IdentityStateSnafu {
                reason: "the pending exception recovery identity differs from its candidate",
            }
        );
        record.tenant_id.clone_from(&candidate.tenant_id);
        record
            .exception_source_revision_id
            .clone_from(&candidate.exception_source_revision_id);
        record.profile_generation_ref_id = candidate.profile_generation_ref_id;
        record.grant_handle = prepared.grant_handle;
        record.valid_until_utc_ns = candidate.valid_until_utc_ns;
        self.persist_state()
    }

    fn observe_pending_exception(
        host: &erebor_interceptor::KernelHost,
        config: &NodeConfig,
        instance_id: &str,
        record: &ExceptionDeliveryRecordV1,
        candidate: &ExceptionDeliveryCandidateV1,
    ) -> Result<PendingExceptionPhysicalV1> {
        let runtime_key = ExceptionRuntimeStateKeyV1 {
            node_id: crate::policy::stable_node_id(&config.node_id)?,
            exception_instance_id: crate::policy::parse_id("exception_instance_id", instance_id)?,
        };
        let binding_key = ExceptionHandleBindingKeyV1 {
            profile_generation_ref_id: record.profile_generation_ref_id,
            exception_numeric_handle: record.grant_handle,
            reserved: 0,
        };
        let runtime = host
            .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
            .context(InterceptorSnafu)?;
        let binding = host
            .lookup_map("exception_handle_bindings", binding_key.as_bytes())
            .context(InterceptorSnafu)?;
        let definition: [u8; 32] = hex::decode(&record.candidate_content_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .context(IdentityStateSnafu {
                reason: "the pending exception definition digest is invalid",
            })?;
        Self::pending_exception_physical_state(
            runtime.as_deref(),
            binding.as_deref(),
            runtime_key,
            definition,
            candidate.maximum_uses,
            crate::policy::current_boottime_ns()?,
        )
    }

    fn pending_exception_physical_state(
        runtime: Option<&[u8]>,
        binding: Option<&[u8]>,
        runtime_key: ExceptionRuntimeStateKeyV1,
        definition: [u8; 32],
        maximum_uses: u32,
        now_boottime_ns: u64,
    ) -> Result<PendingExceptionPhysicalV1> {
        let (runtime, binding) = match (runtime, binding) {
            (None, None) => return Ok(PendingExceptionPhysicalV1::Absent),
            (Some(runtime), Some(binding)) => (runtime, binding),
            _ => {
                return IdentityStateSnafu {
                    reason: "the pending exception has an incomplete physical publication"
                        .to_owned(),
                }
                .fail()
            }
        };
        let runtime = ExceptionRuntimeStateV1::try_read_from_bytes(runtime).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("the pending exception runtime state is invalid: {error}"),
            }
            .build()
        })?;
        let binding = ExceptionHandleBindingV1::try_read_from_bytes(binding).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("the pending exception binding is invalid: {error}"),
            }
            .build()
        })?;
        ensure!(
            binding.runtime_state_key == runtime_key
                && binding.state == ExceptionBindingStateV1::Active
                && runtime.exception_definition_sha256 == definition
                && runtime.maximum_uses == maximum_uses
                && runtime.consumed_uses <= runtime.maximum_uses
                && runtime.bound_profile_generation_refs > 0,
            IdentityStateSnafu {
                reason: "the pending exception physical state differs from its durable identity",
            }
        );
        let consumed_uses = runtime.consumed_uses;
        match runtime.state {
            ExceptionRuntimeStateKindV1::Active
                if now_boottime_ns >= runtime.deadline_boottime_ns =>
            {
                Ok(PendingExceptionPhysicalV1::Expired { consumed_uses })
            }
            ExceptionRuntimeStateKindV1::Active => {
                Ok(PendingExceptionPhysicalV1::Active { consumed_uses })
            }
            ExceptionRuntimeStateKindV1::Exhausted => {
                Ok(PendingExceptionPhysicalV1::Consumed { consumed_uses })
            }
            ExceptionRuntimeStateKindV1::Expired => {
                Ok(PendingExceptionPhysicalV1::Expired { consumed_uses })
            }
            ExceptionRuntimeStateKindV1::Unknown
            | ExceptionRuntimeStateKindV1::ReconciliationRequired => IdentityStateSnafu {
                reason: "the pending exception physical state is ambiguous".to_owned(),
            }
            .fail(),
        }
    }

    fn resolve_pending_exception(
        &mut self,
        instance_id: &str,
        candidate: &ExceptionDeliveryCandidateV1,
        prepared: PreparedExceptionDeliveryV1,
        physical: PendingExceptionPhysicalV1,
        now_utc_ns: i64,
    ) -> Result<Option<PreparedExceptionDeliveryV1>> {
        match (candidate.operation, physical) {
            (ExceptionDeliveryOperationV1::Activate, PendingExceptionPhysicalV1::Absent)
                if now_utc_ns < candidate.valid_until_utc_ns =>
            {
                Ok(Some(prepared))
            }
            (ExceptionDeliveryOperationV1::Activate, PendingExceptionPhysicalV1::Absent)
            | (
                ExceptionDeliveryOperationV1::Activate,
                PendingExceptionPhysicalV1::Expired { .. },
            ) => {
                let consumed_uses = match physical {
                    PendingExceptionPhysicalV1::Expired { consumed_uses } => consumed_uses,
                    _ => 0,
                };
                self.commit_recovered_exception(
                    instance_id,
                    LocalExceptionStateV1::Expired,
                    consumed_uses,
                    now_utc_ns,
                )?;
                Ok(None)
            }
            (
                ExceptionDeliveryOperationV1::Activate,
                PendingExceptionPhysicalV1::Active { consumed_uses },
            ) => {
                self.commit_recovered_exception(
                    instance_id,
                    LocalExceptionStateV1::Active,
                    consumed_uses,
                    now_utc_ns,
                )?;
                Ok(None)
            }
            (
                ExceptionDeliveryOperationV1::Activate,
                PendingExceptionPhysicalV1::Consumed { consumed_uses },
            ) => {
                self.commit_recovered_exception(
                    instance_id,
                    LocalExceptionStateV1::Consumed,
                    consumed_uses,
                    now_utc_ns,
                )?;
                Ok(None)
            }
            (ExceptionDeliveryOperationV1::Revoke, PendingExceptionPhysicalV1::Absent) => {
                let consumed_uses = self
                    .state
                    .exception_records
                    .get(instance_id)
                    .map_or(0, |record| record.consumed_uses);
                self.commit_recovered_exception(
                    instance_id,
                    LocalExceptionStateV1::Revoked,
                    consumed_uses,
                    now_utc_ns,
                )?;
                Ok(None)
            }
            (ExceptionDeliveryOperationV1::Revoke, _) => Ok(Some(prepared)),
        }
    }

    fn commit_recovered_exception(
        &mut self,
        instance_id: &str,
        state: LocalExceptionStateV1,
        consumed_uses: u32,
        observed_utc_ns: i64,
    ) -> Result<()> {
        let record =
            self.state
                .exception_records
                .get_mut(instance_id)
                .context(IdentityStateSnafu {
                    reason: "the pending exception record disappeared during recovery",
                })?;
        ensure!(
            record.state == LocalExceptionStateV1::Pending
                && matches!(
                    state,
                    LocalExceptionStateV1::Active
                        | LocalExceptionStateV1::Consumed
                        | LocalExceptionStateV1::Expired
                        | LocalExceptionStateV1::Revoked
                )
                && observed_utc_ns > 0,
            IdentityStateSnafu {
                reason: "the recovered exception terminal state is invalid",
            }
        );
        record.state = state;
        record.consumed_uses = consumed_uses;
        record.transition_version = 1;
        record.observed_utc_ns = observed_utc_ns;
        record.control_acknowledged = false;
        // Control must receive this durable result before it can send another exception.
        self.persist_state()
    }

    fn prepare_exception_delivery(
        &self,
        candidate: ExceptionDeliveryCandidateV1,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
        now_utc_ns: i64,
    ) -> Result<PreparedExceptionDeliveryV1> {
        let base_bundle = self.policy_bundle_for_candidate(&candidate.base_candidate_content_id)?;
        let trusted_key = trust.policy_signing_key(
            &candidate.signing_key_id,
            base_bundle.profile_artifact.header.sequence_epoch,
        )?;
        candidate
            .verify(&trusted_key, &config.node_id, now_utc_ns)
            .context(PolicySnafu)?;
        let identity = candidate.exact_target.kubernetes.as_ref().ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "the exception candidate has no Kubernetes identity".to_owned(),
            }
            .build()
        })?;
        let expected_node_name = config.kubernetes_node_name.as_deref().ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "exception delivery needs the registered Kubernetes Node name".to_owned(),
            }
            .build()
        })?;
        let tenant_id = config
            .evidence
            .as_ref()
            .map(|evidence| evidence.tenant_id.as_str())
            .unwrap_or_default();
        let base_contains_target = base_bundle
            .candidate
            .exact_target
            .workload_targets
            .contains(&candidate.exact_target);
        // The signed exception must repeat one exact workload from its signed base candidate.
        let current = self
            .state
            .exception_records
            .get(&candidate.exception_instance_id);
        let operation_is_valid = current.map_or_else(
            || {
                candidate.operation == ExceptionDeliveryOperationV1::Activate
                    && candidate.predecessor_candidate_content_id.is_none()
                    && self.state.active_profiles.values().any(|record| {
                        record.candidate_content_id == candidate.base_candidate_content_id
                            && record.policy_source_revision_id
                                == candidate.base_policy_source_revision_id
                            && record.profile_generation_ref_id
                                == candidate.profile_generation_ref_id
                    })
            },
            |record| {
                if record.candidate_content_id == candidate.candidate_content_id {
                    return record.state == LocalExceptionStateV1::Pending;
                }
                candidate.operation == ExceptionDeliveryOperationV1::Revoke
                    && candidate.predecessor_candidate_content_id.as_deref()
                        == Some(record.candidate_content_id.as_str())
                    && record.operation == ExceptionDeliveryOperationV1::Activate
            },
        );
        let distribution = SequenceV1 {
            epoch: candidate.distribution_sequence_epoch,
            sequence: candidate.distribution_sequence,
        };
        let sequence_is_valid = current
            .is_some_and(|record| record.candidate_content_id == candidate.candidate_content_id)
            || self
                .state
                .exception_distribution_high_water
                .get(&candidate.exception_instance_id)
                .is_none_or(|high_water| distribution > *high_water);
        let grant = base_bundle
            .profile_artifact
            .policy_document
            .file_exception_grants
            .iter()
            .find(|grant| grant.grant_id == candidate.grant_id)
            .ok_or_else(|| {
                ControlProtocolSnafu {
                    reason: "the base policy does not define the exception grant".to_owned(),
                }
                .build()
            })?;
        let requested_duration = candidate
            .valid_until_utc_ns
            .saturating_sub(candidate.issued_utc_ns);
        ensure!(
            candidate.tenant_id == tenant_id
                && candidate.base_policy_source_revision_id
                    == base_bundle.candidate.policy_source_revision_id
                && candidate.profile_id
                    == base_bundle
                        .profile_artifact
                        .policy_document
                        .metadata
                        .profile_id
                && base_contains_target
                && candidate.exact_target.node_id == config.node_id
                && identity.kubernetes_node_name == expected_node_name
                && identity.node_boot_id == hex::encode(node_boot_id)
                && identity.label_epoch == label_epoch
                && identity.policy_source_revision_id == candidate.base_policy_source_revision_id
                && candidate.maximum_uses <= grant.maximum_uses
                && (candidate.operation == ExceptionDeliveryOperationV1::Revoke
                    || u64::try_from(requested_duration)
                        .is_ok_and(|duration| duration <= grant.maximum_duration_ns))
                && operation_is_valid
                && sequence_is_valid,
            ControlProtocolSnafu {
                reason: "the exception candidate is stale or differs from its exact base binding",
            }
        );
        Ok(PreparedExceptionDeliveryV1 {
            grant_handle: exception_grant_handle(
                &base_bundle.profile_artifact.policy_document,
                &candidate.grant_id,
            )?,
            candidate,
        })
    }

    pub(crate) fn commit_exception_result(
        &mut self,
        candidate: &ExceptionDeliveryCandidateV1,
        state: ExceptionActivationStateV1,
        consumed_uses: u32,
        observed_utc_ns: i64,
    ) -> Result<()> {
        let record = self
            .state
            .exception_records
            .get_mut(&candidate.exception_instance_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "the exception result has no durable delivery record".to_owned(),
                }
                .build()
            })?;
        ensure!(
            record.candidate_content_id == candidate.candidate_content_id
                && record.state == LocalExceptionStateV1::Pending
                && consumed_uses >= record.consumed_uses
                && consumed_uses <= candidate.maximum_uses
                && observed_utc_ns > 0,
            IdentityStateSnafu {
                reason: "the exception result does not match its pending candidate",
            }
        );
        let operation_state_is_valid = match candidate.operation {
            ExceptionDeliveryOperationV1::Activate => {
                !matches!(state, ExceptionActivationStateV1::Revoked)
            }
            ExceptionDeliveryOperationV1::Revoke => matches!(
                state,
                ExceptionActivationStateV1::Revoked
                    | ExceptionActivationStateV1::Rejected
                    | ExceptionActivationStateV1::Stale
            ),
        };
        ensure!(
            operation_state_is_valid,
            IdentityStateSnafu {
                reason: "the local exception state is invalid for its delivery operation",
            }
        );
        record.state = local_exception_state(state);
        record.consumed_uses = consumed_uses;
        record.transition_version = 1;
        record.observed_utc_ns = observed_utc_ns;
        record.control_acknowledged = false;
        // Persist the physical result before the network acknowledgement can leave this node.
        self.persist_state()?;
        erebor_telemetry::info!(
            "changed local exception authority",
            candidate_id = %candidate.candidate_content_id,
            state = %local_exception_state_name(local_exception_state(state)),
            consumed_uses = %consumed_uses
        );
        Ok(())
    }

    pub(crate) fn pending_exception_acknowledgement(
        &self,
    ) -> Result<Option<ExceptionActivationAcknowledgement>> {
        let Some(record) = self.state.exception_records.values().find(|record| {
            record.state != LocalExceptionStateV1::Pending
                && !record.control_acknowledged
                && record.report_to_control
        }) else {
            return Ok(None);
        };
        Ok(Some(ExceptionActivationAcknowledgement {
            tenant_id: record.tenant_id.clone(),
            candidate_content_id: record.candidate_content_id.clone(),
            exception_source_revision_id: record.exception_source_revision_id.clone(),
            state: local_exception_state_name(record.state).to_owned(),
            consumed_uses: record.consumed_uses,
            transition_version: record.transition_version,
            reason_code: matches!(
                record.state,
                LocalExceptionStateV1::Rejected | LocalExceptionStateV1::Stale
            )
            .then(|| "EXCEPTION_CANDIDATE_REJECTED".to_owned())
            .unwrap_or_default(),
            observed_utc_ns: record.observed_utc_ns,
        }))
    }

    pub(crate) fn acknowledged_active_exception_candidates(
        &self,
    ) -> Result<Vec<ExceptionDeliveryCandidateV1>> {
        self.state
            .exception_records
            .values()
            .filter(|record| {
                record.state == LocalExceptionStateV1::Active && record.control_acknowledged
            })
            .map(|record| self.read_exception_candidate(record))
            .collect()
    }

    pub(crate) fn observe_exception_result(
        &mut self,
        candidate: &ExceptionDeliveryCandidateV1,
        observation: crate::policy::ExceptionRuntimeObservationV1,
        observed_utc_ns: i64,
    ) -> Result<()> {
        let record = self
            .state
            .exception_records
            .get_mut(&candidate.exception_instance_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "the observed exception has no durable delivery record".to_owned(),
                }
                .build()
            })?;
        ensure!(
            record.candidate_content_id == candidate.candidate_content_id
                && record.state == LocalExceptionStateV1::Active
                && record.control_acknowledged
                && matches!(
                    observation.state,
                    ExceptionActivationStateV1::Active
                        | ExceptionActivationStateV1::Consumed
                        | ExceptionActivationStateV1::Expired
                        | ExceptionActivationStateV1::Stale
                )
                && observation.consumed_uses >= record.consumed_uses
                && observation.consumed_uses <= candidate.maximum_uses,
            IdentityStateSnafu {
                reason: "the observed exception state is stale or non-monotonic",
            }
        );
        let next_state = local_exception_state(observation.state);
        if next_state == record.state && observation.consumed_uses == record.consumed_uses {
            return Ok(());
        }
        // Runtime transitions are monotonic and each new state requires a new Control ACK.
        record.state = next_state;
        record.consumed_uses = observation.consumed_uses;
        record.transition_version = record.transition_version.checked_add(1).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "the exception acknowledgement transition version is exhausted".to_owned(),
            }
            .build()
        })?;
        record.observed_utc_ns = observed_utc_ns;
        record.control_acknowledged = false;
        self.persist_state()
    }

    pub(crate) fn acknowledge_exception_control(
        &mut self,
        candidate_content_id: &str,
    ) -> Result<()> {
        let record = self
            .state
            .exception_records
            .values_mut()
            .find(|record| record.candidate_content_id == candidate_content_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "Control accepted an unknown exception candidate".to_owned(),
                }
                .build()
            })?;
        ensure!(
            record.state != LocalExceptionStateV1::Pending,
            IdentityStateSnafu {
                reason: "Control accepted an exception before its local result",
            }
        );
        record.control_acknowledged = true;
        self.persist_state()?;
        erebor_telemetry::debug!(
            "acknowledged local exception authority with Control",
            candidate_id = %candidate_content_id
        );
        Ok(())
    }

    pub(crate) fn begin_control_session(&mut self) {
        self.session_inventory = None;
    }

    pub(crate) fn next_transfer_action(&mut self) -> Result<PolicyTransferActionV1> {
        let Some(inventory) = self.session_inventory.as_ref() else {
            return Ok(PolicyTransferActionV1::Inventory {
                active_candidate_content_id: self.active_candidate_content_id().map(str::to_owned),
                durable_bundle_digests: self.durable_bundle_digests(),
            });
        };
        let transfer = self.load_transfer()?;
        if let Some(index) = (0..inventory.chunk_count)
            .find(|index| !self.transferred_chunk_is_valid(&transfer, *index))
        {
            return Ok(PolicyTransferActionV1::Fetch {
                candidate_content_id: inventory.candidate_content_id.clone(),
                bundle_digest: inventory.bundle_digest.clone(),
                chunk_index: index,
            });
        }
        let bytes = self.assemble_transfer(&transfer)?;
        let directory = self.transfer_directory(&inventory.bundle_digest);
        let bundle: PolicyBundleV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &directory })?;
        ensure!(
            bundle.bundle_digest == inventory.bundle_digest
                && bundle.candidate.candidate_content_id == inventory.candidate_content_id,
            ControlProtocolSnafu {
                reason: "the assembled policy bundle differs from inventory",
            }
        );
        self.session_inventory = None;
        Ok(PolicyTransferActionV1::Ready(Box::new(bundle)))
    }

    pub(crate) fn accept_inventory(&mut self, inventory: PolicyInventory) -> Result<bool> {
        self.validate_desired_inventory(&inventory)?;
        if !inventory.candidate_available {
            self.session_inventory = None;
            if inventory.desired_inventory_complete {
                self.begin_inventory_retirement(&inventory.desired_bundle_digests)?;
            }
            erebor_telemetry::trace!("policy inventory has no candidate");
            return Ok(false);
        }
        self.validate_inventory(&inventory)?;
        ensure!(
            !inventory.desired_inventory_complete
                || inventory
                    .desired_bundle_digests
                    .contains(&inventory.bundle_digest),
            ControlProtocolSnafu {
                reason: "Control candidate is absent from its complete desired inventory",
            }
        );
        if self.state.active_candidate_content_id.as_deref()
            == Some(inventory.candidate_content_id.as_str())
        {
            self.session_inventory = None;
            return Ok(false);
        }
        // Reuse a partial transfer only when all inventory identity and size fields match.
        let mut transfer = self.load_transfer()?;
        if transfer.candidate_content_id != inventory.candidate_content_id
            || transfer.bundle_digest != inventory.bundle_digest
            || transfer.bundle_bytes != inventory.bundle_bytes
            || transfer.chunk_count != inventory.chunk_count
        {
            transfer = TransferStateV1 {
                candidate_content_id: inventory.candidate_content_id.clone(),
                bundle_digest: inventory.bundle_digest.clone(),
                bundle_bytes: inventory.bundle_bytes,
                chunk_count: inventory.chunk_count,
                chunk_digests: BTreeMap::new(),
            };
            self.persist_transfer(&transfer)?;
            erebor_telemetry::debug!(
                "started a policy bundle transfer",
                candidate_id = %inventory.candidate_content_id,
                chunk_count = %inventory.chunk_count,
                bundle_bytes = %inventory.bundle_bytes
            );
        }
        let directory = self.transfer_directory(&inventory.bundle_digest);
        fs::create_dir_all(&directory).context(IoSnafu { path: &directory })?;
        self.session_inventory = Some(inventory);
        Ok(true)
    }

    fn begin_inventory_retirement(&mut self, desired_bundle_digests: &[String]) -> Result<()> {
        if self.state.inventory_retirement.is_some() {
            return Ok(());
        }
        let desired = desired_bundle_digests.iter().collect::<BTreeSet<_>>();
        let Some(record) = self.state.active_profiles.values().find(|record| {
            !desired.contains(&record.bundle_digest)
                && record.scheduled_bindings.iter().all(|binding| {
                    binding.root_cgroup_path.is_none()
                        && binding.container_id.starts_with("scheduled:")
                })
        }) else {
            return Ok(());
        };
        let retirement = InventoryPolicyRetirementV1 {
            candidate_content_id: record.candidate_content_id.clone(),
            profile_id: self
                .state
                .active_profiles
                .iter()
                .find_map(|(profile_id, candidate)| {
                    (candidate.candidate_content_id == record.candidate_content_id)
                        .then(|| profile_id.clone())
                })
                .context(IdentityStateSnafu {
                    reason: "stale policy inventory lost its active profile identity",
                })?,
            bundle_digest: record.bundle_digest.clone(),
            profile_generation_ref_id: record.profile_generation_ref_id,
            binding_ids: record.binding_ids.clone(),
            legacy_control_commit_index: 0,
            delivery_state_retired: false,
        };
        let previous = self.state.clone();
        self.state.inventory_retirement = Some(retirement);
        self.persist_state_or_restore(previous)?;
        Ok(())
    }

    pub(crate) fn accept_chunk(&mut self, chunk: PolicyChunk) -> Result<()> {
        let inventory = self.session_inventory.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "a policy chunk has no validated session inventory".to_owned(),
            }
            .build()
        })?;
        ensure!(
            chunk.candidate_content_id == inventory.candidate_content_id
                && chunk.bundle_digest == inventory.bundle_digest
                && chunk.chunk_index < inventory.chunk_count
                && chunk.chunk_count == inventory.chunk_count
                && chunk.payload.len() <= MAX_POLICY_BUNDLE_CHUNK_BYTES
                && sha256(&chunk.payload) == chunk.chunk_sha256,
            ControlProtocolSnafu {
                reason: "Control delivered an invalid policy chunk",
            }
        );
        let mut transfer = self.load_transfer()?;
        let path = self
            .transfer_directory(&inventory.bundle_digest)
            .join(format!("{:08}.chunk", chunk.chunk_index));
        // Persist one verified chunk before the next action can advance the cursor.
        write_atomic(&path, &chunk.payload)?;
        transfer
            .chunk_digests
            .insert(chunk.chunk_index, chunk.chunk_sha256);
        self.persist_transfer(&transfer)?;
        erebor_telemetry::trace!(
            "stored a policy bundle chunk",
            candidate_id = %chunk.candidate_content_id,
            chunk_index = %chunk.chunk_index,
            chunk_count = %chunk.chunk_count
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn prepare_activation(
        &self,
        bundle: &PolicyBundleV1,
        trust: &TrustCache,
        config: &NodeConfig,
        capabilities: &[CapabilityRecord],
        profile_generation_ref_id: u64,
        now_utc_ns: i64,
    ) -> Result<PreparedPolicyActivationV1> {
        self.prepare_activation_inner(
            bundle,
            trust,
            config,
            capabilities,
            profile_generation_ref_id,
            now_utc_ns,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_activation_for_session(
        &self,
        bundle: &PolicyBundleV1,
        trust: &TrustCache,
        config: &NodeConfig,
        capabilities: &[CapabilityRecord],
        profile_generation_ref_id: u64,
        now_utc_ns: i64,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<PreparedPolicyActivationV1> {
        let prepared = self.prepare_activation_inner(
            bundle,
            trust,
            config,
            capabilities,
            profile_generation_ref_id,
            now_utc_ns,
            Some((node_boot_id, label_epoch)),
        );
        if let Err(error) = &prepared {
            erebor_telemetry::warn!(
                error;
                "rejected a policy candidate",
                candidate_id = %bundle.candidate.candidate_content_id,
                retry = %"after_new_candidate"
            );
        }
        prepared
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_activation_inner(
        &self,
        bundle: &PolicyBundleV1,
        trust: &TrustCache,
        config: &NodeConfig,
        capabilities: &[CapabilityRecord],
        profile_generation_ref_id: u64,
        now_utc_ns: i64,
        session: Option<(&[u8], u64)>,
    ) -> Result<PreparedPolicyActivationV1> {
        let candidate = &bundle.candidate;
        let profile = &bundle.profile_artifact;
        let profile_id = profile.header.profile_id.clone();
        // Trust, tenant, capability, target, and replay checks all precede kernel staging.
        let trusted_key =
            trust.policy_signing_key(&candidate.signing_key_id, profile.header.sequence_epoch)?;
        ensure!(
            candidate.signing_key_id == profile.signed_profile.signing_key_id
                && trusted_key.to_bytes().as_slice() == bundle.profile_signing_public_key
                && candidate.tenant_id
                    == config
                        .evidence
                        .as_ref()
                        .map(|evidence| evidence.tenant_id.as_str())
                        .unwrap_or_default(),
            ControlProtocolSnafu {
                reason: "the policy bundle signer or tenant is not trusted for this node",
            }
        );
        bundle
            .verify(&trusted_key, &config.node_id, now_utc_ns)
            .context(PolicySnafu)?;
        let supported_capabilities = capabilities
            .iter()
            .filter(|capability| matches!(capability.state.as_str(), "SUPPORTED" | "DEGRADED"))
            .map(|capability| capability.capability_id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            profile
                .policy_document
                .required_capability_ids
                .iter()
                .all(|capability| supported_capabilities.contains(capability.as_str())),
            ControlProtocolSnafu {
                reason: "the node does not support every required policy capability",
            }
        );
        // Issuer and node-distribution sequences are independent replay domains.
        let issuer = SequenceV1 {
            epoch: profile.header.sequence_epoch,
            sequence: profile.header.issuer_sequence,
        };
        let distribution = SequenceV1 {
            epoch: candidate.distribution_sequence_epoch,
            sequence: candidate.distribution_sequence,
        };
        let current = self.state.active_profiles.get(&profile_id);
        ensure!(
            self.state
                .issuer_high_water
                .get(&candidate.signing_key_id)
                .is_none_or(|high_water| issuer > *high_water)
                && self
                    .state
                    .distribution_high_water
                    .get(&profile_id)
                    .is_none_or(|high_water| distribution > *high_water)
                && current.map_or_else(
                    || {
                        (candidate.operation == PolicyDeliveryOperationV1::Activate
                            && candidate.predecessor_candidate_content_id.is_none())
                            || (candidate.operation == PolicyDeliveryOperationV1::Replace
                                && candidate.predecessor_candidate_content_id.is_some())
                    },
                    |current| {
                        (candidate.operation == PolicyDeliveryOperationV1::Replace
                            && candidate.predecessor_candidate_content_id.is_some())
                            || (candidate.operation
                                == PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
                                && candidate.predecessor_candidate_content_id.as_deref()
                                    == Some(current.candidate_content_id.as_str()))
                    }
                ),
            ControlProtocolSnafu {
                reason:
                    "the policy candidate failed issuer, distribution, or predecessor anti-replay",
            }
        );
        // Build and validate a complete next configuration without mutating the live owner.
        let mut dynamic = config.clone();
        let scheduled_targets = materialize_scheduled_bindings(
            bundle,
            &mut dynamic,
            profile_generation_ref_id,
            session,
        )?;
        let mut local_targets = dynamic
            .workload_bindings
            .iter()
            .filter(|binding| binding.scheduled_binding_authority_id.is_none())
            .filter(|binding| binding.profile_id == profile_id)
            .map(|binding| {
                Ok((
                    crate::node::workload_binding_generation_digest(binding)?,
                    binding.binding_id.clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        local_targets.extend(scheduled_targets);
        let target_digests = candidate
            .exact_target
            .workload_binding_generation_digests
            .iter()
            .collect::<BTreeSet<_>>();
        ensure!(
            !target_digests.is_empty()
                && target_digests.len()
                    == candidate
                        .exact_target
                        .workload_binding_generation_digests
                        .len()
                && target_digests
                    .iter()
                    .all(|digest| local_targets.contains_key(*digest)),
            ControlProtocolSnafu {
                reason: "the policy candidate does not bind exact local workloads",
            }
        );
        let mut binding_ids = target_digests
            .into_iter()
            .filter_map(|digest| local_targets.get(digest).cloned())
            .collect::<Vec<_>>();
        binding_ids.sort();
        let selected_bindings = dynamic
            .workload_bindings
            .iter()
            .filter(|binding| binding_ids.contains(&binding.binding_id))
            .collect::<Vec<_>>();
        let administrative_required =
            profile
                .policy_document
                .entry_role_assignments
                .iter()
                .any(|assignment| {
                    assignment.required_administrative_exec_approval
                        && selected_bindings.iter().any(|binding| {
                            assignment
                                .workload_selector_ids
                                .contains(&binding.workload_selector_id)
                        })
                });
        ensure!(
            !administrative_required || config.administrative_authorization.is_some(),
            ControlProtocolSnafu {
                reason: "the policy requires administrative authorization that is not configured",
            }
        );
        let bundle_directory = self.root.join("bundles").join(&bundle.bundle_digest);
        fs::create_dir_all(&bundle_directory).context(IoSnafu {
            path: &bundle_directory,
        })?;
        let artifact_path = bundle_directory.join("profile-artifact.json");
        let public_key_path = bundle_directory.join("profile-public-key.hex");
        let bundle_path = bundle_directory.join("bundle.json");
        // Persist signed inputs before the node can record a pending kernel activation.
        write_atomic(
            &artifact_path,
            &serde_json::to_vec_pretty(&bundle.profile_artifact).context(JsonSnafu {
                path: &artifact_path,
            })?,
        )?;
        write_atomic(
            &public_key_path,
            hex::encode(&bundle.profile_signing_public_key).as_bytes(),
        )?;
        write_atomic(
            &bundle_path,
            &serde_json::to_vec(bundle).context(JsonSnafu { path: &bundle_path })?,
        )?;
        dynamic.policy_candidates.retain(|candidate| {
            self.state.active_profiles.values().any(|active| {
                self.checked_bundle_file(&active.artifact_file)
                    .is_ok_and(|path| path == candidate.artifact_path)
            })
        });
        self.replace_profile_candidate(&mut dynamic, &profile_id, artifact_path, public_key_path)?;
        let selected = binding_ids.iter().collect::<BTreeSet<_>>();
        for binding in &mut dynamic.workload_bindings {
            if selected.contains(&binding.binding_id) {
                binding.active_profile_generation_ref_id = profile_generation_ref_id;
            }
        }
        dynamic.validate()?;
        Ok(PreparedPolicyActivationV1 {
            config: dynamic,
            profile_id,
            binding_ids,
            profile_generation_ref_id,
            staged_utc_ns: now_utc_ns,
        })
    }

    pub(crate) fn commit_activation(
        &mut self,
        bundle: &PolicyBundleV1,
        prepared: &PreparedPolicyActivationV1,
        proof: PolicyActivationProofV1,
    ) -> Result<()> {
        self.ensure_active_profile_inventory_capacity(&prepared.profile_id)?;
        let profile = &bundle.profile_artifact;
        let bundle_directory = self.root.join("bundles").join(&bundle.bundle_digest);
        let artifact_path = bundle_directory.join("profile-artifact.json");
        let public_key_path = bundle_directory.join("profile-public-key.hex");
        let record = ActivePolicyRecordV1 {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            artifact_file: self.relative_bundle_file(&artifact_path)?,
            public_key_file: self.relative_bundle_file(&public_key_path)?,
            profile_generation_ref_id: prepared.profile_generation_ref_id,
            staged_utc_ns: prepared.staged_utc_ns,
            binding_ids: prepared.binding_ids.clone(),
            scheduled_bindings: prepared_scheduled_bindings(prepared),
            node_bound_generation_digest: proof.node_bound_generation_digest,
            readback_digest: proof.readback_digest,
            probe_result_digest: proof.probe_result_digest,
            observed_utc_ns: proof.observed_utc_ns,
        };
        // Publish durable active state only after NodePolicyGenerationOwner returns readback proof.
        self.state.active_candidate_content_id =
            Some(bundle.candidate.candidate_content_id.clone());
        self.state.active_bundle_digest = Some(bundle.bundle_digest.clone());
        self.state.control_acknowledged_candidate_content_id = None;
        self.state.pending_activation = None;
        self.state
            .active_profiles
            .insert(prepared.profile_id.clone(), record);
        self.state.policy_candidate_bundles.insert(
            bundle.candidate.candidate_content_id.clone(),
            bundle.bundle_digest.clone(),
        );
        self.state.issuer_high_water.insert(
            bundle.candidate.signing_key_id.clone(),
            SequenceV1 {
                epoch: profile.header.sequence_epoch,
                sequence: profile.header.issuer_sequence,
            },
        );
        self.state.distribution_high_water.insert(
            prepared.profile_id.clone(),
            SequenceV1 {
                epoch: bundle.candidate.distribution_sequence_epoch,
                sequence: bundle.candidate.distribution_sequence,
            },
        );
        self.persist_state()?;
        // Emit the transition only after restart recovery can observe the same active record.
        erebor_telemetry::info!(
            "activated a policy candidate",
            candidate_id = %bundle.candidate.candidate_content_id,
            profile_id = %prepared.profile_id,
            operation = %policy_delivery_operation_name(bundle.candidate.operation),
            target_count = %prepared.binding_ids.len()
        );
        Ok(())
    }

    fn ensure_active_profile_inventory_capacity(&self, profile_id: &str) -> Result<()> {
        ensure!(
            self.state.active_profiles.contains_key(profile_id)
                || self.state.active_profiles.len() < MAX_ACTIVE_POLICY_PROFILES,
            IdentityStateSnafu {
                reason: "the active policy profile inventory reached its protocol bound",
            }
        );
        Ok(())
    }

    pub(crate) fn begin_activation(
        &mut self,
        bundle: &PolicyBundleV1,
        prepared: &PreparedPolicyActivationV1,
    ) -> Result<()> {
        let bundle_directory = self.root.join("bundles").join(&bundle.bundle_digest);
        let artifact_file =
            self.relative_bundle_file(&bundle_directory.join("profile-artifact.json"))?;
        let public_key_file =
            self.relative_bundle_file(&bundle_directory.join("profile-public-key.hex"))?;
        let bundle_file = self.relative_bundle_file(&bundle_directory.join("bundle.json"))?;
        // This record lets restart recovery distinguish staged intent from committed activation.
        self.state.pending_activation = Some(PendingPolicyRecordV1 {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            profile_id: prepared.profile_id.clone(),
            artifact_file,
            public_key_file,
            bundle_file,
            profile_generation_ref_id: prepared.profile_generation_ref_id,
            staged_utc_ns: prepared.staged_utc_ns,
            binding_ids: prepared.binding_ids.clone(),
            scheduled_bindings: prepared_scheduled_bindings(prepared),
        });
        self.persist_state()?;
        erebor_telemetry::debug!(
            "staged a policy candidate",
            candidate_id = %bundle.candidate.candidate_content_id,
            profile_id = %prepared.profile_id,
            operation = %policy_delivery_operation_name(bundle.candidate.operation)
        );
        Ok(())
    }

    pub(crate) fn validate_pending_activation_pointer(
        &self,
        host: &erebor_interceptor::KernelHost,
    ) -> Result<bool> {
        let Some(pending) = self.state.pending_activation.clone() else {
            return Ok(false);
        };
        let observed = self.pending_profile_generation(host, &pending)?;
        self.validate_pending_activation_generation(&pending, observed)?;
        Ok(true)
    }

    pub(crate) fn commit_pending_activation_from_readback(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        config: &NodeConfig,
        observed_utc_ns: i64,
    ) -> Result<()> {
        let Some(pending) = self.state.pending_activation.clone() else {
            return Ok(());
        };
        let observed = self.pending_profile_generation(host, &pending)?;
        ensure!(
            observed == Some(pending.profile_generation_ref_id),
            IdentityStateSnafu {
                reason: "policy restart did not publish the exact pending generation",
            }
        );
        let receipt = crate::NodePolicyGenerationOwner::activation_receipt(
            host,
            &pending.profile_id,
            pending.profile_generation_ref_id,
        )?;
        self.commit_pending_activation_with_proof(
            config,
            pending.profile_generation_ref_id,
            PolicyActivationProofV1 {
                node_bound_generation_digest: receipt.node_bound_generation_digest,
                readback_digest: receipt.readback_digest,
                probe_result_digest: receipt.probe_result_digest,
                observed_utc_ns,
            },
        )
    }

    fn pending_profile_generation(
        &self,
        host: &erebor_interceptor::KernelHost,
        pending: &PendingPolicyRecordV1,
    ) -> Result<Option<u64>> {
        Self::profile_generation(host, &pending.profile_id)
    }

    fn profile_generation(
        host: &erebor_interceptor::KernelHost,
        profile_id: &str,
    ) -> Result<Option<u64>> {
        let profile_id = crate::policy::parse_id("profile_id", profile_id)?;
        host.lookup_map(
            "active_profile_generations",
            zerocopy::IntoBytes::as_bytes(&profile_id),
        )
        .context(InterceptorSnafu)?
        .as_deref()
        .map(|bytes| {
            <[u8; 8]>::try_from(bytes)
                .map(u64::from_ne_bytes)
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("the active policy pointer is invalid: {error}"),
                    }
                    .build()
                })
        })
        .transpose()
    }

    fn validate_pending_activation_generation(
        &self,
        pending: &PendingPolicyRecordV1,
        observed: Option<u64>,
    ) -> Result<()> {
        let bundle = self.read_bundle(&self.checked_bundle_file(&pending.bundle_file)?)?;
        let expected_predecessor = match bundle.candidate.operation {
            PolicyDeliveryOperationV1::Activate => {
                ensure!(
                    bundle.candidate.predecessor_candidate_content_id.is_none()
                        && !self.state.active_profiles.contains_key(&pending.profile_id),
                    IdentityStateSnafu {
                        reason: "a root pending policy has an active predecessor",
                    }
                );
                None
            }
            PolicyDeliveryOperationV1::Replace => {
                let predecessor = self.state.active_profiles.get(&pending.profile_id);
                ensure!(
                    bundle.candidate.predecessor_candidate_content_id.is_some()
                        && bundle.candidate.operation == PolicyDeliveryOperationV1::Replace,
                    IdentityStateSnafu {
                        reason: "the pending replacement has no prior desired identity",
                    }
                );
                predecessor.map(|predecessor| predecessor.profile_generation_ref_id)
            }
            PolicyDeliveryOperationV1::RetireToRestrictiveTerminal => {
                let predecessor = self
                    .state
                    .active_profiles
                    .get(&pending.profile_id)
                    .context(IdentityStateSnafu {
                        reason: "a legacy terminal policy has no durable predecessor",
                    })?;
                ensure!(
                    bundle.candidate.predecessor_candidate_content_id.as_deref()
                        == Some(predecessor.candidate_content_id.as_str()),
                    IdentityStateSnafu {
                        reason: "the legacy terminal policy names a different predecessor",
                    }
                );
                Some(predecessor.profile_generation_ref_id)
            }
        };
        ensure!(
            observed == Some(pending.profile_generation_ref_id) || observed == expected_predecessor,
            IdentityStateSnafu {
                reason: "the active policy pointer is neither pending nor its exact predecessor",
            }
        );
        Ok(())
    }

    fn commit_pending_activation_with_proof(
        &mut self,
        config: &NodeConfig,
        active_generation: u64,
        proof: PolicyActivationProofV1,
    ) -> Result<()> {
        let pending = self
            .state
            .pending_activation
            .clone()
            .context(IdentityStateSnafu {
                reason: "physical policy recovery has no durable pending identity",
            })?;
        ensure!(
            active_generation == pending.profile_generation_ref_id && proof.observed_utc_ns > 0,
            IdentityStateSnafu {
                reason: "pending policy recovery lacks exact active-generation proof",
            }
        );
        let bundle_path = self.checked_bundle_file(&pending.bundle_file)?;
        let bundle = self.read_bundle(&bundle_path)?;
        self.commit_activation(
            &bundle,
            &PreparedPolicyActivationV1 {
                config: config.clone(),
                profile_id: pending.profile_id,
                binding_ids: pending.binding_ids,
                profile_generation_ref_id: pending.profile_generation_ref_id,
                staged_utc_ns: pending.staged_utc_ns,
            },
            proof,
        )
    }

    pub(crate) fn pending_acknowledgement(&self) -> Option<PolicyActivationAcknowledgement> {
        let candidate_id = self.state.active_candidate_content_id.as_deref()?;
        if self
            .state
            .control_acknowledged_candidate_content_id
            .as_deref()
            == Some(candidate_id)
        {
            return None;
        }
        let record = self
            .state
            .active_profiles
            .values()
            .find(|record| record.candidate_content_id == candidate_id)?;
        // Replay this proof until Control returns its durable commit index.
        Some(PolicyActivationAcknowledgement {
            tenant_id: record.tenant_id.clone(),
            candidate_content_id: record.candidate_content_id.clone(),
            policy_source_revision_id: record.policy_source_revision_id.clone(),
            target_snapshot_digest: record.target_snapshot_digest.clone(),
            state: "ACTIVE".to_owned(),
            node_bound_generation_digest: record.node_bound_generation_digest.clone(),
            profile_generation_ref_id: record.profile_generation_ref_id,
            readback_digest: record.readback_digest.clone(),
            probe_result_digest: record.probe_result_digest.clone(),
            reason_code: String::new(),
            observed_utc_ns: record.observed_utc_ns,
        })
    }

    pub(crate) fn acknowledge_control(
        &mut self,
        acknowledgement: &PolicyActivationAcknowledgement,
        accepted: &PolicyAcknowledgementAccepted,
    ) -> Result<bool> {
        let candidate_content_id = acknowledgement.candidate_content_id.as_str();
        ensure!(
            accepted.control_commit_index > 0
                && accepted.rollout_state == acknowledgement.state
                && (!accepted.terminal_chain_closure_authorized
                    || acknowledgement.state == "ACTIVE"),
            IdentityStateSnafu {
                reason: "Control returned an invalid policy acknowledgement receipt",
            }
        );
        if acknowledgement.state != "ACTIVE" {
            return Ok(false);
        }
        ensure!(
            self.state.active_candidate_content_id.as_deref() == Some(candidate_content_id),
            IdentityStateSnafu {
                reason: "Control accepted an acknowledgement for a noncurrent active candidate",
            }
        );
        let record = self
            .state
            .active_profiles
            .values()
            .find(|record| record.candidate_content_id == candidate_content_id)
            .context(IdentityStateSnafu {
                reason: "Control accepted a candidate without an active delivery record",
            })?;
        ensure!(
            acknowledgement.tenant_id == record.tenant_id
                && acknowledgement.policy_source_revision_id == record.policy_source_revision_id
                && acknowledgement.target_snapshot_digest == record.target_snapshot_digest
                && acknowledgement.profile_generation_ref_id == record.profile_generation_ref_id
                && acknowledgement.node_bound_generation_digest
                    == record.node_bound_generation_digest
                && acknowledgement.readback_digest == record.readback_digest
                && acknowledgement.probe_result_digest == record.probe_result_digest
                && acknowledgement.observed_utc_ns == record.observed_utc_ns,
            IdentityStateSnafu {
                reason: "Control accepted proof that differs from the durable active policy",
            }
        );
        ensure!(
            !accepted.terminal_chain_closure_authorized,
            IdentityStateSnafu {
                reason: "Control returned obsolete terminal cleanup authority",
            }
        );
        let previous = self.state.clone();
        self.state.control_acknowledged_candidate_content_id =
            Some(candidate_content_id.to_owned());
        self.persist_state_or_restore(previous)?;
        erebor_telemetry::debug!(
            "acknowledged an active policy candidate with Control",
            candidate_id = %candidate_content_id,
            commit_index = %accepted.control_commit_index
        );
        Ok(false)
    }

    pub(crate) fn finish_inventory_retirement(&mut self) -> Result<()> {
        let cleanup = self.retire_inventory_delivery_state()?;
        let transfer = self.load_transfer()?;
        if transfer.bundle_digest == cleanup.bundle_digest {
            self.persist_transfer(&TransferStateV1::default())?;
            remove_directory_if_present(&self.transfer_directory(&cleanup.bundle_digest))?;
        }
        self.remove_unreferenced_bundle_directories()?;
        let previous = self.state.clone();
        self.state.inventory_retirement = None;
        self.persist_state_or_restore(previous)?;
        erebor_telemetry::info!(
            "completed stale policy retirement",
            candidate_id = %cleanup.candidate_content_id,
            profile_id = %cleanup.profile_id
        );
        Ok(())
    }

    fn retire_inventory_delivery_state(&mut self) -> Result<InventoryPolicyRetirementV1> {
        let cleanup = self
            .state
            .inventory_retirement
            .clone()
            .context(IdentityStateSnafu {
                reason: "stale policy retirement has no durable inventory record",
            })?;
        if !cleanup.delivery_state_retired {
            let previous = self.state.clone();
            let record = self
                .state
                .active_profiles
                .get(&cleanup.profile_id)
                .context(IdentityStateSnafu {
                    reason: "stale policy retirement lost its active policy delivery record",
                })?;
            ensure!(
                record.candidate_content_id == cleanup.candidate_content_id
                    && record.bundle_digest == cleanup.bundle_digest
                    && record.profile_generation_ref_id == cleanup.profile_generation_ref_id
                    && record.binding_ids == cleanup.binding_ids,
                IdentityStateSnafu {
                    reason: "stale policy retirement differs from the active policy record",
                }
            );
            self.state.active_profiles.remove(&cleanup.profile_id);
            if self.state.active_candidate_content_id.as_deref()
                == Some(cleanup.candidate_content_id.as_str())
            {
                self.state.active_candidate_content_id = None;
                self.state.active_bundle_digest = None;
                self.state.control_acknowledged_candidate_content_id = None;
            }
            let mut referenced_candidates = self.exception_base_candidate_ids()?;
            referenced_candidates.extend(
                self.state
                    .active_profiles
                    .values()
                    .map(|record| record.candidate_content_id.clone()),
            );
            referenced_candidates.extend(
                self.state
                    .pending_activation
                    .iter()
                    .map(|pending| pending.candidate_content_id.clone()),
            );
            self.state
                .policy_candidate_bundles
                .retain(|candidate, _digest| referenced_candidates.contains(candidate));
            self.state
                .inventory_retirement
                .as_mut()
                .context(IdentityStateSnafu {
                    reason: "stale policy retirement disappeared during delivery retirement",
                })?
                .delivery_state_retired = true;
            // Keep the receipt until cache cleanup completes after this durable state transition.
            self.persist_state_or_restore(previous)?;
        }
        Ok(cleanup)
    }

    fn exception_base_candidate_ids(&self) -> Result<BTreeSet<String>> {
        self.state
            .exception_records
            .values()
            .filter(|record| {
                !matches!(
                    record.state,
                    LocalExceptionStateV1::Rejected | LocalExceptionStateV1::Stale
                )
            })
            .map(|record| {
                self.read_exception_candidate(record)
                    .map(|candidate| candidate.base_candidate_content_id)
            })
            .collect()
    }

    fn remove_unreferenced_bundle_directories(&self) -> Result<()> {
        let referenced = self
            .state
            .active_profiles
            .values()
            .map(|record| record.bundle_digest.as_str())
            .chain(
                self.state
                    .pending_activation
                    .iter()
                    .map(|pending| pending.bundle_digest.as_str()),
            )
            .chain(
                self.state
                    .policy_candidate_bundles
                    .values()
                    .map(String::as_str),
            )
            .collect::<BTreeSet<_>>();
        let bundles = self.root.join("bundles");
        for entry in fs::read_dir(&bundles).context(IoSnafu { path: &bundles })? {
            let entry = entry.context(IoSnafu { path: &bundles })?;
            let name = entry.file_name();
            let Some(digest) = name.to_str() else {
                continue;
            };
            if entry
                .file_type()
                .context(IoSnafu { path: &bundles })?
                .is_dir()
                && is_sha256(digest)
                && !referenced.contains(digest)
            {
                remove_directory_if_present(&entry.path())?;
            }
        }
        Ok(())
    }

    pub(crate) fn record_runtime_binding(
        &mut self,
        binding: &WorkloadBindingConfig,
    ) -> Result<RuntimeBindingRollbackV1> {
        let authority = binding
            .scheduled_binding_authority_id
            .as_deref()
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "runtime binding has no signed scheduled authority".to_owned(),
                }
                .build()
            })?;
        // Keep the prior in-memory state so a failed durable write cannot authorize the runtime.
        let previous = self.state.clone();
        let record = self
            .state
            .active_profiles
            .get_mut(&binding.profile_id)
            .context(IdentityStateSnafu {
                reason: "runtime binding has no active delivered profile",
            })?;
        let stored = record
            .scheduled_bindings
            .iter_mut()
            .find(|stored| stored.scheduled_binding_authority_id.as_deref() == Some(authority))
            .context(IdentityStateSnafu {
                reason: "runtime binding has no durable signed scheduled target",
            })?;
        ensure!(
            stored.scheduled_target_digest == binding.scheduled_target_digest
                && stored.namespace == binding.namespace
                && stored.pod_uid == binding.pod_uid
                && stored.container_name == binding.container_name
                && stored.image_digest == binding.image_digest,
            IdentityStateSnafu {
                reason: "runtime binding differs from its durable scheduled target",
            }
        );
        let old_binding_id = stored.binding_id.clone();
        stored.clone_from(binding);
        if let Some(recorded) = record
            .binding_ids
            .iter_mut()
            .find(|recorded| **recorded == old_binding_id)
        {
            recorded.clone_from(&binding.binding_id);
        }
        record.binding_ids.sort();
        if let Err(error) = self.persist_state() {
            self.state = previous;
            return Err(error);
        }
        Ok(RuntimeBindingRollbackV1 {
            previous,
            profile_id: binding.profile_id.clone(),
            authority_binding_id: authority.to_owned(),
            runtime_binding_id: binding.binding_id.clone(),
        })
    }

    pub(crate) fn retire_runtime_bindings(&mut self, binding_ids: &[String]) -> Result<()> {
        if binding_ids.is_empty() {
            return Ok(());
        }
        let requested = binding_ids.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            requested.len() == binding_ids.len(),
            IdentityStateSnafu {
                reason: "runtime retirement contains a duplicate binding identity",
            }
        );
        let previous = self.state.clone();
        let mut retired = BTreeSet::new();
        for record in self.state.active_profiles.values_mut() {
            for binding in &mut record.scheduled_bindings {
                if !requested.contains(&binding.binding_id) {
                    continue;
                }
                let runtime_binding_id = binding.binding_id.clone();
                let authority =
                    binding
                        .scheduled_binding_authority_id
                        .clone()
                        .context(IdentityStateSnafu {
                            reason: "retired runtime binding has no signed scheduled authority",
                        })?;
                let digest =
                    binding
                        .scheduled_target_digest
                        .clone()
                        .context(IdentityStateSnafu {
                            reason: "retired runtime binding has no signed target digest",
                        })?;
                ensure!(
                    !binding.container_id.starts_with("scheduled:")
                        && binding.root_cgroup_path.is_some()
                        && retired.insert(runtime_binding_id.clone()),
                    IdentityStateSnafu {
                        reason: "runtime retirement does not name one live runtime lifetime",
                    }
                );
                binding.binding_id.clone_from(&authority);
                binding.container_id = format!("scheduled:{digest}");
                binding.sandbox_id = format!("scheduled:{digest}");
                binding.container_generation = 1;
                binding.root_cgroup_path = None;
                binding.lifecycle_generation = 1;
                let recorded = record
                    .binding_ids
                    .iter_mut()
                    .find(|recorded| **recorded == runtime_binding_id)
                    .context(IdentityStateSnafu {
                        reason: "active policy lost its retired runtime binding identity",
                    })?;
                recorded.clone_from(&authority);
            }
            record.binding_ids.sort();
        }
        ensure!(
            retired == requested,
            IdentityStateSnafu {
                reason: "runtime retirement names an unowned or inactive binding",
            }
        );
        if let Err(error) = self.persist_state() {
            self.state = previous;
            return Err(error);
        }
        self.session_inventory = None;
        Ok(())
    }

    pub(crate) fn rollback_runtime_binding(
        &mut self,
        rollback: RuntimeBindingRollbackV1,
    ) -> Result<()> {
        let current = self
            .state
            .active_profiles
            .get(&rollback.profile_id)
            .and_then(|profile| {
                profile.scheduled_bindings.iter().find(|binding| {
                    binding.scheduled_binding_authority_id.as_deref()
                        == Some(rollback.authority_binding_id.as_str())
                })
            });
        ensure!(
            current.is_some_and(|binding| binding.binding_id == rollback.runtime_binding_id),
            IdentityStateSnafu {
                reason: "runtime binding rollback does not name the current durable lifetime",
            }
        );
        // Restore only the state snapshot that immediately preceded this serialized admission.
        let committed = std::mem::replace(&mut self.state, rollback.previous);
        if let Err(error) = self.persist_state() {
            self.state = committed;
            return Err(error);
        }
        Ok(())
    }

    fn validate_inventory(&self, inventory: &PolicyInventory) -> Result<()> {
        ensure!(
            is_sha256(&inventory.candidate_content_id)
                && is_sha256(&inventory.policy_source_revision_id)
                && is_sha256(&inventory.target_snapshot_digest)
                && is_sha256(&inventory.bundle_digest)
                && inventory.bundle_bytes > 0
                && inventory.bundle_bytes
                    <= u64::try_from(MAX_POLICY_BUNDLE_BYTES).unwrap_or(u64::MAX)
                && inventory.chunk_count > 0
                && usize::try_from(inventory.chunk_count).is_ok_and(|count| count
                    <= MAX_POLICY_BUNDLE_BYTES.div_ceil(MAX_POLICY_BUNDLE_CHUNK_BYTES))
                && matches!(inventory.operation.as_str(), "ACTIVATE" | "REPLACE"),
            ControlProtocolSnafu {
                reason: "Control delivered invalid policy inventory",
            }
        );
        Ok(())
    }

    fn validate_desired_inventory(&self, inventory: &PolicyInventory) -> Result<()> {
        if !inventory.desired_inventory_complete {
            return Ok(());
        }
        ensure!(
            inventory.desired_bundle_digests.len() <= MAX_ACTIVE_POLICY_PROFILES
                && inventory
                    .desired_bundle_digests
                    .iter()
                    .all(|digest| is_sha256(digest))
                && inventory
                    .desired_bundle_digests
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            ControlProtocolSnafu {
                reason: "Control delivered an invalid complete desired policy inventory",
            }
        );
        Ok(())
    }

    fn load_transfer(&self) -> Result<TransferStateV1> {
        match fs::read(&self.transfer_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context(JsonSnafu {
                path: &self.transfer_path,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(TransferStateV1::default())
            }
            Err(source) => Err(crate::Error::Io {
                path: self.transfer_path.clone(),
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    fn persist_transfer(&self, transfer: &TransferStateV1) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(transfer).context(JsonSnafu {
            path: &self.transfer_path,
        })?;
        write_atomic(&self.transfer_path, &bytes)
    }

    fn transfer_directory(&self, bundle_digest: &str) -> PathBuf {
        self.root.join("transfers").join(bundle_digest)
    }

    fn transferred_chunk_is_valid(&self, transfer: &TransferStateV1, index: u32) -> bool {
        transfer.chunk_digests.get(&index).is_some_and(|digest| {
            file_sha256(
                &self
                    .transfer_directory(&transfer.bundle_digest)
                    .join(format!("{index:08}.chunk")),
            )
            .as_deref()
                == Some(digest)
        })
    }

    fn assemble_transfer(&self, transfer: &TransferStateV1) -> Result<Vec<u8>> {
        ensure!(
            transfer.chunk_count > 0
                && transfer.chunk_digests.len()
                    == usize::try_from(transfer.chunk_count).unwrap_or(usize::MAX),
            ControlProtocolSnafu {
                reason: "the policy transfer is incomplete",
            }
        );
        // Read every chunk again before assembly; transfer metadata alone is not proof.
        let mut bytes = Vec::with_capacity(
            usize::try_from(transfer.bundle_bytes).unwrap_or(MAX_POLICY_BUNDLE_BYTES),
        );
        for index in 0..transfer.chunk_count {
            ensure!(
                self.transferred_chunk_is_valid(transfer, index),
                ControlProtocolSnafu {
                    reason: "a durable policy chunk failed exact digest readback",
                }
            );
            let path = self
                .transfer_directory(&transfer.bundle_digest)
                .join(format!("{index:08}.chunk"));
            bytes.extend(fs::read(&path).context(IoSnafu { path: &path })?);
        }
        ensure!(
            bytes.len() == usize::try_from(transfer.bundle_bytes).unwrap_or(usize::MAX)
                && bytes.len() <= MAX_POLICY_BUNDLE_BYTES,
            ControlProtocolSnafu {
                reason: "the assembled policy bundle has an invalid size",
            }
        );
        Ok(bytes)
    }

    fn persist_state(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.state).context(JsonSnafu {
            path: &self.state_path,
        })?;
        write_atomic(&self.state_path, &bytes)
    }

    fn persist_state_or_restore(&mut self, previous: PolicyDeliveryStateV1) -> Result<()> {
        if let Err(error) = self.persist_state() {
            self.state = previous;
            return Err(error);
        }
        Ok(())
    }

    fn validate_state(&self) -> Result<()> {
        ensure!(
            self.state.active_profiles.len() <= MAX_ACTIVE_POLICY_PROFILES
                && self
                    .state
                    .active_profiles
                    .iter()
                    .all(|(profile_id, record)| {
                        uuid::Uuid::parse_str(profile_id)
                            .is_ok_and(|id| id.hyphenated().to_string() == *profile_id)
                            && uuid::Uuid::parse_str(&record.tenant_id)
                                .is_ok_and(|id| id.hyphenated().to_string() == record.tenant_id)
                            && is_sha256(&record.candidate_content_id)
                            && is_sha256(&record.policy_source_revision_id)
                            && is_sha256(&record.target_snapshot_digest)
                            && is_sha256(&record.bundle_digest)
                            && record.profile_generation_ref_id > 0
                            && record.staged_utc_ns >= 0
                            && !record.binding_ids.is_empty()
                            && record.binding_ids.windows(2).all(|pair| pair[0] < pair[1])
                            && is_sha256(&record.node_bound_generation_digest)
                            && is_sha256(&record.readback_digest)
                            && is_sha256(&record.probe_result_digest)
                            && record.observed_utc_ns > 0
                    })
                && self
                    .state
                    .pending_activation
                    .as_ref()
                    .is_none_or(|pending| {
                        let legacy_identity = pending.tenant_id.is_empty()
                            && pending.policy_source_revision_id.is_empty()
                            && pending.target_snapshot_digest.is_empty();
                        let complete_identity = uuid::Uuid::parse_str(&pending.tenant_id)
                            .is_ok_and(|id| id.hyphenated().to_string() == pending.tenant_id)
                            && is_sha256(&pending.policy_source_revision_id)
                            && is_sha256(&pending.target_snapshot_digest);
                        (legacy_identity || complete_identity)
                            && is_sha256(&pending.candidate_content_id)
                            && is_sha256(&pending.bundle_digest)
                            && uuid::Uuid::parse_str(&pending.profile_id)
                                .is_ok_and(|id| id.hyphenated().to_string() == pending.profile_id)
                            && pending.profile_generation_ref_id > 0
                            && pending.staged_utc_ns >= 0
                            && !pending.binding_ids.is_empty()
                            && pending.binding_ids.windows(2).all(|pair| pair[0] < pair[1])
                            && !pending.bundle_file.is_empty()
                    })
                && self.state.policy_candidate_bundles.iter().all(
                    |(candidate_content_id, bundle_digest)| {
                        is_sha256(candidate_content_id) && is_sha256(bundle_digest)
                    }
                )
                && self
                    .state
                    .exception_records
                    .iter()
                    .all(|(instance_id, record)| {
                        let legacy_pending_identity = record.state
                            == LocalExceptionStateV1::Pending
                            && record.tenant_id.is_empty()
                            && record.exception_source_revision_id.is_empty();
                        let complete_ack_identity = uuid::Uuid::parse_str(&record.tenant_id)
                            .is_ok_and(|id| id.hyphenated().to_string() == record.tenant_id)
                            && is_sha256(&record.exception_source_revision_id);
                        let legacy_physical_identity = record.profile_generation_ref_id == 0
                            && record.grant_handle == 0
                            && record.valid_until_utc_ns == 0;
                        let complete_physical_identity = record.profile_generation_ref_id > 0
                            && record.grant_handle > 0
                            && record.valid_until_utc_ns > 0;
                        uuid::Uuid::parse_str(instance_id)
                            .is_ok_and(|id| id.hyphenated().to_string() == *instance_id)
                            && (legacy_pending_identity || complete_ack_identity)
                            && (legacy_physical_identity || complete_physical_identity)
                            && is_sha256(&record.candidate_content_id)
                            && !record.candidate_file.is_empty()
                            && record.observed_utc_ns > 0
                            && match record.state {
                                LocalExceptionStateV1::Pending => record.transition_version == 0,
                                _ => record.transition_version > 0,
                            }
                            && (record.report_to_control
                                || matches!(
                                    record.state,
                                    LocalExceptionStateV1::Consumed
                                        | LocalExceptionStateV1::Revoked
                                ))
                    })
                && self.state.exception_distribution_high_water.iter().all(
                    |(instance_id, sequence)| {
                        uuid::Uuid::parse_str(instance_id)
                            .is_ok_and(|id| id.hyphenated().to_string() == *instance_id)
                            && sequence.epoch > 0
                            && sequence.sequence > 0
                    }
                ),
            IdentityStateSnafu {
                reason: "the durable policy delivery state is invalid",
            }
        );
        ensure!(
            self.state.exception_records.len()
                <= usize::try_from(EXCEPTION_USE_RECEIPT_CAPACITY).unwrap_or(usize::MAX),
            IdentityStateSnafu {
                reason: "the durable exception record capacity is invalid",
            }
        );
        ensure!(
            self.state
                .exception_records
                .values()
                .filter(|record| record.state == LocalExceptionStateV1::Pending)
                .count()
                <= 1,
            IdentityStateSnafu {
                reason: "durable exception delivery has more than one pending candidate",
            }
        );
        if let Some(cleanup) = self.state.inventory_retirement.as_ref() {
            let valid_identity = is_sha256(&cleanup.candidate_content_id)
                && uuid::Uuid::parse_str(&cleanup.profile_id)
                    .is_ok_and(|id| id.hyphenated().to_string() == cleanup.profile_id)
                && is_sha256(&cleanup.bundle_digest)
                && cleanup.profile_generation_ref_id > 0
                && !cleanup.binding_ids.is_empty()
                && cleanup.binding_ids.windows(2).all(|pair| pair[0] < pair[1]);
            let active_matches = self
                .state
                .active_profiles
                .get(&cleanup.profile_id)
                .is_some_and(|record| {
                    record.candidate_content_id == cleanup.candidate_content_id
                        && record.bundle_digest == cleanup.bundle_digest
                        && record.profile_generation_ref_id == cleanup.profile_generation_ref_id
                        && record.binding_ids == cleanup.binding_ids
                });
            ensure!(
                valid_identity
                    && if cleanup.delivery_state_retired {
                        !self.state.active_profiles.contains_key(&cleanup.profile_id)
                    } else {
                        active_matches
                    },
                IdentityStateSnafu {
                    reason: "the durable stale policy retirement record is invalid",
                }
            );
        }
        // Rejected records keep ACK identity separately because their candidate bytes can be bad.
        for record in self.state.exception_records.values().filter(|record| {
            !matches!(
                record.state,
                LocalExceptionStateV1::Pending
                    | LocalExceptionStateV1::Rejected
                    | LocalExceptionStateV1::Stale
            )
        }) {
            self.read_exception_candidate(record)?;
        }
        Ok(())
    }

    fn relative_bundle_file(&self, path: &Path) -> Result<String> {
        path.strip_prefix(&self.root)
            .ok()
            .and_then(Path::to_str)
            .filter(|value| !value.is_empty() && !value.split('/').any(|part| part == ".."))
            .map(str::to_owned)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "the policy cache path escapes its state directory".to_owned(),
                }
                .build()
            })
    }

    fn checked_bundle_file(&self, relative: &str) -> Result<PathBuf> {
        ensure!(
            !relative.is_empty()
                && !Path::new(relative).is_absolute()
                && !relative.split('/').any(|part| part == ".."),
            IdentityStateSnafu {
                reason: "the policy cache contains an unsafe relative path",
            }
        );
        Ok(self.root.join(relative))
    }

    fn read_bundle(&self, path: &Path) -> Result<PolicyBundleV1> {
        serde_json::from_slice(&fs::read(path).context(IoSnafu { path })?)
            .context(JsonSnafu { path })
    }

    fn policy_bundle_for_candidate(&self, candidate_content_id: &str) -> Result<PolicyBundleV1> {
        let bundle_digest = self
            .state
            .policy_candidate_bundles
            .get(candidate_content_id)
            .cloned()
            .or_else(|| {
                self.state
                    .active_profiles
                    .values()
                    .find(|record| record.candidate_content_id == candidate_content_id)
                    .map(|record| record.bundle_digest.clone())
            })
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "the exception candidate has no durable base-policy bundle".to_owned(),
                }
                .build()
            })?;
        let bundle = self.read_bundle(
            &self
                .root
                .join("bundles")
                .join(bundle_digest)
                .join("bundle.json"),
        )?;
        ensure!(
            bundle.candidate.candidate_content_id == candidate_content_id,
            IdentityStateSnafu {
                reason: "the durable base-policy index names a different candidate",
            }
        );
        Ok(bundle)
    }

    fn read_exception_candidate(
        &self,
        record: &ExceptionDeliveryRecordV1,
    ) -> Result<ExceptionDeliveryCandidateV1> {
        let path = self.checked_bundle_file(&record.candidate_file)?;
        let candidate: ExceptionDeliveryCandidateV1 =
            serde_json::from_slice(&fs::read(&path).context(IoSnafu { path: &path })?)
                .context(JsonSnafu { path: &path })?;
        ensure!(
            candidate.candidate_content_id == record.candidate_content_id
                && candidate.operation == record.operation,
            IdentityStateSnafu {
                reason: "the durable exception record differs from its signed candidate",
            }
        );
        Ok(candidate)
    }

    fn hydrate_pending_policy_ack_identity(
        &mut self,
        pending: &PendingPolicyRecordV1,
        bundle: &PolicyBundleV1,
    ) -> Result<()> {
        if !pending.tenant_id.is_empty() {
            return Ok(());
        }
        let stored = self
            .state
            .pending_activation
            .as_mut()
            .context(IdentityStateSnafu {
                reason: "the pending policy record disappeared during recovery",
            })?;
        stored.tenant_id.clone_from(&bundle.candidate.tenant_id);
        stored
            .policy_source_revision_id
            .clone_from(&bundle.candidate.policy_source_revision_id);
        stored
            .target_snapshot_digest
            .clone_from(&bundle.candidate.target_snapshot_digest);
        self.persist_state()
    }

    fn retire_old_session_active_profile(
        &mut self,
        profile_id: &str,
        record: &ActivePolicyRecordV1,
        observed_generation: Option<u64>,
        generation_rows_absent: bool,
    ) -> Result<()> {
        ensure!(
            observed_generation.is_none() && generation_rows_absent,
            IdentityStateSnafu {
                reason: "an old-session active policy still has a live pointer or generation row",
            }
        );
        self.state.active_profiles.remove(profile_id);
        if self.state.active_candidate_content_id.as_deref()
            == Some(record.candidate_content_id.as_str())
        {
            self.state.active_candidate_content_id = None;
            self.state.active_bundle_digest = None;
            self.state.control_acknowledged_candidate_content_id = None;
        }
        // The source high-water stays durable while session-bound authority is retired.
        self.persist_state()
    }

    pub(crate) fn reconcile_old_session_delivery(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<()> {
        let session = Some((node_boot_id, label_epoch));
        self.retire_old_session_exceptions(host, trust, config, node_boot_id, label_epoch)?;

        for (profile_id, record) in self.state.active_profiles.clone() {
            if self
                .state
                .inventory_retirement
                .as_ref()
                .is_some_and(|cleanup| cleanup.profile_id == profile_id)
            {
                // Inventory retirement owns this record until exact kernel absence is durable.
                continue;
            }
            let bundle = self.read_bundle(
                &self
                    .root
                    .join("bundles")
                    .join(&record.bundle_digest)
                    .join("bundle.json"),
            )?;
            let key = trust.policy_signing_key(
                &bundle.candidate.signing_key_id,
                bundle.profile_artifact.header.sequence_epoch,
            )?;
            bundle
                .verify(
                    &key,
                    &config.node_id,
                    if record.staged_utc_ns == 0 {
                        bundle.candidate.issued_utc_ns
                    } else {
                        record.staged_utc_ns
                    },
                )
                .context(PolicySnafu)?;
            if scheduled_session_state(&bundle, config, session)? != Some(false) {
                continue;
            }
            ensure!(
                scheduled_record_is_exclusive(&record.binding_ids, &record.scheduled_bindings),
                IdentityStateSnafu {
                    reason: "an old-session active policy mixes scheduled and static ownership",
                }
            );
            let observed = Self::profile_generation(host, &profile_id)?;
            let rows_absent = crate::policy::generation_publication_is_absent(
                host,
                record.profile_generation_ref_id,
            )?;
            self.retire_old_session_active_profile(&profile_id, &record, observed, rows_absent)?;
        }

        if let Some(pending) = self.state.pending_activation.clone() {
            let bundle = self.read_bundle(&self.checked_bundle_file(&pending.bundle_file)?)?;
            self.verify_pending_bundle(&pending, &bundle, trust, config)?;
            if scheduled_session_state(&bundle, config, session)? == Some(false) {
                ensure!(
                    scheduled_record_is_exclusive(
                        &pending.binding_ids,
                        &pending.scheduled_bindings,
                    ),
                    IdentityStateSnafu {
                        reason:
                            "an old-session pending policy mixes scheduled and static ownership",
                    }
                );
                let observed = Self::profile_generation(host, &pending.profile_id)?;
                let rows_absent = crate::policy::generation_publication_is_absent(
                    host,
                    pending.profile_generation_ref_id,
                )?;
                self.retire_old_session_pending_policy(&bundle, observed, rows_absent)?;
            }
        }
        Ok(())
    }

    fn retire_old_session_exceptions(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        trust: &TrustCache,
        config: &NodeConfig,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<()> {
        let records = self
            .state
            .exception_records
            .iter()
            .filter(|(_, record)| {
                matches!(
                    record.state,
                    LocalExceptionStateV1::Pending | LocalExceptionStateV1::Active
                )
            })
            .map(|(instance_id, record)| (instance_id.clone(), record.clone()))
            .collect::<Vec<_>>();
        for (instance_id, record) in records {
            let candidate = self.read_exception_candidate(&record)?;
            let prepared = self.verify_stored_exception_candidate(
                &instance_id,
                &record,
                candidate.clone(),
                trust,
                config,
            )?;
            self.restore_exception_recovery_identity(&instance_id, &candidate, &prepared)?;
            let identity =
                candidate
                    .exact_target
                    .kubernetes
                    .as_ref()
                    .context(IdentityStateSnafu {
                        reason: "stored exception recovery has no Kubernetes identity",
                    })?;
            let signed_boot_id = hex::decode(&identity.node_boot_id).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("stored exception recovery has an invalid boot ID: {error}"),
                }
                .build()
            })?;
            if signed_boot_id == node_boot_id && identity.label_epoch == label_epoch {
                continue;
            }

            let stored = self
                .state
                .exception_records
                .get(&instance_id)
                .context(IdentityStateSnafu {
                    reason: "the old-session exception disappeared during recovery",
                })?
                .clone();
            let runtime_key = ExceptionRuntimeStateKeyV1 {
                node_id: crate::policy::stable_node_id(&config.node_id)?,
                exception_instance_id: crate::policy::parse_id(
                    "exception_instance_id",
                    &instance_id,
                )?,
            };
            let binding_key = ExceptionHandleBindingKeyV1 {
                profile_generation_ref_id: stored.profile_generation_ref_id,
                exception_numeric_handle: stored.grant_handle,
                reserved: 0,
            };
            let runtime_present = host
                .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                .context(InterceptorSnafu)?
                .is_some();
            let binding_present = host
                .lookup_map("exception_handle_bindings", binding_key.as_bytes())
                .context(InterceptorSnafu)?
                .is_some();
            self.settle_old_session_exception(
                &instance_id,
                &candidate,
                runtime_present,
                binding_present,
                crate::policy::current_utc_ns()?,
            )?;
        }
        Ok(())
    }

    fn verify_stored_exception_candidate(
        &self,
        instance_id: &str,
        record: &ExceptionDeliveryRecordV1,
        candidate: ExceptionDeliveryCandidateV1,
        trust: &TrustCache,
        config: &NodeConfig,
    ) -> Result<PreparedExceptionDeliveryV1> {
        let base_bundle = self.policy_bundle_for_candidate(&candidate.base_candidate_content_id)?;
        let trusted_key = trust.policy_signing_key(
            &candidate.signing_key_id,
            base_bundle.profile_artifact.header.sequence_epoch,
        )?;
        candidate
            .verify(&trusted_key, &config.node_id, candidate.issued_utc_ns)
            .context(PolicySnafu)?;
        let grant = base_bundle
            .profile_artifact
            .policy_document
            .file_exception_grants
            .iter()
            .find(|grant| grant.grant_id == candidate.grant_id)
            .context(IdentityStateSnafu {
                reason: "the stored exception has no signed base-policy grant",
            })?;
        let requested_duration = candidate
            .valid_until_utc_ns
            .saturating_sub(candidate.issued_utc_ns);
        let expected_node_name =
            config
                .kubernetes_node_name
                .as_deref()
                .context(IdentityStateSnafu {
                    reason: "stored exception recovery needs the Kubernetes Node name",
                })?;
        let tenant_id = config
            .evidence
            .as_ref()
            .map(|evidence| evidence.tenant_id.as_str())
            .unwrap_or_default();
        ensure!(
            candidate.exception_instance_id == instance_id
                && record.candidate_content_id == candidate.candidate_content_id
                && record.operation == candidate.operation
                && candidate.tenant_id == tenant_id
                && candidate.tenant_id == base_bundle.candidate.tenant_id
                && candidate.base_policy_source_revision_id
                    == base_bundle.candidate.policy_source_revision_id
                && candidate.profile_id
                    == base_bundle
                        .profile_artifact
                        .policy_document
                        .metadata
                        .profile_id
                && base_bundle
                    .candidate
                    .exact_target
                    .workload_targets
                    .contains(&candidate.exact_target)
                && candidate.exact_target.node_id == config.node_id
                && candidate
                    .exact_target
                    .kubernetes
                    .as_ref()
                    .is_some_and(|identity| identity.kubernetes_node_name == expected_node_name)
                && candidate.maximum_uses <= grant.maximum_uses
                && (candidate.operation == ExceptionDeliveryOperationV1::Revoke
                    || u64::try_from(requested_duration)
                        .is_ok_and(|duration| duration <= grant.maximum_duration_ns))
                && (record.state == LocalExceptionStateV1::Pending
                    || (record.state == LocalExceptionStateV1::Active
                        && candidate.operation == ExceptionDeliveryOperationV1::Activate)),
            IdentityStateSnafu {
                reason: "the stored exception differs from its signed base-policy authority",
            }
        );
        Ok(PreparedExceptionDeliveryV1 {
            grant_handle: exception_grant_handle(
                &base_bundle.profile_artifact.policy_document,
                &candidate.grant_id,
            )?,
            candidate,
        })
    }

    fn settle_old_session_exception(
        &mut self,
        instance_id: &str,
        candidate: &ExceptionDeliveryCandidateV1,
        runtime_present: bool,
        binding_present: bool,
        observed_utc_ns: i64,
    ) -> Result<()> {
        ensure!(
            !runtime_present && !binding_present,
            IdentityStateSnafu {
                reason: "an old-session exception still has live physical authority",
            }
        );
        let stored =
            self.state
                .exception_records
                .get_mut(instance_id)
                .context(IdentityStateSnafu {
                    reason: "the old-session exception disappeared before retirement",
                })?;
        ensure!(
            matches!(
                stored.state,
                LocalExceptionStateV1::Pending | LocalExceptionStateV1::Active
            ) && stored.operation == candidate.operation
                && observed_utc_ns > 0,
            IdentityStateSnafu {
                reason: "the old-session exception retirement identity is invalid",
            }
        );
        stored.state = match (
            candidate.operation,
            candidate.valid_until_utc_ns <= observed_utc_ns,
        ) {
            (ExceptionDeliveryOperationV1::Activate, false) => {
                stored.consumed_uses = candidate.maximum_uses;
                LocalExceptionStateV1::Consumed
            }
            (ExceptionDeliveryOperationV1::Activate, true) => LocalExceptionStateV1::Expired,
            (ExceptionDeliveryOperationV1::Revoke, _) => LocalExceptionStateV1::Revoked,
        };
        stored.transition_version =
            stored
                .transition_version
                .checked_add(1)
                .context(IdentityStateSnafu {
                    reason: "old-session exception transition version exhausted",
                })?;
        stored.observed_utc_ns = observed_utc_ns;
        stored.control_acknowledged = false;
        stored.report_to_control = false;
        // This tombstone preserves replay and use state without crossing node sessions.
        self.persist_state()
    }

    fn retire_old_session_pending_policy(
        &mut self,
        bundle: &PolicyBundleV1,
        observed_generation: Option<u64>,
        generation_rows_absent: bool,
    ) -> Result<()> {
        ensure!(
            observed_generation.is_none() && generation_rows_absent,
            IdentityStateSnafu {
                reason: "an old-session pending policy still has a live pointer or generation row",
            }
        );
        advance_sequence(
            &mut self.state.issuer_high_water,
            bundle.candidate.signing_key_id.clone(),
            SequenceV1 {
                epoch: bundle.profile_artifact.header.sequence_epoch,
                sequence: bundle.profile_artifact.header.issuer_sequence,
            },
        );
        advance_sequence(
            &mut self.state.distribution_high_water,
            bundle.profile_artifact.header.profile_id.clone(),
            SequenceV1 {
                epoch: bundle.candidate.distribution_sequence_epoch,
                sequence: bundle.candidate.distribution_sequence,
            },
        );
        self.state.pending_activation = None;
        // Control must issue a fresh chain for the current node session.
        self.persist_state()
    }

    fn verify_pending_bundle(
        &self,
        pending: &PendingPolicyRecordV1,
        bundle: &PolicyBundleV1,
        trust: &TrustCache,
        config: &NodeConfig,
    ) -> Result<()> {
        let key = trust.policy_signing_key(
            &bundle.candidate.signing_key_id,
            bundle.profile_artifact.header.sequence_epoch,
        )?;
        bundle
            .verify(
                &key,
                &config.node_id,
                if pending.staged_utc_ns == 0 {
                    bundle.candidate.issued_utc_ns
                } else {
                    pending.staged_utc_ns
                },
            )
            .context(PolicySnafu)?;
        ensure!(
            pending.candidate_content_id == bundle.candidate.candidate_content_id
                && (pending.tenant_id.is_empty()
                    || (pending.tenant_id == bundle.candidate.tenant_id
                        && pending.policy_source_revision_id
                            == bundle.candidate.policy_source_revision_id
                        && pending.target_snapshot_digest
                            == bundle.candidate.target_snapshot_digest))
                && pending.bundle_digest == bundle.bundle_digest
                && pending.profile_id == bundle.profile_artifact.header.profile_id
                && key.to_bytes().as_slice() == bundle.profile_signing_public_key.as_slice(),
            IdentityStateSnafu {
                reason: "the pending policy record differs from its verified bundle",
            }
        );
        Ok(())
    }
}

pub fn policy_delivery_status(state_directory: &Path) -> Result<PolicyDeliveryStatusV1> {
    NodePolicyDeliveryOwner::load(state_directory)?.inspection_status()
}

fn materialize_scheduled_bindings(
    bundle: &PolicyBundleV1,
    config: &mut NodeConfig,
    profile_generation_ref_id: u64,
    session: Option<(&[u8], u64)>,
) -> Result<BTreeMap<String, String>> {
    let targets = &bundle.candidate.exact_target.workload_targets;
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let (node_boot_id, label_epoch) = session.ok_or_else(|| {
        ControlProtocolSnafu {
            reason: "scheduled Kubernetes policy needs the current node session".to_owned(),
        }
        .build()
    })?;
    let expected_boot_id = hex::encode(node_boot_id);
    let expected_node_name = config.kubernetes_node_name.as_deref().ok_or_else(|| {
        ControlProtocolSnafu {
            reason: "scheduled Kubernetes policy needs the registered Kubernetes Node name"
                .to_owned(),
        }
        .build()
    })?;
    let document = &bundle.profile_artifact.policy_document;
    // Preserve an admitted container lifetime across policy refresh for the same signed target.
    let previous = config
        .workload_bindings
        .iter()
        .filter(|binding| {
            binding.profile_id == document.metadata.profile_id
                && binding.scheduled_binding_authority_id.is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    config.workload_bindings.retain(|binding| {
        binding.profile_id != document.metadata.profile_id
            || binding.scheduled_binding_authority_id.is_none()
    });
    let mut materialized = BTreeMap::new();
    for target in targets {
        let identity = target.kubernetes.as_ref().ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "scheduled policy target has no Kubernetes identity".to_owned(),
            }
            .build()
        })?;
        // Retirement can name the previous source; all other operations name the current source.
        ensure!(
            mithril_control::workload_target_fact_digest(target)
                .is_ok_and(|digest| digest == target.workload_binding_generation_digest)
                && target.node_id == config.node_id
                && identity.profile_id == document.metadata.profile_id
                && identity.kubernetes_node_name == expected_node_name
                && identity.node_boot_id == expected_boot_id
                && identity.label_epoch == label_epoch
                && (identity.policy_source_revision_id
                    == bundle.candidate.policy_source_revision_id
                    || bundle.candidate.operation
                        == PolicyDeliveryOperationV1::RetireToRestrictiveTerminal),
            ControlProtocolSnafu {
                reason: "scheduled policy target does not match this node session and candidate",
            }
        );
        let initial_role_id = entry_role_handle(
            document,
            &identity.workload_selector_id,
            target.container_kind,
            EntryKindV1::ContainerStart,
        )?;
        let external_role_id = entry_role_handle(
            document,
            &identity.workload_selector_id,
            target.container_kind,
            EntryKindV1::ExternalRuntimeUnknown,
        )?;
        let prior = previous.iter().find(|existing| {
            existing.scheduled_binding_authority_id.as_deref() == Some(identity.binding_id.as_str())
                && existing.profile_id == identity.profile_id
                && existing.namespace == identity.namespace_name
                && existing.pod_uid == target.pod_uid
                && existing.container_name == target.container_name
                && existing.image_digest == target.image_digest
        });
        let mut binding = crate::WorkloadBindingConfig {
            binding_id: identity.binding_id.clone(),
            scheduled_binding_authority_id: Some(identity.binding_id.clone()),
            scheduled_target_digest: Some(target.workload_binding_generation_digest.clone()),
            execution_set_id: target.execution_set_id.clone(),
            protected_scope_id: identity.protected_scope_id.clone(),
            workload_selector_id: identity.workload_selector_id.clone(),
            profile_id: identity.profile_id.clone(),
            container_id: target.container_id.clone(),
            namespace: identity.namespace_name.clone(),
            cluster_uid: target.cluster_uid.clone(),
            namespace_uid: target.namespace_uid.clone(),
            controller_uid: target.controller_uid.clone(),
            service_account_uid: target.service_account_uid.clone(),
            pod_labels: target.pod_labels.clone(),
            pod_uid: target.pod_uid.clone(),
            sandbox_id: format!("scheduled:{}", target.workload_binding_generation_digest),
            container_name: target.container_name.clone(),
            image_digest: target.image_digest.clone(),
            container_kind: node_container_kind(target.container_kind),
            container_generation: 1,
            root_cgroup_path: None,
            lifecycle_generation: 1,
            active_profile_generation_ref_id: profile_generation_ref_id,
            initial_role_id,
            external_role_id,
            arm_initial_root: true,
        };
        // A policy refresh keeps the current runtime lifetime. Only runtime
        // admission can replace it with a new container identity.
        if let Some(existing) = prior {
            ensure!(
                existing.profile_id == binding.profile_id
                    && existing.execution_set_id == binding.execution_set_id
                    && existing.protected_scope_id == binding.protected_scope_id
                    && existing.workload_selector_id == binding.workload_selector_id
                    && existing.namespace == binding.namespace
                    && existing.pod_uid == binding.pod_uid
                    && existing.container_name == binding.container_name
                    && existing.image_digest == binding.image_digest,
                ControlProtocolSnafu {
                    reason: "scheduled policy target conflicts with its existing local binding",
                }
            );
            if !existing.container_id.starts_with("scheduled:") {
                ensure!(
                    existing.binding_id
                        == crate::runtime_admission::ScheduledRuntimeBindingV1::runtime_binding_id(
                            &identity.binding_id,
                            &existing.container_id,
                        ),
                    ControlProtocolSnafu {
                        reason: "scheduled runtime binding is not derived from signed authority",
                    }
                );
                binding.binding_id = existing.binding_id.clone();
            }
            binding.container_id = existing.container_id.clone();
            binding.sandbox_id = existing.sandbox_id.clone();
            binding.container_generation = existing.container_generation;
            binding.root_cgroup_path = existing.root_cgroup_path.clone();
            binding.lifecycle_generation = existing.lifecycle_generation;
        }
        binding.active_profile_generation_ref_id = profile_generation_ref_id;
        config.workload_bindings.push(binding.clone());
        ensure!(
            materialized
                .insert(
                    target.workload_binding_generation_digest.clone(),
                    binding.binding_id,
                )
                .is_none(),
            ControlProtocolSnafu {
                reason: "scheduled policy target digest occurs more than once",
            }
        );
    }
    config.validate()?;
    Ok(materialized)
}

fn prepared_scheduled_bindings(
    prepared: &PreparedPolicyActivationV1,
) -> Vec<WorkloadBindingConfig> {
    let selected = prepared.binding_ids.iter().collect::<BTreeSet<_>>();
    let mut bindings = prepared
        .config
        .workload_bindings
        .iter()
        .filter(|binding| {
            binding.scheduled_binding_authority_id.is_some()
                && selected.contains(&binding.binding_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| left.binding_id.cmp(&right.binding_id));
    bindings
}

fn scheduled_record_is_exclusive(
    binding_ids: &[String],
    scheduled_bindings: &[WorkloadBindingConfig],
) -> bool {
    let scheduled_ids = scheduled_bindings
        .iter()
        .map(|binding| binding.binding_id.as_str())
        .collect::<BTreeSet<_>>();
    binding_ids.len() == scheduled_ids.len()
        && binding_ids
            .iter()
            .all(|binding_id| scheduled_ids.contains(binding_id.as_str()))
}

fn advance_sequence(target: &mut BTreeMap<String, SequenceV1>, key: String, value: SequenceV1) {
    target
        .entry(key)
        .and_modify(|current| *current = (*current).max(value))
        .or_insert(value);
}

fn scheduled_session_state(
    bundle: &PolicyBundleV1,
    config: &NodeConfig,
    session: Option<(&[u8], u64)>,
) -> Result<Option<bool>> {
    let targets = &bundle.candidate.exact_target.workload_targets;
    if targets.is_empty() {
        return Ok(None);
    }
    let Some((node_boot_id, label_epoch)) = session else {
        return Ok(None);
    };
    let node_name = config
        .kubernetes_node_name
        .as_deref()
        .context(IdentityStateSnafu {
            reason: "scheduled policy recovery has no Kubernetes Node name",
        })?;
    let boot_id = hex::encode(node_boot_id);
    let current = targets
        .iter()
        .map(|target| {
            let identity = target.kubernetes.as_ref().context(IdentityStateSnafu {
                reason: "scheduled policy recovery has a non-Kubernetes target",
            })?;
            ensure!(
                target.node_id == config.node_id && identity.kubernetes_node_name == node_name,
                IdentityStateSnafu {
                    reason: "scheduled policy recovery targets another node identity",
                }
            );
            Ok(identity.node_boot_id == boot_id && identity.label_epoch == label_epoch)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        current.iter().all(|matches| *matches) || current.iter().all(|matches| !*matches),
        IdentityStateSnafu {
            reason: "scheduled policy recovery mixes current and old node sessions",
        }
    );
    Ok(Some(current[0]))
}

fn entry_role_handle(
    document: &mithril_control::PolicyDocumentV1,
    workload_selector_id: &str,
    container_kind: mithril_control::ContainerKindV1,
    entry_kind: EntryKindV1,
) -> Result<u32> {
    let role_ids = document
        .entry_role_assignments
        .iter()
        .filter(|assignment| {
            assignment
                .workload_selector_ids
                .iter()
                .any(|selector| selector == workload_selector_id)
                && assignment.entry_kinds.contains(&entry_kind)
                && assignment.container_kinds.contains(&container_kind)
        })
        .map(|assignment| assignment.resulting_role_id.as_str())
        .collect::<BTreeSet<_>>();
    // One exact role is required because runtime admission cannot resolve role ambiguity.
    ensure!(
        role_ids.len() == 1,
        ControlProtocolSnafu {
            reason: format!(
                "scheduled binding needs one exact signed {entry_kind:?} role assignment"
            ),
        }
    );
    let role_id = role_ids.iter().next().copied().ok_or_else(|| {
        ControlProtocolSnafu {
            reason: "scheduled binding lost its signed role assignment".to_owned(),
        }
        .build()
    })?;
    document
        .roles
        .iter()
        .map(|role| role.role_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .position(|candidate| candidate == role_id)
        .and_then(|index| u32::try_from(index + 1).ok())
        .ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "scheduled binding role has no numeric handle".to_owned(),
            }
            .build()
        })
}

const fn node_container_kind(kind: mithril_control::ContainerKindV1) -> crate::ContainerKindV1 {
    match kind {
        mithril_control::ContainerKindV1::Init => crate::ContainerKindV1::Init,
        mithril_control::ContainerKindV1::Sidecar => crate::ContainerKindV1::Sidecar,
        mithril_control::ContainerKindV1::Application => crate::ContainerKindV1::Application,
        mithril_control::ContainerKindV1::Ephemeral => crate::ContainerKindV1::Ephemeral,
    }
}

const fn policy_delivery_operation_name(operation: PolicyDeliveryOperationV1) -> &'static str {
    match operation {
        PolicyDeliveryOperationV1::Activate => "ACTIVATE",
        PolicyDeliveryOperationV1::Replace => "REPLACE",
        PolicyDeliveryOperationV1::RetireToRestrictiveTerminal => "RETIRE_TO_RESTRICTIVE_TERMINAL",
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        IdentityStateSnafu {
            reason: "the policy state path has no parent".to_owned(),
        }
        .build()
    })?;
    fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
    let temporary = path.with_extension("next");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .context(IoSnafu { path: &temporary })?;
    file.write_all(bytes)
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    // Rename publishes complete bytes; parent fsync makes the new directory entry durable.
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    File::open(parent)
        .context(IoSnafu { path: parent })?
        .sync_all()
        .context(IoSnafu { path: parent })
}

fn remove_directory_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(crate::Error::Io {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        }),
    }
}

fn file_sha256(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| sha256(&bytes))
}

fn exception_grant_handle(
    document: &mithril_control::PolicyDocumentV1,
    grant_id: &str,
) -> Result<u32> {
    let identifiers = document
        .exceptions
        .iter()
        .map(|exception| exception.exception_id.as_str())
        .chain(
            document
                .file_exception_grants
                .iter()
                .map(|grant| grant.grant_id.as_str()),
        )
        .collect::<BTreeSet<_>>();
    identifiers
        .into_iter()
        .position(|identifier| identifier == grant_id)
        .and_then(|index| u32::try_from(index + 1).ok())
        .ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "the exception grant has no deterministic numeric handle".to_owned(),
            }
            .build()
        })
}

const fn exception_operation_name(operation: ExceptionDeliveryOperationV1) -> &'static str {
    match operation {
        ExceptionDeliveryOperationV1::Activate => "ACTIVATE",
        ExceptionDeliveryOperationV1::Revoke => "REVOKE",
    }
}

const fn local_exception_state(state: ExceptionActivationStateV1) -> LocalExceptionStateV1 {
    match state {
        ExceptionActivationStateV1::Active => LocalExceptionStateV1::Active,
        ExceptionActivationStateV1::Consumed => LocalExceptionStateV1::Consumed,
        ExceptionActivationStateV1::Expired => LocalExceptionStateV1::Expired,
        ExceptionActivationStateV1::Revoked => LocalExceptionStateV1::Revoked,
        ExceptionActivationStateV1::Rejected => LocalExceptionStateV1::Rejected,
        ExceptionActivationStateV1::Stale => LocalExceptionStateV1::Stale,
    }
}

const fn local_exception_state_name(state: LocalExceptionStateV1) -> &'static str {
    match state {
        LocalExceptionStateV1::Pending => "PENDING",
        LocalExceptionStateV1::Active => "ACTIVE",
        LocalExceptionStateV1::Consumed => "CONSUMED",
        LocalExceptionStateV1::Expired => "EXPIRED",
        LocalExceptionStateV1::Revoked => "REVOKED",
        LocalExceptionStateV1::Rejected => "REJECTED",
        LocalExceptionStateV1::Stale => "STALE",
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const fn default_true() -> bool {
    true
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use mithril_control::{
        CapabilityRecord, ExceptionActivationStateV1, ExceptionDeliveryCandidateV1,
        ExceptionDeliveryOperationV1, ExceptionInventory, ExceptionSourceRevisionV1,
        ExceptionSourceStateV1, FileExceptionGrantTemplateV1, KubernetesWorkloadIdentityV1,
        PolicyAcknowledgementAccepted, PolicyChunk, PolicyCompiler, PolicyDeliveryCandidateV1,
        PolicyDocumentV1, PolicyInventory, PolicySignerTrust, PolicyTargetSnapshotV1,
        PolicyTargetV1, ProfileCandidateArtifactV1, ProfileModeV1, ProfileSealRequestV1,
        RegistryDigestsV1, WorkloadProtectionException, WorkloadTargetFactV1,
    };
    use sha2::{Digest as _, Sha256};
    use snafu::ResultExt as _;
    use zerocopy::IntoBytes as _;

    use super::{
        write_atomic, NodePolicyDeliveryOwner, PolicyActivationProofV1, PolicyDeliveryOperationV1,
        PolicyTransferActionV1, TransferStateV1,
    };
    use crate::error::{IoSnafu, PolicySnafu};
    use crate::trust::InstalledPolicySignerV1;
    use crate::{
        ContainerKindV1, ContainerRuntimeConfig, EvidenceConfig, InterceptorConfig, NodeConfig,
        NodeControlConfig, RuntimeAdmissionConfig, TrustCache, WorkloadBindingConfig,
    };

    #[test]
    fn verified_candidate_is_durable_replay_safe_and_acknowledged_once() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary policy delivery directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let bundle = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let trust = trust(directory.path(), &key)?;
        let capabilities = capabilities();
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;

        let prepared = owner.prepare_activation(&bundle, &trust, &config, &capabilities, 2, 20)?;
        assert_eq!(prepared.profile_generation_ref_id, 2);
        assert!(prepared.config.policy_candidates[0].artifact_path.is_file());
        owner.begin_activation(&bundle, &prepared)?;

        let mut restored = config.clone();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config(&mut restored, &trust)?;
        assert_eq!(
            restored.workload_bindings[0].active_profile_generation_ref_id,
            2
        );

        owner.commit_activation(
            &bundle,
            &prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;
        let Some(acknowledgement) = owner.pending_acknowledgement() else {
            return super::IdentityStateSnafu {
                reason: "a committed activation needs one Control acknowledgement".to_owned(),
            }
            .fail();
        };
        assert_eq!(acknowledgement.state, "ACTIVE");
        assert_eq!(acknowledgement.profile_generation_ref_id, 2);
        assert!(owner
            .acknowledge_control(
                &acknowledgement,
                &PolicyAcknowledgementAccepted {
                    control_commit_index: 1,
                    rollout_state: "ACTIVE".to_owned(),
                    terminal_chain_closure_authorized: true,
                },
            )
            .is_err());

        let mut reloaded = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(reloaded.pending_acknowledgement().is_some());
        let acknowledgement = reloaded.pending_acknowledgement().ok_or_else(|| {
            super::IdentityStateSnafu {
                reason: "a committed activation lost its pending acknowledgement".to_owned(),
            }
            .build()
        })?;
        reloaded.acknowledge_control(
            &acknowledgement,
            &PolicyAcknowledgementAccepted {
                control_commit_index: 1,
                rollout_state: "ACTIVE".to_owned(),
                terminal_chain_closure_authorized: false,
            },
        )?;
        assert!(reloaded.pending_acknowledgement().is_none());
        assert!(reloaded
            .prepare_activation(&bundle, &trust, &config, &capabilities, 3, 22)
            .is_err());
        Ok(())
    }

    #[test]
    fn rejected_policy_receipt_is_recomputed_after_restart() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary rejected policy receipt directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(directory.path(), &key)?;
        let bundle = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let owner = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(owner
            .prepare_activation(&bundle, &trust, &config, &capabilities()[..1], 2, 20)
            .is_err());
        let acknowledgement = mithril_control::PolicyActivationAcknowledgement {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: "REJECTED".to_owned(),
            node_bound_generation_digest: String::new(),
            profile_generation_ref_id: 0,
            readback_digest: String::new(),
            probe_result_digest: String::new(),
            reason_code: "NODE_POLICY_REJECTED".to_owned(),
            observed_utc_ns: 20,
        };
        drop(owner);
        let mut recovered = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(!recovered.acknowledge_control(
            &acknowledgement,
            &PolicyAcknowledgementAccepted {
                control_commit_index: 3,
                rollout_state: "REJECTED".to_owned(),
                terminal_chain_closure_authorized: false,
            },
        )?);
        assert!(recovered
            .acknowledge_control(
                &acknowledgement,
                &PolicyAcknowledgementAccepted {
                    control_commit_index: 3,
                    rollout_state: "ACTIVE".to_owned(),
                    terminal_chain_closure_authorized: false,
                },
            )
            .is_err());
        drop(recovered);

        let replayed = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(replayed.pending_acknowledgement().is_none());
        // A process loss does not turn an ephemeral rejection into durable policy state.
        assert!(replayed
            .prepare_activation(&bundle, &trust, &config, &capabilities()[..1], 2, 21)
            .is_err());
        Ok(())
    }

    #[test]
    fn pending_policy_restart_reapplies_expected_pointer_and_rejects_ambiguity() -> crate::Result<()>
    {
        for observed_before_install in [None, Some(2)] {
            let directory = tempfile::tempdir().context(IoSnafu {
                path: "temporary policy crash recovery directory",
            })?;
            let (config, trust, candidate, mut restarted) =
                pending_policy_fixture(directory.path())?;
            let mut restored = config.clone();
            restarted.restore_config(&mut restored, &trust)?;
            assert!(restarted.status().activation_pending);
            assert_eq!(restored.policy_candidates.len(), 1);
            let pending = restarted.state.pending_activation.clone().ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "restart lost its pending policy identity".to_owned(),
                }
                .build()
            })?;
            restarted.validate_pending_activation_generation(&pending, observed_before_install)?;
            restarted.commit_pending_activation_with_proof(
                &restored,
                2,
                PolicyActivationProofV1 {
                    node_bound_generation_digest: "1".repeat(64),
                    readback_digest: "2".repeat(64),
                    probe_result_digest: "3".repeat(64),
                    observed_utc_ns: 31,
                },
            )?;
            let acknowledgement = restarted.pending_acknowledgement().ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "resolved pending policy has no durable acknowledgement".to_owned(),
                }
                .build()
            })?;
            assert_eq!(acknowledgement.state, "ACTIVE");
            assert_eq!(
                acknowledgement.candidate_content_id,
                candidate.candidate.candidate_content_id
            );
            assert_eq!(
                NodePolicyDeliveryOwner::load(directory.path())?
                    .pending_acknowledgement()
                    .map(|acknowledgement| acknowledgement.state),
                Some("ACTIVE".to_owned())
            );
        }

        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary unexpected policy pointer directory",
        })?;
        let (ambiguous_config, ambiguous_trust, _candidate, mut ambiguous) =
            pending_policy_fixture(directory.path())?;
        let mut restored = ambiguous_config;
        ambiguous.restore_config(&mut restored, &ambiguous_trust)?;
        let pending = ambiguous.state.pending_activation.clone().ok_or_else(|| {
            super::IdentityStateSnafu {
                reason: "restart lost its ambiguous pending policy".to_owned(),
            }
            .build()
        })?;
        assert!(ambiguous
            .validate_pending_activation_generation(&pending, Some(99))
            .is_err());
        assert!(ambiguous.status().activation_pending);
        assert!(ambiguous.pending_acknowledgement().is_none());

        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary replacement policy recovery directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(directory.path(), &key)?;
        let mut replacement = NodePolicyDeliveryOwner::load(directory.path())?;
        let active = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let active_prepared =
            replacement.prepare_activation(&active, &trust, &config, &capabilities(), 2, 20)?;
        replacement.begin_activation(&active, &active_prepared)?;
        replacement.commit_activation(
            &active,
            &active_prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;
        let next = bundle(
            &active_prepared.config,
            &key,
            2,
            2,
            PolicyDeliveryOperationV1::Replace,
            Some(active.candidate.candidate_content_id.clone()),
            22,
            30,
            "node-a",
        )?;
        let next_prepared = replacement.prepare_activation(
            &next,
            &trust,
            &active_prepared.config,
            &capabilities(),
            3,
            23,
        )?;
        assert_eq!(next_prepared.config.policy_candidates.len(), 1);
        replacement.begin_activation(&next, &next_prepared)?;
        let mut restored = active_prepared.config.clone();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config(&mut restored, &trust)?;
        assert_eq!(restored.policy_candidates.len(), 1);
        assert_eq!(
            restored.policy_candidates[0].artifact_path,
            next_prepared.config.policy_candidates[0].artifact_path
        );
        let pending = replacement
            .state
            .pending_activation
            .clone()
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "replacement restart lost its pending policy".to_owned(),
                }
                .build()
            })?;
        replacement.validate_pending_activation_generation(&pending, Some(2))?;
        replacement.commit_pending_activation_with_proof(
            &next_prepared.config,
            3,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "4".repeat(64),
                readback_digest: "5".repeat(64),
                probe_result_digest: "6".repeat(64),
                observed_utc_ns: 31,
            },
        )?;
        assert_eq!(
            replacement
                .pending_acknowledgement()
                .map(|acknowledgement| acknowledgement.state),
            Some("ACTIVE".to_owned())
        );

        for corrupt in [false, true] {
            let directory = tempfile::tempdir().context(IoSnafu {
                path: "temporary invalid policy crash recovery directory",
            })?;
            let (config, trust, _candidate, mut restarted) =
                pending_policy_fixture(directory.path())?;
            let bundle_file = restarted
                .state
                .pending_activation
                .as_ref()
                .map(|pending| pending.bundle_file.clone())
                .ok_or_else(|| {
                    super::IdentityStateSnafu {
                        reason: "staged policy has no pending activation".to_owned(),
                    }
                    .build()
                })?;
            let path = restarted.checked_bundle_file(&bundle_file)?;
            if corrupt {
                write_atomic(&path, b"not a signed policy bundle")?;
            } else {
                std::fs::remove_file(&path).context(IoSnafu { path: &path })?;
            }
            let mut restored = config.clone();
            assert!(restarted.restore_config(&mut restored, &trust).is_err());
            assert!(restarted.status().activation_pending);
            assert!(restarted.pending_acknowledgement().is_none());
            assert!(
                NodePolicyDeliveryOwner::load(directory.path())?
                    .status()
                    .activation_pending
            );
        }
        Ok(())
    }

    #[test]
    fn candidate_rejects_missing_capability_wrong_target_and_expiry() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary rejected policy directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(directory.path(), &key)?;
        let owner = NodePolicyDeliveryOwner::load(directory.path())?;
        let current = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        assert!(owner
            .prepare_activation(&current, &trust, &config, &capabilities()[..1], 2, 20,)
            .is_err());

        let wrong_target = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-b",
        )?;
        assert!(owner
            .prepare_activation(&wrong_target, &trust, &config, &capabilities(), 2, 20,)
            .is_err());

        let expired = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            19,
            "node-a",
        )?;
        assert!(owner
            .prepare_activation(&expired, &trust, &config, &capabilities(), 2, 20,)
            .is_err());
        Ok(())
    }

    #[test]
    fn active_profile_inventory_enforces_the_control_protocol_bound() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary active profile inventory directory",
        })?;
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;
        for index in 0..super::MAX_ACTIVE_POLICY_PROFILES {
            let profile_id = uuid::Uuid::from_u128(index as u128 + 1)
                .hyphenated()
                .to_string();
            owner.state.active_profiles.insert(
                profile_id,
                super::ActivePolicyRecordV1 {
                    tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    candidate_content_id: format!("{index:064x}"),
                    policy_source_revision_id: "b".repeat(64),
                    target_snapshot_digest: "c".repeat(64),
                    bundle_digest: "d".repeat(64),
                    artifact_file: "bundles/d/profile-artifact.json".to_owned(),
                    public_key_file: "bundles/d/profile-public-key.hex".to_owned(),
                    profile_generation_ref_id: index as u64 + 1,
                    staged_utc_ns: 1,
                    binding_ids: vec![uuid::Uuid::from_u128(index as u128 + 1_000)
                        .hyphenated()
                        .to_string()],
                    scheduled_bindings: Vec::new(),
                    node_bound_generation_digest: "e".repeat(64),
                    readback_digest: "f".repeat(64),
                    probe_result_digest: "1".repeat(64),
                    observed_utc_ns: 2,
                },
            );
        }
        let existing = owner
            .state
            .active_profiles
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the bounded inventory fixture is empty".to_owned(),
                }
                .build()
            })?;
        owner.ensure_active_profile_inventory_capacity(&existing)?;
        assert!(owner
            .ensure_active_profile_inventory_capacity(
                &uuid::Uuid::from_u128(10_000).hyphenated().to_string(),
            )
            .is_err());
        owner.state.active_profiles.remove(&existing);
        owner.ensure_active_profile_inventory_capacity(
            &uuid::Uuid::from_u128(10_000).hyphenated().to_string(),
        )?;
        Ok(())
    }

    #[test]
    fn complete_desired_inventory_retires_only_a_stale_inactive_profile() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary desired policy inventory directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(directory.path(), &key)?;
        let capabilities = capabilities();
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;
        let active = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let prepared = owner.prepare_activation(&active, &trust, &config, &capabilities, 2, 20)?;
        owner.begin_activation(&active, &prepared)?;
        owner.commit_activation(
            &active,
            &prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;

        owner.accept_inventory(PolicyInventory {
            desired_bundle_digests: vec![active.bundle_digest.clone()],
            desired_inventory_complete: true,
            ..PolicyInventory::default()
        })?;
        assert!(owner.inventory_retirement().is_none());

        owner.accept_inventory(PolicyInventory {
            desired_inventory_complete: false,
            ..PolicyInventory::default()
        })?;
        assert!(owner.inventory_retirement().is_none());

        owner.accept_inventory(PolicyInventory {
            desired_inventory_complete: true,
            ..PolicyInventory::default()
        })?;
        let retirement = owner.inventory_retirement().ok_or_else(|| {
            super::IdentityStateSnafu {
                reason: "the stale inactive profile has no durable retirement".to_owned(),
            }
            .build()
        })?;
        assert_eq!(retirement.bundle_digest, active.bundle_digest);

        let mut restarted = NodePolicyDeliveryOwner::load(directory.path())?;
        let mut restored = prepared.config.clone();
        restarted.restore_config(&mut restored, &trust)?;
        assert!(restored.policy_candidates.is_empty());
        assert!(restored.workload_bindings.is_empty());

        let issuer_high_water = restarted.state.issuer_high_water.clone();
        let distribution_high_water = restarted.state.distribution_high_water.clone();
        restarted.retire_inventory_delivery_state()?;
        drop(restarted);

        let mut recovered = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(recovered
            .inventory_retirement()
            .is_some_and(|retirement| retirement.delivery_state_retired));
        recovered.finish_inventory_retirement()?;
        assert!(recovered.state.active_profiles.is_empty());
        assert_eq!(recovered.state.issuer_high_water, issuer_high_water);
        assert_eq!(
            recovered.state.distribution_high_water,
            distribution_high_water
        );
        assert!(
            recovered
                .startup_authority_absence_from_readback(false)
                .policy_authority_absent
        );
        Ok(())
    }

    #[test]
    fn complete_desired_inventory_waits_for_runtime_lifetime_retirement() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary live runtime inventory directory",
        })?;
        let static_config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let base = bundle(
            &static_config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let scheduled = scheduled_bundle(base, &key, "worker-a", &[1; 16])?;
        let mut config = static_config;
        config.kubernetes_node_name = Some("worker-a".to_owned());
        config.runtime_admission = Some(RuntimeAdmissionConfig {
            socket_path: directory.path().join("runtime-admission.sock"),
            maximum_request_bytes: 64 * 1_024,
            timeout_ms: 10_000,
        });
        config.container_runtime = Some(ContainerRuntimeConfig {
            socket_path: directory.path().join("containerd.sock"),
            effect_controller_cgroup_path: directory.path().join("mithril-node-cgroup"),
            containerd_event_socket_path: None,
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings.clear();
        config.validate()?;

        let trust = trust(directory.path(), &key)?;
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;
        let prepared = owner.prepare_activation_for_session(
            &scheduled,
            &trust,
            &config,
            &capabilities(),
            2,
            20,
            &[1; 16],
            7,
        )?;
        owner.begin_activation(&scheduled, &prepared)?;
        owner.commit_activation(
            &scheduled,
            &prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;

        let mut runtime = prepared.config.workload_bindings[0].clone();
        runtime.binding_id = "88888888-8888-4888-8888-888888888888".to_owned();
        runtime.container_id = "d".repeat(64);
        runtime.sandbox_id = "e".repeat(64);
        runtime.root_cgroup_path = Some(directory.path().join("live-cgroup"));
        owner.record_runtime_binding(&runtime)?;

        owner.accept_inventory(PolicyInventory {
            desired_inventory_complete: true,
            ..PolicyInventory::default()
        })?;
        assert!(owner.inventory_retirement().is_none());

        owner.retire_runtime_bindings(std::slice::from_ref(&runtime.binding_id))?;
        owner.accept_inventory(PolicyInventory {
            desired_inventory_complete: true,
            ..PolicyInventory::default()
        })?;
        assert!(owner.inventory_retirement().is_some());
        Ok(())
    }

    #[test]
    fn inventory_retirement_keeps_a_bundle_used_by_durable_exception_state() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary exception base cache directory",
        })?;
        let fixture = pending_exception_fixture(directory.path())?;
        let mut owner = fixture.owner;
        assert!(
            !owner
                .startup_authority_absence_from_readback(false)
                .exception_authority_absent
        );
        let profile_id = fixture.scheduled.profile_artifact.header.profile_id;
        let record = owner.state.active_profiles[&profile_id].clone();
        owner.state.inventory_retirement = Some(super::InventoryPolicyRetirementV1 {
            candidate_content_id: record.candidate_content_id.clone(),
            profile_id,
            bundle_digest: record.bundle_digest.clone(),
            profile_generation_ref_id: record.profile_generation_ref_id,
            binding_ids: record.binding_ids.clone(),
            legacy_control_commit_index: 0,
            delivery_state_retired: false,
        });
        owner.finish_inventory_retirement()?;

        let recovered = NodePolicyDeliveryOwner::load(directory.path())?;
        assert_eq!(
            recovered
                .state
                .policy_candidate_bundles
                .get(&record.candidate_content_id),
            Some(&record.bundle_digest)
        );
        assert!(directory
            .path()
            .join("policy-delivery-v1/bundles")
            .join(record.bundle_digest)
            .is_dir());
        Ok(())
    }

    #[test]
    fn incremental_chunk_transfer_resumes_only_from_exact_durable_readback() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary interrupted transfer directory",
        })?;
        let config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let bundle = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let bundle_bytes = serde_json::to_vec(&bundle).context(super::JsonSnafu {
            path: "in-memory policy bundle",
        })?;
        let split = bundle_bytes.len() / 2;
        let chunks = [&bundle_bytes[..split], &bundle_bytes[split..]];
        let inventory = PolicyInventory {
            candidate_available: true,
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            bundle_bytes: u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX),
            chunk_count: 2,
            operation: "ACTIVATE".to_owned(),
            desired_bundle_digests: vec![bundle.bundle_digest.clone()],
            desired_inventory_complete: true,
        };
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(matches!(
            owner.next_transfer_action()?,
            PolicyTransferActionV1::Inventory { .. }
        ));
        assert!(owner.accept_inventory(inventory.clone())?);
        let PolicyTransferActionV1::Fetch { chunk_index, .. } = owner.next_transfer_action()?
        else {
            return super::IdentityStateSnafu {
                reason: "incremental transfer did not request its first chunk".to_owned(),
            }
            .fail();
        };
        assert_eq!(chunk_index, 0);
        owner.accept_chunk(PolicyChunk {
            candidate_content_id: inventory.candidate_content_id.clone(),
            bundle_digest: inventory.bundle_digest.clone(),
            chunk_index,
            chunk_count: inventory.chunk_count,
            chunk_sha256: super::sha256(chunks[0]),
            payload: chunks[0].to_vec(),
        })?;

        let mut resumed = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(matches!(
            resumed.next_transfer_action()?,
            PolicyTransferActionV1::Inventory { .. }
        ));
        assert!(resumed.accept_inventory(inventory.clone())?);
        let PolicyTransferActionV1::Fetch { chunk_index, .. } = resumed.next_transfer_action()?
        else {
            return super::IdentityStateSnafu {
                reason: "resumed transfer did not request its missing chunk".to_owned(),
            }
            .fail();
        };
        assert_eq!(chunk_index, 1);
        resumed.accept_chunk(PolicyChunk {
            candidate_content_id: inventory.candidate_content_id.clone(),
            bundle_digest: inventory.bundle_digest.clone(),
            chunk_index,
            chunk_count: inventory.chunk_count,
            chunk_sha256: super::sha256(chunks[1]),
            payload: chunks[1].to_vec(),
        })?;
        let PolicyTransferActionV1::Ready(assembled) = resumed.next_transfer_action()? else {
            return super::IdentityStateSnafu {
                reason: "complete incremental transfer did not produce its bundle".to_owned(),
            }
            .fail();
        };
        assert_eq!(*assembled, bundle);

        let transfer = TransferStateV1 {
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            bundle_bytes: u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX),
            chunk_count: 2,
            chunk_digests: BTreeMap::from([
                (0, super::sha256(chunks[0])),
                (1, super::sha256(chunks[1])),
            ]),
        };
        let transfer_directory = resumed.transfer_directory(&bundle.bundle_digest);
        write_atomic(&transfer_directory.join("00000000.chunk"), b"tampered")?;
        assert!(!resumed.transferred_chunk_is_valid(&transfer, 0));
        assert!(resumed.assemble_transfer(&transfer).is_err());

        resumed.begin_control_session();
        assert!(resumed.accept_inventory(inventory)?);
        assert!(matches!(
            resumed.next_transfer_action()?,
            PolicyTransferActionV1::Fetch { chunk_index: 0, .. }
        ));
        Ok(())
    }

    #[test]
    fn maximum_policy_transfer_advances_one_chunk_per_action() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary maximum transfer directory",
        })?;
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;
        let inventory = PolicyInventory {
            candidate_available: true,
            candidate_content_id: "a".repeat(64),
            policy_source_revision_id: "b".repeat(64),
            target_snapshot_digest: "c".repeat(64),
            bundle_digest: "d".repeat(64),
            bundle_bytes: mithril_control::MAX_POLICY_BUNDLE_BYTES as u64,
            chunk_count: 256,
            operation: "ACTIVATE".to_owned(),
            desired_bundle_digests: vec!["d".repeat(64)],
            desired_inventory_complete: true,
        };
        assert!(owner.accept_inventory(inventory.clone())?);
        for expected_index in 0..inventory.chunk_count {
            let PolicyTransferActionV1::Fetch { chunk_index, .. } = owner.next_transfer_action()?
            else {
                return super::IdentityStateSnafu {
                    reason: "maximum transfer emitted more than one chunk action".to_owned(),
                }
                .fail();
            };
            assert_eq!(chunk_index, expected_index);
            let payload = vec![u8::try_from(expected_index % 251).unwrap_or_default()];
            owner.accept_chunk(PolicyChunk {
                candidate_content_id: inventory.candidate_content_id.clone(),
                bundle_digest: inventory.bundle_digest.clone(),
                chunk_index,
                chunk_count: inventory.chunk_count,
                chunk_sha256: super::sha256(&payload),
                payload,
            })?;
        }
        assert_eq!(owner.load_transfer()?.chunk_digests.len(), 256);
        Ok(())
    }

    #[test]
    fn signed_scheduled_material_is_bound_to_one_node_session() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary scheduled policy directory",
        })?;
        let static_config = config(directory.path());
        let key = SigningKey::from_bytes(&[9; 32]);
        let base = bundle(
            &static_config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
        )?;
        let scheduled = scheduled_bundle(base, &key, "worker-a", &[1; 16])?;
        let mut config = static_config;
        config.kubernetes_node_name = Some("worker-a".to_owned());
        config.runtime_admission = Some(RuntimeAdmissionConfig {
            socket_path: directory.path().join("runtime-admission.sock"),
            maximum_request_bytes: 64 * 1_024,
            timeout_ms: 10_000,
        });
        config.container_runtime = Some(ContainerRuntimeConfig {
            socket_path: directory.path().join("containerd.sock"),
            effect_controller_cgroup_path: directory.path().join("mithril-node-cgroup"),
            containerd_event_socket_path: None,
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings.clear();
        config.validate()?;
        let trust = trust(directory.path(), &key)?;
        let mut owner = NodePolicyDeliveryOwner::load(directory.path())?;

        let prepared = owner.prepare_activation_for_session(
            &scheduled,
            &trust,
            &config,
            &capabilities(),
            2,
            20,
            &[1; 16],
            7,
        )?;
        assert_eq!(prepared.config.workload_bindings.len(), 1);
        let binding = &prepared.config.workload_bindings[0];
        assert!(binding.container_id.starts_with("scheduled:"));
        assert!(binding.root_cgroup_path.is_none());
        assert_eq!(binding.active_profile_generation_ref_id, 2);

        assert!(owner
            .prepare_activation_for_session(
                &scheduled,
                &trust,
                &config,
                &capabilities(),
                2,
                20,
                &[2; 16],
                7,
            )
            .is_err());
        let mut wrong_node = config.clone();
        wrong_node.kubernetes_node_name = Some("worker-b".to_owned());
        assert!(owner
            .prepare_activation_for_session(
                &scheduled,
                &trust,
                &wrong_node,
                &capabilities(),
                2,
                20,
                &[1; 16],
                7,
            )
            .is_err());
        owner.begin_activation(&scheduled, &prepared)?;
        let pending_snapshot = owner.state.clone();
        let mut same_boot_pending = config.clone();
        same_boot_pending.workload_bindings.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut same_boot_pending,
            &trust,
            &[1; 16],
            7,
        )?;
        assert_eq!(same_boot_pending.workload_bindings.len(), 1);
        let mut old_boot_pending_config = config.clone();
        old_boot_pending_config.workload_bindings.clear();
        old_boot_pending_config.policy_candidates.clear();
        let mut old_boot_pending = NodePolicyDeliveryOwner::load(directory.path())?;
        old_boot_pending.restore_config_for_session(
            &mut old_boot_pending_config,
            &trust,
            &[2; 16],
            7,
        )?;
        assert!(old_boot_pending_config.workload_bindings.is_empty());
        assert!(old_boot_pending_config.policy_candidates.is_empty());
        assert!(old_boot_pending.status().activation_pending);
        assert!(old_boot_pending
            .retire_old_session_pending_policy(&scheduled, Some(2), true)
            .is_err());
        assert!(old_boot_pending.status().activation_pending);
        assert!(old_boot_pending
            .retire_old_session_pending_policy(&scheduled, None, false)
            .is_err());
        old_boot_pending.retire_old_session_pending_policy(&scheduled, None, true)?;
        assert!(!old_boot_pending.status().activation_pending);
        assert_eq!(
            old_boot_pending
                .state
                .distribution_high_water
                .get(scheduled.profile_artifact.policy_document.profile_id())
                .map(|sequence| sequence.sequence),
            Some(1)
        );
        owner.state = pending_snapshot;
        owner.persist_state()?;
        owner.commit_activation(
            &scheduled,
            &prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;
        let delivered = owner.status();
        assert_eq!(delivered.scheduled_binding_count, 1);
        assert_eq!(delivered.runtime_binding_count, 0);
        assert!(!delivered.activation_pending);
        assert!(!delivered.control_acknowledged);
        let mut runtime_binding = prepared.config.workload_bindings[0].clone();
        let authority = runtime_binding
            .scheduled_binding_authority_id
            .clone()
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "scheduled test binding has no authority".to_owned(),
                }
                .build()
            })?;
        runtime_binding.container_id = "d".repeat(64);
        runtime_binding.binding_id =
            crate::runtime_admission::ScheduledRuntimeBindingV1::runtime_binding_id(
                &authority,
                &runtime_binding.container_id,
            );
        runtime_binding.sandbox_id = "e".repeat(64);
        runtime_binding.root_cgroup_path = Some(directory.path().join("pod-cgroup"));
        runtime_binding.container_generation = 42;
        let rollback = owner.record_runtime_binding(&runtime_binding)?;
        let admitted = super::policy_delivery_status(directory.path())?;
        assert_eq!(
            admitted.active_profile_ids,
            vec![scheduled.profile_artifact.policy_document.profile_id()]
        );
        assert_eq!(admitted.scheduled_binding_count, 0);
        assert_eq!(admitted.runtime_binding_count, 1);
        assert_eq!(admitted.active_target_count, 1);
        assert!(!admitted.active_targets_truncated);
        let inspected_target = &admitted.active_targets[0];
        let signed_target = &scheduled.candidate.exact_target.workload_targets[0];
        let signed_identity = signed_target.kubernetes.as_ref().ok_or_else(|| {
            super::IdentityStateSnafu {
                reason: "the signed test target has no Kubernetes identity",
            }
            .build()
        })?;
        assert_eq!(inspected_target.node_id, signed_target.node_id);
        assert_eq!(
            inspected_target.operation,
            PolicyDeliveryOperationV1::Activate
        );
        assert!(inspected_target.predecessor_candidate_content_id.is_none());
        assert_eq!(inspected_target.pod_uid, signed_target.pod_uid);
        assert_eq!(
            inspected_target.kubernetes_node_uid,
            signed_identity.kubernetes_node_uid
        );
        assert_eq!(inspected_target.node_boot_id, signed_identity.node_boot_id);
        assert_eq!(inspected_target.label_epoch, signed_identity.label_epoch);
        assert_eq!(
            inspected_target.runtime_container_id.as_deref(),
            Some(runtime_binding.container_id.as_str())
        );
        assert_eq!(
            inspected_target.runtime_binding_id.as_deref(),
            Some(runtime_binding.binding_id.as_str())
        );
        assert_eq!(inspected_target.container_generation, Some(42));
        let mut restored = config.clone();
        restored.workload_bindings.clear();
        restored.policy_candidates.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut restored,
            &trust,
            &[1; 16],
            7,
        )?;
        assert_eq!(restored.workload_bindings.len(), 1);
        assert_eq!(
            restored.workload_bindings[0].binding_id,
            runtime_binding.binding_id
        );

        let mut new_boot = config.clone();
        new_boot.workload_bindings.clear();
        new_boot.policy_candidates.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut new_boot,
            &trust,
            &[2; 16],
            7,
        )?;
        assert!(new_boot.workload_bindings.is_empty());
        owner.rollback_runtime_binding(rollback)?;
        let rolled_back = super::policy_delivery_status(directory.path())?;
        assert_eq!(rolled_back.scheduled_binding_count, 1);
        assert_eq!(rolled_back.runtime_binding_count, 0);
        assert_eq!(rolled_back.active_target_count, 1);
        assert!(rolled_back.active_targets[0].runtime_container_id.is_none());
        assert!(rolled_back.active_targets[0].runtime_binding_id.is_none());
        owner.record_runtime_binding(&runtime_binding)?;
        owner.retire_runtime_bindings(std::slice::from_ref(&runtime_binding.binding_id))?;
        let retired = super::policy_delivery_status(directory.path())?;
        assert_eq!(retired.scheduled_binding_count, 1);
        assert_eq!(retired.runtime_binding_count, 0);
        let mut retired_config = config.clone();
        retired_config.workload_bindings.clear();
        retired_config.policy_candidates.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut retired_config,
            &trust,
            &[1; 16],
            7,
        )?;
        assert_eq!(retired_config.workload_bindings.len(), 1);
        assert_eq!(retired_config.workload_bindings[0].binding_id, authority);
        assert!(retired_config.workload_bindings[0]
            .root_cgroup_path
            .is_none());
        let mut old_boot_active = NodePolicyDeliveryOwner::load(directory.path())?;
        let (profile_id, record) = old_boot_active
            .state
            .active_profiles
            .iter()
            .next()
            .map(|(profile_id, record)| (profile_id.clone(), record.clone()))
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "scheduled restart has no active profile".to_owned(),
                }
                .build()
            })?;
        assert!(old_boot_active
            .retire_old_session_active_profile(&profile_id, &record, Some(2), true)
            .is_err());
        assert_eq!(old_boot_active.status().active_profile_ids.len(), 1);
        assert!(old_boot_active
            .retire_old_session_active_profile(&profile_id, &record, None, false)
            .is_err());
        old_boot_active.retire_old_session_active_profile(&profile_id, &record, None, true)?;
        assert!(old_boot_active.status().active_profile_ids.is_empty());
        assert!(old_boot_active
            .state
            .policy_candidate_bundles
            .contains_key(&record.candidate_content_id));
        Ok(())
    }

    #[test]
    fn expired_exception_inventory_becomes_terminal_without_kernel_work() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary expired exception delivery directory",
        })?;
        let PendingExceptionFixture {
            config,
            trust,
            activation,
            mut owner,
            ..
        } = pending_exception_fixture(directory.path())?;
        owner.state.exception_records.clear();
        owner.state.exception_distribution_high_water.clear();
        owner.persist_state()?;
        let candidate_json = serde_json::to_vec(&activation).context(super::JsonSnafu {
            path: "in-memory expired exception candidate",
        })?;
        let prepared = owner.accept_exception_inventory_at(
            ExceptionInventory {
                candidate_available: true,
                candidate_content_id: activation.candidate_content_id.clone(),
                operation: "ACTIVATE".to_owned(),
                candidate_json,
            },
            &trust,
            &config,
            &[1; 16],
            7,
            activation.valid_until_utc_ns,
        )?;
        assert!(prepared.is_none());
        assert_eq!(owner.status().pending_exception_count, 0);
        assert_eq!(owner.status().expired_exception_count, 1);
        let acknowledgement = owner.pending_exception_acknowledgement()?.ok_or_else(|| {
            super::IdentityStateSnafu {
                reason: "the expired exception has no acknowledgement".to_owned(),
            }
            .build()
        })?;
        assert_eq!(acknowledgement.state, "EXPIRED");
        assert_eq!(acknowledgement.consumed_uses, 0);
        Ok(())
    }

    #[test]
    fn exception_delivery_survives_restart_and_keeps_revocation_monotonic() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary exception delivery directory",
        })?;
        let PendingExceptionFixture {
            config,
            trust,
            key,
            scheduled,
            source,
            target,
            activation,
            owner,
        } = pending_exception_fixture(directory.path())?;
        let expired_restart_state = owner.state.clone();
        let pending_status = owner.status();
        assert_eq!(pending_status.pending_exception_count, 1);
        assert_eq!(pending_status.active_exception_count, 0);

        let mut restarted = NodePolicyDeliveryOwner::load(directory.path())?;
        let (instance_id, recovered_candidate, recovered) = restarted
            .verified_pending_exception(&trust, &config, &[1; 16], 7)?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "restart lost its valid pending exception".to_owned(),
                }
                .build()
            })?;
        assert!(restarted
            .resolve_pending_exception(
                &instance_id,
                &recovered_candidate,
                recovered,
                super::PendingExceptionPhysicalV1::Absent,
                24,
            )?
            .is_some());
        restarted.commit_exception_result(
            &activation,
            ExceptionActivationStateV1::Active,
            0,
            25,
        )?;
        let activation_ack = restarted
            .pending_exception_acknowledgement()?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the active exception has no acknowledgement".to_owned(),
                }
                .build()
            })?;
        assert_eq!(activation_ack.state, "ACTIVE");
        assert_eq!(restarted.status().exception_ack_pending_count, 1);
        restarted.acknowledge_exception_control(&activation.candidate_content_id)?;
        assert_eq!(restarted.status().active_exception_count, 1);
        assert_eq!(restarted.status().exception_ack_pending_count, 0);
        restarted.observe_exception_result(
            &activation,
            crate::policy::ExceptionRuntimeObservationV1 {
                state: ExceptionActivationStateV1::Consumed,
                consumed_uses: 1,
            },
            26,
        )?;
        let consumed_ack = restarted
            .pending_exception_acknowledgement()?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the consumed exception has no acknowledgement".to_owned(),
                }
                .build()
            })?;
        assert_eq!(consumed_ack.state, "CONSUMED");
        assert_eq!(consumed_ack.transition_version, 2);
        assert_eq!(restarted.status().terminal_exception_count, 1);
        assert_eq!(restarted.status().consumed_exception_count, 1);
        restarted.acknowledge_exception_control(&activation.candidate_content_id)?;

        let deletion = source.deletion_requested().context(PolicySnafu)?;
        let revocation = ExceptionDeliveryCandidateV1::sign(
            &deletion,
            scheduled.candidate.candidate_content_id.clone(),
            scheduled
                .profile_artifact
                .policy_document
                .profile_id()
                .to_owned(),
            2,
            target,
            ExceptionDeliveryOperationV1::Revoke,
            1,
            50,
            Some(activation.candidate_content_id.clone()),
            1,
            2,
            60,
            100,
            "test-key".to_owned(),
            &key,
        )
        .context(PolicySnafu)?;
        let prepared_revocation = restarted.prepare_exception_delivery(
            revocation.clone(),
            &trust,
            &config,
            &[1; 16],
            7,
            61,
        )?;
        restarted.stage_exception_delivery(
            &prepared_revocation,
            &serde_json::to_vec(&revocation).context(super::JsonSnafu {
                path: "in-memory exception revocation",
            })?,
            61,
        )?;
        let pending_revocation_state = restarted.state.clone();
        restarted.commit_exception_result(
            &revocation,
            ExceptionActivationStateV1::Revoked,
            1,
            62,
        )?;
        assert_eq!(
            restarted
                .pending_exception_acknowledgement()?
                .map(|acknowledgement| acknowledgement.state),
            Some("REVOKED".to_owned())
        );
        assert_eq!(restarted.status().revoked_exception_count, 1);
        assert!(restarted
            .prepare_exception_delivery(activation.clone(), &trust, &config, &[1; 16], 7, 63)
            .is_err());

        restarted.state = pending_revocation_state.clone();
        restarted.persist_state()?;
        let startup_revocation = restarted
            .reconcile_pending_exception_with_readback(
                &trust,
                &config,
                (&[1; 16], 7),
                63,
                |_, _, _| Ok(super::PendingExceptionPhysicalV1::Active { consumed_uses: 1 }),
            )?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "startup lost a pending physical revocation".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            startup_revocation.candidate.operation,
            ExceptionDeliveryOperationV1::Revoke
        );
        assert_eq!(restarted.status().pending_exception_count, 1);

        restarted.state = pending_revocation_state.clone();
        restarted.persist_state()?;
        assert!(restarted
            .reconcile_pending_exception_with_readback(
                &trust,
                &config,
                (&[1; 16], 7),
                63,
                |_, _, _| Ok(super::PendingExceptionPhysicalV1::Absent),
            )?
            .is_none());
        let recovered_revocation =
            restarted
                .pending_exception_acknowledgement()?
                .ok_or_else(|| {
                    super::IdentityStateSnafu {
                        reason: "the recovered revocation has no acknowledgement".to_owned(),
                    }
                    .build()
                })?;
        assert_eq!(recovered_revocation.state, "REVOKED");
        assert_eq!(recovered_revocation.consumed_uses, 1);

        restarted.state = pending_revocation_state;
        restarted.persist_state()?;
        restarted.settle_old_session_exception(
            &revocation.exception_instance_id,
            &revocation,
            false,
            false,
            64,
        )?;
        let retired = restarted
            .state
            .exception_records
            .get(&revocation.exception_instance_id)
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "old-session revocation lost its durable tombstone".to_owned(),
                }
                .build()
            })?;
        assert_eq!(retired.state, super::LocalExceptionStateV1::Revoked);
        assert_eq!(retired.consumed_uses, 1);
        assert!(!retired.report_to_control);
        assert!(restarted.pending_exception_acknowledgement()?.is_none());

        // Restore the crash checkpoint from before physical activation and restart after expiry.
        restarted.state = expired_restart_state.clone();
        restarted.persist_state()?;
        drop(restarted);
        let mut expired = NodePolicyDeliveryOwner::load(directory.path())?;
        let (instance_id, recovered_candidate, recovered) = expired
            .verified_pending_exception(&trust, &config, &[1; 16], 7)?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "restart lost its expired pending exception".to_owned(),
                }
                .build()
            })?;
        assert!(expired
            .resolve_pending_exception(
                &instance_id,
                &recovered_candidate,
                recovered,
                super::PendingExceptionPhysicalV1::Absent,
                101,
            )?
            .is_none());
        assert_eq!(expired.status().pending_exception_count, 0);
        assert_eq!(expired.status().expired_exception_count, 1);
        let expired_ack = expired
            .pending_exception_acknowledgement()?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "expired pending exception has no durable acknowledgement".to_owned(),
                }
                .build()
            })?;
        assert_eq!(expired_ack.state, "EXPIRED");
        assert_eq!(
            expired_ack.candidate_content_id,
            activation.candidate_content_id
        );

        let replayed = NodePolicyDeliveryOwner::load(directory.path())?;
        assert_eq!(
            replayed
                .pending_exception_acknowledgement()?
                .map(|acknowledgement| acknowledgement.state),
            Some("EXPIRED".to_owned())
        );
        drop(replayed);

        let mut still_active = NodePolicyDeliveryOwner::load(directory.path())?;
        still_active.state = expired_restart_state.clone();
        still_active.persist_state()?;
        let (instance_id, recovered_candidate, recovered) = still_active
            .verified_pending_exception(&trust, &config, &[1; 16], 7)?
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "restart lost its physically active exception".to_owned(),
                }
                .build()
            })?;
        assert!(still_active
            .resolve_pending_exception(
                &instance_id,
                &recovered_candidate,
                recovered,
                super::PendingExceptionPhysicalV1::Active { consumed_uses: 0 },
                101,
            )?
            .is_none());
        assert_eq!(
            still_active
                .pending_exception_acknowledgement()?
                .map(|acknowledgement| acknowledgement.state),
            Some("ACTIVE".to_owned())
        );
        drop(still_active);

        let mut invalid = NodePolicyDeliveryOwner::load(directory.path())?;
        invalid.state = expired_restart_state;
        invalid.persist_state()?;
        let candidate_file = invalid
            .state
            .exception_records
            .values()
            .find(|record| record.state == super::LocalExceptionStateV1::Pending)
            .map(|record| record.candidate_file.clone())
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "staged exception has no pending record".to_owned(),
                }
                .build()
            })?;
        let candidate_path = invalid.checked_bundle_file(&candidate_file)?;
        write_atomic(&candidate_path, b"not a signed exception candidate")?;
        drop(invalid);

        let mut invalid = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(invalid
            .verified_pending_exception(&trust, &config, &[1; 16], 7)
            .is_err());
        assert_eq!(invalid.status().pending_exception_count, 1);
        assert!(invalid.pending_exception_acknowledgement()?.is_none());
        assert_eq!(
            NodePolicyDeliveryOwner::load(directory.path())?
                .status()
                .pending_exception_count,
            1
        );
        Ok(())
    }

    #[test]
    fn startup_exception_reconciliation_blocks_ambiguous_durable_or_physical_state(
    ) -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary startup exception recovery directory",
        })?;
        let PendingExceptionFixture {
            config,
            trust,
            activation,
            mut owner,
            ..
        } = pending_exception_fixture(directory.path())?;
        let pending = owner.state.clone();

        assert!(owner
            .reconcile_pending_exception_with_readback(
                &trust,
                &config,
                (&[1; 16], 7),
                24,
                |_, _, _| Ok(super::PendingExceptionPhysicalV1::Absent),
            )?
            .is_some());
        assert_eq!(owner.status().pending_exception_count, 1);

        owner.state = pending.clone();
        owner.persist_state()?;
        let partial_runtime = [0; std::mem::size_of::<super::ExceptionRuntimeStateV1>()];
        assert!(owner
            .reconcile_pending_exception_with_readback(
                &trust,
                &config,
                (&[1; 16], 7),
                24,
                |_, _, _| {
                    NodePolicyDeliveryOwner::pending_exception_physical_state(
                        Some(&partial_runtime),
                        None,
                        super::ExceptionRuntimeStateKeyV1 {
                            node_id: erebor_interceptor_abi::Id128V1::new(1, 2),
                            exception_instance_id: erebor_interceptor_abi::Id128V1::new(3, 4),
                        },
                        [7; 32],
                        1,
                        24,
                    )
                },
            )
            .is_err());
        assert_eq!(owner.status().pending_exception_count, 1);

        owner.state = pending.clone();
        owner.persist_state()?;
        let instance_id = owner
            .state
            .exception_records
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the startup fixture has no exception instance".to_owned(),
                }
                .build()
            })?;
        assert!(owner
            .settle_old_session_exception(&instance_id, &activation, true, false, 24,)
            .is_err());
        assert_eq!(owner.status().pending_exception_count, 1);
        owner.settle_old_session_exception(&instance_id, &activation, false, false, 24)?;
        assert_eq!(owner.status().pending_exception_count, 0);
        assert_eq!(owner.status().terminal_exception_count, 1);
        let retired_activation =
            owner
                .state
                .exception_records
                .get(&instance_id)
                .ok_or_else(|| {
                    super::IdentityStateSnafu {
                        reason: "old-session activation lost its durable tombstone".to_owned(),
                    }
                    .build()
                })?;
        assert_eq!(
            retired_activation.state,
            super::LocalExceptionStateV1::Consumed
        );
        assert_eq!(retired_activation.consumed_uses, 1);
        assert!(!retired_activation.report_to_control);
        assert!(owner.pending_exception_acknowledgement()?.is_none());

        owner.state = pending.clone();
        let active = owner
            .state
            .exception_records
            .get_mut(&instance_id)
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the startup fixture lost its active exception".to_owned(),
                }
                .build()
            })?;
        active.state = super::LocalExceptionStateV1::Active;
        active.transition_version = 1;
        active.control_acknowledged = true;
        owner.settle_old_session_exception(&instance_id, &activation, false, false, 24)?;
        let active_retirement = &owner.state.exception_records[&instance_id];
        assert_eq!(
            active_retirement.state,
            super::LocalExceptionStateV1::Consumed
        );
        assert_eq!(active_retirement.transition_version, 2);
        assert_eq!(active_retirement.consumed_uses, 1);

        owner.state = pending.clone();
        owner.settle_old_session_exception(
            &instance_id,
            &activation,
            false,
            false,
            activation.valid_until_utc_ns,
        )?;
        assert_eq!(
            owner.state.exception_records[&instance_id].state,
            super::LocalExceptionStateV1::Expired
        );

        owner.state = pending.clone();
        let duplicate = owner
            .state
            .exception_records
            .values()
            .next()
            .cloned()
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the startup fixture has no pending exception".to_owned(),
                }
                .build()
            })?;
        owner
            .state
            .exception_records
            .insert("dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(), duplicate);
        owner.persist_state()?;
        assert!(NodePolicyDeliveryOwner::load(directory.path()).is_err());

        owner.state = pending;
        owner.persist_state()?;
        let candidate_file = owner
            .state
            .exception_records
            .values()
            .next()
            .map(|record| record.candidate_file.clone())
            .ok_or_else(|| {
                super::IdentityStateSnafu {
                    reason: "the startup fixture has no candidate file".to_owned(),
                }
                .build()
            })?;
        let candidate_path = owner.checked_bundle_file(&candidate_file)?;
        write_atomic(&candidate_path, b"not a signed exception candidate")?;
        let mut readback_called = false;
        assert!(owner
            .reconcile_pending_exception_with_readback(
                &trust,
                &config,
                (&[1; 16], 7),
                24,
                |_, _, _| {
                    readback_called = true;
                    Ok(super::PendingExceptionPhysicalV1::Absent)
                },
            )
            .is_err());
        // Invalid staged identity stops startup before physical state can justify readiness.
        assert!(!readback_called);
        assert_eq!(owner.status().pending_exception_count, 1);
        Ok(())
    }

    #[test]
    fn pending_exception_terminal_state_requires_exact_physical_readback() -> crate::Result<()> {
        let runtime_key = super::ExceptionRuntimeStateKeyV1 {
            node_id: erebor_interceptor_abi::Id128V1::new(1, 2),
            exception_instance_id: erebor_interceptor_abi::Id128V1::new(3, 4),
        };
        let definition = [7; 32];
        let runtime = super::ExceptionRuntimeStateV1 {
            maximum_uses: 2,
            consumed_uses: 1,
            bound_profile_generation_refs: 1,
            deadline_boottime_ns: 100,
            exception_definition_sha256: definition,
            state: super::ExceptionRuntimeStateKindV1::Active,
            ..Default::default()
        };
        let binding = super::ExceptionHandleBindingV1 {
            runtime_state_key: runtime_key,
            state: super::ExceptionBindingStateV1::Active,
            ..Default::default()
        };

        assert_eq!(
            NodePolicyDeliveryOwner::pending_exception_physical_state(
                Some(runtime.as_bytes()),
                Some(binding.as_bytes()),
                runtime_key,
                definition,
                2,
                99,
            )?,
            super::PendingExceptionPhysicalV1::Active { consumed_uses: 1 }
        );
        assert_eq!(
            NodePolicyDeliveryOwner::pending_exception_physical_state(
                Some(runtime.as_bytes()),
                Some(binding.as_bytes()),
                runtime_key,
                definition,
                2,
                100,
            )?,
            super::PendingExceptionPhysicalV1::Expired { consumed_uses: 1 }
        );
        assert_eq!(
            NodePolicyDeliveryOwner::pending_exception_physical_state(
                None,
                None,
                runtime_key,
                definition,
                2,
                100,
            )?,
            super::PendingExceptionPhysicalV1::Absent
        );
        assert!(NodePolicyDeliveryOwner::pending_exception_physical_state(
            Some(runtime.as_bytes()),
            None,
            runtime_key,
            definition,
            2,
            100,
        )
        .is_err());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn bundle(
        config: &NodeConfig,
        key: &SigningKey,
        issuer_sequence: u64,
        distribution_sequence: u64,
        operation: PolicyDeliveryOperationV1,
        predecessor: Option<String>,
        issued_utc_ns: i64,
        expires_utc_ns: i64,
        node_id: &str,
    ) -> crate::Result<mithril_control::PolicyBundleV1> {
        let document = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../mithril-control/tests/fixtures/policy-v1.yaml"),
        )
        .context(PolicySnafu)?;
        bundle_from_document(
            config,
            key,
            issuer_sequence,
            distribution_sequence,
            operation,
            predecessor,
            issued_utc_ns,
            expires_utc_ns,
            node_id,
            document,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn bundle_from_document(
        config: &NodeConfig,
        key: &SigningKey,
        issuer_sequence: u64,
        distribution_sequence: u64,
        operation: PolicyDeliveryOperationV1,
        predecessor: Option<String>,
        issued_utc_ns: i64,
        expires_utc_ns: i64,
        node_id: &str,
        document: PolicyDocumentV1,
    ) -> crate::Result<mithril_control::PolicyBundleV1> {
        let compiled = PolicyCompiler.compile(&document).context(PolicySnafu)?;
        let artifact = ProfileCandidateArtifactV1::sign(
            &document,
            compiled,
            ProfileSealRequestV1 {
                signing_key_id: "test-key".to_owned(),
                issuer_id: "88888888-8888-4888-8888-888888888888".to_owned(),
                sequence_epoch: 1,
                issuer_sequence,
                rollback_authorization_id: None,
                registry_digests: RegistryDigestsV1 {
                    provider_numeric_registry_bundle_digest: "1".repeat(64),
                    required_capability_schema_digest: "2".repeat(64),
                    source_selector_registry_digest: "3".repeat(64),
                    object_classifier_registry_digest: "4".repeat(64),
                    reason_code_registry_digest: "5".repeat(64),
                    correlation_package_registry_digest: "6".repeat(64),
                    provider_vocabulary_registry_digest: "7".repeat(64),
                },
            },
            key,
        )
        .context(PolicySnafu)?;
        let signed_profile_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&artifact).context(super::JsonSnafu {
                path: "in-memory signed profile"
            })?)
        );
        let target = PolicyTargetV1 {
            tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            cluster_uid: "55555555-5555-4555-8555-555555555555".to_owned(),
            node_id: node_id.to_owned(),
            workload_binding_generation_digests: vec![
                crate::node::workload_binding_generation_digest(&config.workload_bindings[0])?,
            ],
            workload_targets: Vec::new(),
        };
        let source_revision_id = "a".repeat(64);
        let snapshot = PolicyTargetSnapshotV1::new(
            source_revision_id.clone(),
            signed_profile_digest.clone(),
            1,
            vec![target.clone()],
        )
        .context(PolicySnafu)?;
        let candidate = PolicyDeliveryCandidateV1::sign(
            target.tenant_id.clone(),
            source_revision_id,
            signed_profile_digest,
            &snapshot,
            target,
            operation,
            predecessor,
            1,
            distribution_sequence,
            issued_utc_ns,
            expires_utc_ns,
            "test-key".to_owned(),
            key,
        )
        .context(PolicySnafu)?;
        mithril_control::PolicyBundleV1::new(
            candidate,
            artifact,
            key.verifying_key().to_bytes().to_vec(),
        )
        .context(PolicySnafu)
    }

    fn scheduled_bundle(
        base: mithril_control::PolicyBundleV1,
        key: &SigningKey,
        kubernetes_node_name: &str,
        node_boot_id: &[u8],
    ) -> crate::Result<mithril_control::PolicyBundleV1> {
        let source_revision_id = "a".repeat(64);
        let binding_id = crate::runtime_admission::ScheduledRuntimeBindingV1::authority_binding_id(
            "aaaaaaaa-1111-4111-8111-111111111111",
            "converter",
        );
        let mut workload = WorkloadTargetFactV1 {
            node_id: "node-a".to_owned(),
            workload_binding_generation_digest: String::new(),
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            cluster_uid: "55555555-5555-4555-8555-555555555555".to_owned(),
            namespace_uid: "66666666-6666-4666-8666-666666666666".to_owned(),
            controller_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
            service_account_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
            pod_uid: "aaaaaaaa-1111-4111-8111-111111111111".to_owned(),
            container_id: format!("scheduled:{}", "b".repeat(64)),
            container_name: "converter".to_owned(),
            container_kind: mithril_control::ContainerKindV1::Application,
            image_digest: format!("sha256:{}", "c".repeat(64)),
            pod_labels: BTreeMap::new(),
            kubernetes: Some(KubernetesWorkloadIdentityV1 {
                namespace_name: "default".to_owned(),
                pod_name: "converter-0".to_owned(),
                profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                policy_source_revision_id: source_revision_id.clone(),
                binding_id,
                protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                workload_selector_id: "worker".to_owned(),
                kubernetes_node_name: kubernetes_node_name.to_owned(),
                kubernetes_node_uid: "node-uid-a".to_owned(),
                node_boot_id: hex::encode(node_boot_id),
                label_epoch: 7,
            }),
        };
        workload.workload_binding_generation_digest =
            mithril_control::workload_target_fact_digest(&workload).context(PolicySnafu)?;
        let signed_profile_digest = base.candidate.signed_profile_digest.clone();
        let target = PolicyTargetV1 {
            tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            cluster_uid: "55555555-5555-4555-8555-555555555555".to_owned(),
            node_id: "node-a".to_owned(),
            workload_binding_generation_digests: vec![workload
                .workload_binding_generation_digest
                .clone()],
            workload_targets: vec![workload],
        };
        let snapshot = PolicyTargetSnapshotV1::new(
            source_revision_id.clone(),
            signed_profile_digest.clone(),
            1,
            vec![target.clone()],
        )
        .context(PolicySnafu)?;
        let candidate = PolicyDeliveryCandidateV1::sign(
            target.tenant_id.clone(),
            source_revision_id,
            signed_profile_digest,
            &snapshot,
            target,
            PolicyDeliveryOperationV1::Activate,
            None,
            1,
            1,
            10,
            100,
            "test-key".to_owned(),
            key,
        )
        .context(PolicySnafu)?;
        mithril_control::PolicyBundleV1::new(
            candidate,
            base.profile_artifact,
            key.verifying_key().to_bytes().to_vec(),
        )
        .context(PolicySnafu)
    }

    fn trust(state_directory: &std::path::Path, key: &SigningKey) -> crate::Result<TrustCache> {
        let signer = PolicySignerTrust {
            signing_key_id: "test-key".to_owned(),
            ed25519_public_key: key.verifying_key().to_bytes().to_vec(),
            revoked: false,
        };
        let installed = BTreeMap::from([(
            signer.signing_key_id.clone(),
            InstalledPolicySignerV1 {
                ed25519_public_key_hex: hex::encode(&signer.ed25519_public_key),
                revoked: false,
            },
        )]);
        let digest = crate::trust::trust_bundle_digest(1, 1, &installed);
        let mut trust = TrustCache::load(state_directory)?;
        trust.install_with_policy(1, digest, 1, &[signer], &[1; 16])?;
        Ok(trust)
    }

    fn capabilities() -> Vec<CapabilityRecord> {
        ["EXACT_NATIVE_IDENTITY", "LOCAL_EFFECT_OBSERVATION"]
            .into_iter()
            .map(|capability_id| CapabilityRecord {
                capability_id: capability_id.to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "TEST_CAPABILITY".to_owned(),
            })
            .collect()
    }

    struct PendingExceptionFixture {
        config: NodeConfig,
        trust: TrustCache,
        key: SigningKey,
        scheduled: mithril_control::PolicyBundleV1,
        source: ExceptionSourceRevisionV1,
        target: WorkloadTargetFactV1,
        activation: ExceptionDeliveryCandidateV1,
        owner: NodePolicyDeliveryOwner,
    }

    fn pending_exception_fixture(
        state_directory: &std::path::Path,
    ) -> crate::Result<PendingExceptionFixture> {
        let static_config = config(state_directory);
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(state_directory, &key)?;
        let mut document = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../mithril-control/tests/fixtures/policy-v1.yaml"),
        )
        .context(PolicySnafu)?;
        document.rollout.desired_profile_mode = ProfileModeV1::Protect;
        document.file_exception_grants = vec![FileExceptionGrantTemplateV1 {
            grant_id: "temporary-file-access".to_owned(),
            denied_file_rule_ids: vec!["deny-projected-token-open".to_owned()],
            maximum_duration_ns: 300_000_000_000,
            maximum_uses: 1,
        }];
        let base = bundle_from_document(
            &static_config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            100,
            "node-a",
            document,
        )?;
        let scheduled = scheduled_bundle(base, &key, "worker-a", &[1; 16])?;
        let mut config = static_config;
        config.kubernetes_node_name = Some("worker-a".to_owned());
        config.runtime_admission = Some(RuntimeAdmissionConfig {
            socket_path: state_directory.join("runtime-admission.sock"),
            maximum_request_bytes: 64 * 1_024,
            timeout_ms: 10_000,
        });
        config.container_runtime = Some(ContainerRuntimeConfig {
            socket_path: state_directory.join("containerd.sock"),
            effect_controller_cgroup_path: state_directory.join("mithril-node-cgroup"),
            containerd_event_socket_path: None,
            reconciliation_interval_ms: 2_000,
        });
        config.workload_bindings.clear();
        config.validate()?;
        let mut owner = NodePolicyDeliveryOwner::load(state_directory)?;
        let prepared = owner.prepare_activation_for_session(
            &scheduled,
            &trust,
            &config,
            &capabilities(),
            2,
            20,
            &[1; 16],
            7,
        )?;
        owner.begin_activation(&scheduled, &prepared)?;
        owner.commit_activation(
            &scheduled,
            &prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;
        let resource: WorkloadProtectionException = serde_json::from_value(serde_json::json!({
            "apiVersion": "mithril.erebor.dev/v1alpha1",
            "kind": "WorkloadProtectionException",
            "metadata": {
                "name": "temporary-file-access",
                "namespace": "default",
                "uid": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "generation": 1,
                "resourceVersion": "exception-1"
            },
            "spec": {
                "policyRef": {"name": "profile"},
                "grant": "temporary-file-access",
                "target": {
                    "pod": {
                        "name": "converter-0",
                        "uid": "aaaaaaaa-1111-4111-8111-111111111111"
                    },
                    "containerName": "converter"
                },
                "requestedDuration": "30s",
                "requestedUses": 1
            }
        }))
        .context(super::JsonSnafu {
            path: "in-memory exception",
        })?;
        let source = ExceptionSourceRevisionV1::from_resource(
            &resource,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
            &scheduled.candidate.policy_source_revision_id,
            ExceptionSourceStateV1::Accepted,
        )
        .context(PolicySnafu)?;
        let target = scheduled.candidate.exact_target.workload_targets[0].clone();
        let activation = ExceptionDeliveryCandidateV1::sign(
            &source,
            scheduled.candidate.candidate_content_id.clone(),
            scheduled
                .profile_artifact
                .policy_document
                .profile_id()
                .to_owned(),
            2,
            target.clone(),
            ExceptionDeliveryOperationV1::Activate,
            1,
            50,
            None,
            1,
            1,
            22,
            100,
            "test-key".to_owned(),
            &key,
        )
        .context(PolicySnafu)?;
        let prepared_exception = owner.prepare_exception_delivery(
            activation.clone(),
            &trust,
            &config,
            &[1; 16],
            7,
            23,
        )?;
        let activation_json = serde_json::to_vec(&activation).context(super::JsonSnafu {
            path: "in-memory exception candidate",
        })?;
        owner.stage_exception_delivery(&prepared_exception, &activation_json, 23)?;
        Ok(PendingExceptionFixture {
            config,
            trust,
            key,
            scheduled,
            source,
            target,
            activation,
            owner,
        })
    }

    fn pending_policy_fixture(
        state_directory: &std::path::Path,
    ) -> crate::Result<(
        NodeConfig,
        TrustCache,
        mithril_control::PolicyBundleV1,
        NodePolicyDeliveryOwner,
    )> {
        let config = config(state_directory);
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(state_directory, &key)?;
        let candidate = bundle(
            &config,
            &key,
            1,
            1,
            PolicyDeliveryOperationV1::Activate,
            None,
            10,
            30,
            "node-a",
        )?;
        let mut owner = NodePolicyDeliveryOwner::load(state_directory)?;
        let prepared =
            owner.prepare_activation(&candidate, &trust, &config, &capabilities(), 2, 20)?;
        owner.begin_activation(&candidate, &prepared)?;
        drop(owner);
        Ok((
            config,
            trust,
            candidate,
            NodePolicyDeliveryOwner::load(state_directory)?,
        ))
    }

    fn config(state_directory: &std::path::Path) -> NodeConfig {
        NodeConfig {
            node_id: "node-a".to_owned(),
            kubernetes_node_name: None,
            state_directory: state_directory.to_owned(),
            interceptor: InterceptorConfig {
                runtime_btf_path: state_directory.join("vmlinux"),
                lease_path: state_directory.join("owner.lock"),
                pin_root: state_directory.join("pins"),
            },
            control: NodeControlConfig {
                endpoint: "https://127.0.0.1:7443".to_owned(),
                server_name: "mithril-control".to_owned(),
                ca_path: state_directory.join("ca.pem"),
                certificate_path: state_directory.join("node.pem"),
                private_key_path: state_directory.join("node-key.pem"),
                reconnect_minimum_ms: 100,
                reconnect_maximum_ms: 5_000,
            },
            evidence: Some(EvidenceConfig {
                tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                maximum_record_bytes: 128 * 1_024,
                maximum_retained_bytes: 16 * 1_024 * 1_024,
                maximum_retained_records: 10_000,
                maximum_batch_records: 256,
                maximum_control_delay_ms: 30_000,
                capacity_policy: crate::EvidenceWalCapacityPolicyV1::Block,
            }),
            runtime_observation: None,
            runtime_admission: None,
            container_runtime: None,
            workload_bindings: vec![WorkloadBindingConfig {
                binding_id: "99999999-9999-4999-8999-999999999999".to_owned(),
                scheduled_binding_authority_id: None,
                scheduled_target_digest: None,
                execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                protected_scope_id: "33333333-3333-4333-8333-333333333333".to_owned(),
                workload_selector_id: "worker".to_owned(),
                profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
                container_id: "a".repeat(64),
                namespace: "default".to_owned(),
                cluster_uid: "55555555-5555-4555-8555-555555555555".to_owned(),
                namespace_uid: "66666666-6666-4666-8666-666666666666".to_owned(),
                controller_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
                service_account_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
                pod_labels: BTreeMap::new(),
                pod_uid: "aaaaaaaa-1111-4111-8111-111111111111".to_owned(),
                sandbox_id: "sandbox".to_owned(),
                container_name: "converter".to_owned(),
                image_digest: "sha256:image".to_owned(),
                container_kind: ContainerKindV1::Application,
                container_generation: 1,
                root_cgroup_path: Some(state_directory.join("cgroup")),
                lifecycle_generation: 1,
                active_profile_generation_ref_id: 1,
                initial_role_id: 1,
                external_role_id: 2,
                arm_initial_root: false,
            }],
            policy_candidates: Vec::new(),
            administrative_authorization: None,
        }
    }
}
