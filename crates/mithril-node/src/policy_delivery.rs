use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use mithril_control::{
    CapabilityRecord, EntryKindV1, PolicyActivationAcknowledgement, PolicyBundleV1,
    PolicyDeliveryOperationV1, PolicyInventory, MAX_POLICY_BUNDLE_BYTES,
    MAX_POLICY_BUNDLE_CHUNK_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};

use crate::error::{ControlProtocolSnafu, IdentityStateSnafu, IoSnafu, JsonSnafu, PolicySnafu};
use crate::{
    ControlConnection, NodeConfig, PolicyCandidateConfig, Result, TrustCache, WorkloadBindingConfig,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
// This file is the durable recovery and anti-replay state for node policy delivery.
struct PolicyDeliveryStateV1 {
    active_candidate_content_id: Option<String>,
    active_bundle_digest: Option<String>,
    active_profiles: BTreeMap<String, ActivePolicyRecordV1>,
    pending_activation: Option<PendingPolicyRecordV1>,
    issuer_high_water: BTreeMap<String, SequenceV1>,
    distribution_high_water: BTreeMap<String, SequenceV1>,
    control_acknowledged_candidate_content_id: Option<String>,
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
    candidate_content_id: String,
    bundle_digest: String,
    profile_id: String,
    artifact_file: String,
    public_key_file: String,
    bundle_file: String,
    profile_generation_ref_id: u64,
    binding_ids: Vec<String>,
    #[serde(default)]
    scheduled_bindings: Vec<WorkloadBindingConfig>,
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

pub(crate) struct PreparedPolicyActivationV1 {
    pub config: NodeConfig,
    pub profile_id: String,
    pub binding_ids: Vec<String>,
    pub profile_generation_ref_id: u64,
}

pub(crate) struct PolicyActivationProofV1 {
    pub node_bound_generation_digest: String,
    pub readback_digest: String,
    pub probe_result_digest: String,
    pub observed_utc_ns: i64,
}

pub(crate) struct NodePolicyDeliveryOwner {
    root: PathBuf,
    state_path: PathBuf,
    transfer_path: PathBuf,
    state: PolicyDeliveryStateV1,
}

impl NodePolicyDeliveryOwner {
    pub(crate) fn load(state_directory: &Path) -> Result<Self> {
        let root = state_directory.join("policy-delivery-v1");
        let state_path = root.join("state.json");
        let transfer_path = root.join("transfer.json");
        fs::create_dir_all(root.join("bundles")).context(IoSnafu { path: &root })?;
        fs::create_dir_all(root.join("transfers")).context(IoSnafu { path: &root })?;
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
        let owner = Self {
            root,
            state_path,
            transfer_path,
            state,
        };
        // Invalid recovery state blocks policy delivery instead of dropping replay history.
        owner.validate_state()?;
        Ok(owner)
    }

    #[cfg(test)]
    pub(crate) fn restore_config(
        &self,
        config: &mut NodeConfig,
        trust: &TrustCache,
        now_utc_ns: i64,
    ) -> Result<()> {
        self.restore_config_inner(config, trust, now_utc_ns, None)
    }

    pub(crate) fn restore_config_for_session(
        &self,
        config: &mut NodeConfig,
        trust: &TrustCache,
        now_utc_ns: i64,
        node_boot_id: &[u8],
        label_epoch: u64,
    ) -> Result<()> {
        self.restore_config_inner(config, trust, now_utc_ns, Some((node_boot_id, label_epoch)))
    }

    fn restore_config_inner(
        &self,
        config: &mut NodeConfig,
        trust: &TrustCache,
        now_utc_ns: i64,
        session: Option<(&[u8], u64)>,
    ) -> Result<()> {
        // Rebuild dynamic config only from durable bundles that still pass current trust checks.
        for (profile_id, record) in &self.state.active_profiles {
            let artifact_path = self.checked_bundle_file(&record.artifact_file)?;
            let public_key_path = self.checked_bundle_file(&record.public_key_file)?;
            ensure!(
                artifact_path.is_file() && public_key_path.is_file(),
                IdentityStateSnafu {
                    reason: "the active policy cache has a missing artifact or public key",
                }
            );
            config.policy_candidates.retain(|candidate| {
                candidate.artifact_path != artifact_path
                    && candidate.public_key_path != public_key_path
            });
            config.policy_candidates.push(PolicyCandidateConfig {
                artifact_path,
                public_key_path,
                rollback_authorization_path: None,
                rollback_public_key_path: None,
            });
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
                .verify(&trusted_key, &config.node_id, record.observed_utc_ns)
                .context(PolicySnafu)?;
            // Scheduled authority does not survive a node boot or label-epoch change.
            if scheduled_session_matches(&bundle, config, session) {
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
        if let Some(pending) = &self.state.pending_activation {
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
            self.verify_pending_bundle(pending, &bundle, trust, config, now_utc_ns)?;
            config.policy_candidates.retain(|candidate| {
                candidate.artifact_path != artifact_path
                    && candidate.public_key_path != public_key_path
            });
            config.policy_candidates.push(PolicyCandidateConfig {
                artifact_path,
                public_key_path,
                rollback_authorization_path: None,
                rollback_public_key_path: None,
            });
            if scheduled_session_matches(&bundle, config, session) {
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

    pub(crate) async fn fetch_candidate(
        &mut self,
        connection: &mut ControlConnection,
    ) -> Result<Option<PolicyBundleV1>> {
        let inventory = connection
            .policy_inventory(
                self.active_candidate_content_id(),
                self.durable_bundle_digests(),
            )
            .await?;
        if !inventory.candidate_available {
            return Ok(None);
        }
        self.validate_inventory(&inventory)?;
        if self.state.active_candidate_content_id.as_deref()
            == Some(inventory.candidate_content_id.as_str())
        {
            return Ok(None);
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
        }
        let directory = self.transfer_directory(&inventory.bundle_digest);
        fs::create_dir_all(&directory).context(IoSnafu { path: &directory })?;
        for index in 0..inventory.chunk_count {
            let path = directory.join(format!("{index:08}.chunk"));
            // Digest readback makes a persisted chunk safe to reuse after restart.
            if self.transferred_chunk_is_valid(&transfer, index) {
                continue;
            }
            let chunk = connection
                .fetch_policy_chunk(
                    inventory.candidate_content_id.clone(),
                    inventory.bundle_digest.clone(),
                    index,
                )
                .await?;
            ensure!(
                chunk.candidate_content_id == inventory.candidate_content_id
                    && chunk.bundle_digest == inventory.bundle_digest
                    && chunk.chunk_index == index
                    && chunk.chunk_count == inventory.chunk_count
                    && chunk.payload.len() <= MAX_POLICY_BUNDLE_CHUNK_BYTES
                    && sha256(&chunk.payload) == chunk.chunk_sha256,
                ControlProtocolSnafu {
                    reason: "Control delivered an invalid policy chunk",
                }
            );
            write_atomic(&path, &chunk.payload)?;
            transfer.chunk_digests.insert(index, chunk.chunk_sha256);
            self.persist_transfer(&transfer)?;
        }
        let bytes = self.assemble_transfer(&transfer)?;
        let bundle: PolicyBundleV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &directory })?;
        ensure!(
            bundle.bundle_digest == inventory.bundle_digest
                && bundle.candidate.candidate_content_id == inventory.candidate_content_id,
            ControlProtocolSnafu {
                reason: "the assembled policy bundle differs from inventory",
            }
        );
        Ok(Some(bundle))
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
        self.prepare_activation_inner(
            bundle,
            trust,
            config,
            capabilities,
            profile_generation_ref_id,
            now_utc_ns,
            Some((node_boot_id, label_epoch)),
        )
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
                        candidate.operation == PolicyDeliveryOperationV1::Activate
                            && candidate.predecessor_candidate_content_id.is_none()
                    },
                    |current| {
                        matches!(
                            candidate.operation,
                            PolicyDeliveryOperationV1::Replace
                                | PolicyDeliveryOperationV1::RetireToRestrictiveTerminal
                        ) && candidate.predecessor_candidate_content_id.as_deref()
                            == Some(current.candidate_content_id.as_str())
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
        dynamic
            .policy_candidates
            .retain(|candidate| candidate.artifact_path != artifact_path);
        dynamic.policy_candidates.push(PolicyCandidateConfig {
            artifact_path,
            public_key_path,
            rollback_authorization_path: None,
            rollback_public_key_path: None,
        });
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
        })
    }

    pub(crate) fn commit_activation(
        &mut self,
        bundle: &PolicyBundleV1,
        prepared: &PreparedPolicyActivationV1,
        proof: PolicyActivationProofV1,
    ) -> Result<()> {
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
        self.persist_state()
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
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            profile_id: prepared.profile_id.clone(),
            artifact_file,
            public_key_file,
            bundle_file,
            profile_generation_ref_id: prepared.profile_generation_ref_id,
            binding_ids: prepared.binding_ids.clone(),
            scheduled_bindings: prepared_scheduled_bindings(prepared),
        });
        self.persist_state()
    }

    pub(crate) fn recover_pending_activation(
        &mut self,
        host: &erebor_interceptor::KernelHost,
        config: &NodeConfig,
    ) -> Result<()> {
        let Some(pending) = self.state.pending_activation.clone() else {
            return Ok(());
        };
        let bundle_path = self.checked_bundle_file(&pending.bundle_file)?;
        let bundle = self.read_bundle(&bundle_path)?;
        // Recover only when the kernel active pointer proves that the pending generation won.
        let receipt = crate::NodePolicyGenerationOwner::activation_receipt(
            host,
            &pending.profile_id,
            pending.profile_generation_ref_id,
        )?;
        self.commit_activation(
            &bundle,
            &PreparedPolicyActivationV1 {
                config: config.clone(),
                profile_id: pending.profile_id,
                binding_ids: pending.binding_ids,
                profile_generation_ref_id: pending.profile_generation_ref_id,
            },
            PolicyActivationProofV1 {
                node_bound_generation_digest: receipt.node_bound_generation_digest,
                readback_digest: receipt.readback_digest,
                probe_result_digest: receipt.probe_result_digest,
                observed_utc_ns: crate::policy::current_utc_ns()?,
            },
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

    pub(crate) fn acknowledge_control(&mut self, candidate_content_id: &str) -> Result<()> {
        ensure!(
            self.state.active_candidate_content_id.as_deref() == Some(candidate_content_id),
            IdentityStateSnafu {
                reason: "Control accepted an acknowledgement for a noncurrent candidate",
            }
        );
        self.state.control_acknowledged_candidate_content_id =
            Some(candidate_content_id.to_owned());
        self.persist_state()
    }

    pub(crate) fn record_runtime_binding(&mut self, binding: &WorkloadBindingConfig) -> Result<()> {
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
                && matches!(
                    inventory.operation.as_str(),
                    "ACTIVATE" | "REPLACE" | "RETIRE_TO_RESTRICTIVE_TERMINAL"
                ),
            ControlProtocolSnafu {
                reason: "Control delivered invalid policy inventory",
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

    fn validate_state(&self) -> Result<()> {
        ensure!(
            self.state
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
                        is_sha256(&pending.candidate_content_id)
                            && is_sha256(&pending.bundle_digest)
                            && uuid::Uuid::parse_str(&pending.profile_id)
                                .is_ok_and(|id| id.hyphenated().to_string() == pending.profile_id)
                            && pending.profile_generation_ref_id > 0
                            && !pending.binding_ids.is_empty()
                            && pending.binding_ids.windows(2).all(|pair| pair[0] < pair[1])
                            && !pending.bundle_file.is_empty()
                    }),
            IdentityStateSnafu {
                reason: "the durable policy delivery state is invalid",
            }
        );
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

    fn verify_pending_bundle(
        &self,
        pending: &PendingPolicyRecordV1,
        bundle: &PolicyBundleV1,
        trust: &TrustCache,
        config: &NodeConfig,
        now_utc_ns: i64,
    ) -> Result<()> {
        let key = trust.policy_signing_key(
            &bundle.candidate.signing_key_id,
            bundle.profile_artifact.header.sequence_epoch,
        )?;
        bundle
            .verify(&key, &config.node_id, now_utc_ns)
            .context(PolicySnafu)?;
        ensure!(
            pending.candidate_content_id == bundle.candidate.candidate_content_id
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

fn scheduled_session_matches(
    bundle: &PolicyBundleV1,
    config: &NodeConfig,
    session: Option<(&[u8], u64)>,
) -> bool {
    let targets = &bundle.candidate.exact_target.workload_targets;
    if targets.is_empty() {
        return false;
    }
    let Some((node_boot_id, label_epoch)) = session else {
        return false;
    };
    let Some(node_name) = config.kubernetes_node_name.as_deref() else {
        return false;
    };
    let boot_id = hex::encode(node_boot_id);
    targets.iter().all(|target| {
        target.kubernetes.as_ref().is_some_and(|identity| {
            target.node_id == config.node_id
                && identity.kubernetes_node_name == node_name
                && identity.node_boot_id == boot_id
                && identity.label_epoch == label_epoch
        })
    })
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

fn file_sha256(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
        CapabilityRecord, KubernetesWorkloadIdentityV1, PolicyCompiler, PolicyDeliveryCandidateV1,
        PolicyDocumentV1, PolicySignerTrust, PolicyTargetSnapshotV1, PolicyTargetV1,
        ProfileCandidateArtifactV1, ProfileSealRequestV1, RegistryDigestsV1, WorkloadTargetFactV1,
    };
    use sha2::{Digest as _, Sha256};
    use snafu::ResultExt as _;

    use super::{
        write_atomic, NodePolicyDeliveryOwner, PolicyActivationProofV1, PolicyDeliveryOperationV1,
        TransferStateV1,
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
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config(
            &mut restored,
            &trust,
            20,
        )?;
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

        let mut reloaded = NodePolicyDeliveryOwner::load(directory.path())?;
        assert!(reloaded.pending_acknowledgement().is_some());
        reloaded.acknowledge_control(&bundle.candidate.candidate_content_id)?;
        assert!(reloaded.pending_acknowledgement().is_none());
        assert!(reloaded
            .prepare_activation(&bundle, &trust, &config, &capabilities, 3, 22)
            .is_err());
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
    fn retirement_stages_the_restrictive_terminal_and_keeps_predecessor_order() -> crate::Result<()>
    {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary retirement policy directory",
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
        let active_prepared =
            owner.prepare_activation(&active, &trust, &config, &capabilities, 2, 20)?;
        owner.begin_activation(&active, &active_prepared)?;
        owner.commit_activation(
            &active,
            &active_prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "1".repeat(64),
                readback_digest: "2".repeat(64),
                probe_result_digest: "3".repeat(64),
                observed_utc_ns: 21,
            },
        )?;

        let retirement = bundle(
            &config,
            &key,
            2,
            2,
            PolicyDeliveryOperationV1::RetireToRestrictiveTerminal,
            Some(active.candidate.candidate_content_id.clone()),
            22,
            100,
            "node-a",
        )?;
        let retirement_prepared =
            owner.prepare_activation(&retirement, &trust, &config, &capabilities, 3, 23)?;
        assert_eq!(
            retirement_prepared.config.workload_bindings[0].active_profile_generation_ref_id,
            3
        );
        owner.begin_activation(&retirement, &retirement_prepared)?;
        owner.commit_activation(
            &retirement,
            &retirement_prepared,
            PolicyActivationProofV1 {
                node_bound_generation_digest: "4".repeat(64),
                readback_digest: "5".repeat(64),
                probe_result_digest: "6".repeat(64),
                observed_utc_ns: 24,
            },
        )?;
        assert_eq!(
            owner
                .pending_acknowledgement()
                .map(|acknowledgement| acknowledgement.candidate_content_id),
            Some(retirement.candidate.candidate_content_id.clone())
        );

        let wrong_predecessor = bundle(
            &config,
            &key,
            3,
            3,
            PolicyDeliveryOperationV1::RetireToRestrictiveTerminal,
            Some("f".repeat(64)),
            25,
            100,
            "node-a",
        )?;
        assert!(owner
            .prepare_activation(&wrong_predecessor, &trust, &config, &capabilities, 4, 26,)
            .is_err());
        Ok(())
    }

    #[test]
    fn interrupted_chunk_transfer_resumes_only_from_exact_durable_readback() -> crate::Result<()> {
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
        let owner = NodePolicyDeliveryOwner::load(directory.path())?;
        let mut transfer = TransferStateV1 {
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            bundle_digest: bundle.bundle_digest.clone(),
            bundle_bytes: u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX),
            chunk_count: 2,
            chunk_digests: BTreeMap::new(),
        };
        let transfer_directory = owner.transfer_directory(&bundle.bundle_digest);
        std::fs::create_dir_all(&transfer_directory).context(IoSnafu {
            path: &transfer_directory,
        })?;
        write_atomic(&transfer_directory.join("00000000.chunk"), chunks[0])?;
        transfer.chunk_digests.insert(0, super::sha256(chunks[0]));
        owner.persist_transfer(&transfer)?;

        let resumed = NodePolicyDeliveryOwner::load(directory.path())?;
        let mut transfer = resumed.load_transfer()?;
        assert!(resumed.transferred_chunk_is_valid(&transfer, 0));
        for (index, chunk) in chunks.iter().enumerate().skip(1) {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            write_atomic(&transfer_directory.join(format!("{index:08}.chunk")), chunk)?;
            transfer.chunk_digests.insert(index, super::sha256(chunk));
        }
        assert_eq!(resumed.assemble_transfer(&transfer)?, bundle_bytes);

        write_atomic(&transfer_directory.join("00000000.chunk"), b"tampered")?;
        assert!(!resumed.transferred_chunk_is_valid(&transfer, 0));
        assert!(resumed.assemble_transfer(&transfer).is_err());
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
        owner.record_runtime_binding(&runtime_binding)?;
        let mut restored = config.clone();
        restored.workload_bindings.clear();
        restored.policy_candidates.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut restored,
            &trust,
            22,
            &[1; 16],
            7,
        )?;
        assert_eq!(restored.workload_bindings.len(), 1);
        assert_eq!(
            restored.workload_bindings[0].binding_id,
            runtime_binding.binding_id
        );

        let mut new_boot = config;
        new_boot.workload_bindings.clear();
        new_boot.policy_candidates.clear();
        NodePolicyDeliveryOwner::load(directory.path())?.restore_config_for_session(
            &mut new_boot,
            &trust,
            22,
            &[2; 16],
            7,
        )?;
        assert!(new_boot.workload_bindings.is_empty());
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
