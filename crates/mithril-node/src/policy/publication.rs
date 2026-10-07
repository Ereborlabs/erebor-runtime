use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    AuthorityDomainStateV1, BindingActivationTargetKeyV1, BindingLifecycleStateV1,
    CanonicalMountRootKeyV1, CanonicalMountRootV1, ExecutionApprovalSlotStateV1,
    ExecutionApprovalSlotV1, ExecutionSetBindingStateV1, Id128V1, IoUringRequestStateV1,
    IoUringRingStateV1, PendingExecStateV1, PendingExecV1, PendingExecutionApprovalV1,
    PolicyGenerationStateV1, ProcessGenerationMigrationKeyV1, ProcessGenerationMigrationV1,
    ProcessSecurityStateKindV1, ProcessSecurityStateV1, ProfileGenerationDescriptorV1,
    ReferenceTombstoneStateV1, TaskReferenceTombstoneV1,
};
use mithril_control::{
    AntiRollbackStore, PendingProfileActivationV1, ProfileActivationMetadataV1,
    ValidatedProfileCandidateV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::{FromBytes as _, IntoBytes as _, KnownLayout, TryFromBytes};

use super::{
    ensure_map_capacity, insert_exact, parse_id, GenerationRows, GenerationSemantics, NativeTable,
    CANONICAL_MOUNT_CACHE_GENERATION_OFFSET_V1, CANONICAL_MOUNT_CACHE_KEY_SIZE_V1,
    CANONICAL_MOUNT_CACHE_SECURITY_VIEW_EPOCH_OFFSET_V1, CANONICAL_MOUNT_CACHE_STATE_KEY_SIZE_V1,
};
use crate::error::{IdentityStateSnafu, InterceptorSnafu, PolicySnafu};
use crate::{Result, WorkloadBindingConfig, WorkloadBindingOwner};

pub(super) const GENERATION_REFERENCES: [(&str, &str); 3] = [
    ("profile_generation_task_refs", "task"),
    ("profile_generation_async_refs", "async"),
    ("profile_generation_socket_refs", "socket"),
];

#[derive(Clone, Copy)]
pub(super) struct BindingActivationTarget {
    pub(super) initial_role_id: u32,
    pub(super) external_role_id: u32,
    pub(super) requires_live_cgroup: bool,
}

pub(super) struct ProfileActivation {
    pub(super) generation: u64,
    pub(super) bindings: BTreeMap<Id128V1, BindingActivationTarget>,
}

struct StagedActivationTarget {
    previous: Option<Vec<u8>>,
    desired: ExecutionSetBindingStateV1,
}

impl StagedActivationTarget {
    fn key(&self) -> BindingActivationTargetKeyV1 {
        BindingActivationTargetKeyV1 {
            binding_id: self.desired.binding_id,
            profile_generation_ref_id: self.desired.active_profile_generation_ref_id,
        }
    }
}

pub(super) fn prepare_declared_entry_requests(
    host: &KernelHost,
    desired: &BTreeSet<Vec<u8>>,
) -> Result<()> {
    let map = "declared_entry_requests";
    let capacity = host
        .manifest()
        .maps
        .iter()
        .find(|candidate| candidate.name == map)
        .map(|candidate| u64::from(candidate.max_entries))
        .context(IdentityStateSnafu {
            reason: "the declared-entry request map has no manifest capacity",
        })?;
    ensure_map_capacity(
        map,
        capacity,
        host.map_keys(map).context(InterceptorSnafu)?,
        desired.iter().cloned(),
    )?;
    for key in desired {
        host.update_map(map, key, &[1]).context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map(map, key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some([1].as_slice()),
            IdentityStateSnafu {
                reason: "a declared-entry request failed exact readback",
            }
        );
    }
    Ok(())
}

pub(super) fn retire_undeclared_entry_requests(
    host: &KernelHost,
    desired: &BTreeSet<Vec<u8>>,
) -> Result<()> {
    let map = "declared_entry_requests";
    for key in host.map_keys(map).context(InterceptorSnafu)? {
        if desired.contains(&key) {
            continue;
        }
        host.delete_map_entry(map, &key).context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map(map, &key)
                .context(InterceptorSnafu)?
                .is_none(),
            IdentityStateSnafu {
                reason: "an undeclared entry request remained after retirement",
            }
        );
    }
    Ok(())
}

pub(super) fn reconcile_pending_activations(
    host: &KernelHost,
    rollback: &mut AntiRollbackStore,
    node_boot_id: Id128V1,
    label_epoch: u64,
) -> Result<()> {
    let node_boot_id = id_bytes(node_boot_id);
    for pending in rollback.pending_activations() {
        if pending.activation.node_boot_id != node_boot_id
            || pending.activation.label_epoch != label_epoch
        {
            rollback
                .clear_old_epoch_pending(&pending)
                .context(PolicySnafu)?;
            continue;
        }
        let profile_id = parse_id("pending profile_id", &pending.profile_id)?;
        let observed = read_active_generation(host, &profile_id)?;
        if observed == Some(pending.activation.profile_generation_ref_id) {
            verify_pending_descriptor(host, &pending)?;
            rollback.finalize_pending(&pending).context(PolicySnafu)?;
        } else {
            ensure!(
                observed == pending.previous_profile_generation_ref_id,
                IdentityStateSnafu {
                    reason: format!(
                        "pending profile `{}` has a missing or unexpected active pointer",
                        pending.profile_id
                    ),
                }
            );
        }
    }
    Ok(())
}

fn verify_pending_descriptor(
    host: &KernelHost,
    pending: &PendingProfileActivationV1,
) -> Result<()> {
    let descriptor = host
        .lookup_map(
            "profile_generation_descriptors",
            &pending.activation.profile_generation_ref_id.to_ne_bytes(),
        )
        .context(InterceptorSnafu)?
        .context(IdentityStateSnafu {
            reason: "committed pending activation has no generation descriptor",
        })?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&descriptor)) == pending.activation.descriptor_sha256,
        IdentityStateSnafu {
            reason: "committed pending activation descriptor failed durable digest proof",
        }
    );
    Ok(())
}

pub(super) fn read_active_generation(
    host: &KernelHost,
    profile_id: &Id128V1,
) -> Result<Option<u64>> {
    host.lookup_map("active_profile_generations", profile_id.as_bytes())
        .context(InterceptorSnafu)?
        .as_deref()
        .map(|bytes| {
            u64::read_from_bytes(bytes).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("active generation pointer is invalid: {error}"),
                }
                .build()
            })
        })
        .transpose()
}

fn id_bytes(id: Id128V1) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(id.as_bytes());
    bytes
}

pub(super) fn build_process_generation_migrations<'a>(
    activations: impl IntoIterator<Item = (&'a Id128V1, &'a ProfileActivation)>,
    generations: &BTreeMap<u64, GenerationSemantics>,
) -> Result<GenerationRows> {
    let mut rows = GenerationRows::new();
    for (profile_id, activation) in activations {
        let target = generations
            .get(&activation.generation)
            .context(IdentityStateSnafu {
                reason: "active target generation has no semantic handle map",
            })?;
        ensure!(
            target.profile_id == *profile_id,
            IdentityStateSnafu {
                reason: "active target generation has the wrong semantic profile",
            }
        );
        for (source_generation, source) in generations.iter().filter(|(generation, source)| {
            **generation != activation.generation && source.profile_id == *profile_id
        }) {
            for (role_name, state_name) in &source.live_role_states {
                let Some(target_role_id) = target.role_handles.get(role_name) else {
                    continue;
                };
                let Some((target_state_id, target_state_bits)) =
                    target.process_state_handles.get(state_name)
                else {
                    continue;
                };
                if !target
                    .live_role_states
                    .contains(&(role_name.clone(), state_name.clone()))
                {
                    continue;
                }
                let (source_state_id, source_state_bits) = source.process_state_handles[state_name];
                let key = ProcessGenerationMigrationKeyV1 {
                    source_profile_generation_ref_id: *source_generation,
                    target_profile_generation_ref_id: activation.generation,
                    source_state_bits,
                    source_role_id: source.role_handles[role_name],
                    source_process_state_vector_id: source_state_id,
                };
                let value = ProcessGenerationMigrationV1 {
                    target_state_bits: *target_state_bits,
                    target_role_id: *target_role_id,
                    target_process_state_vector_id: *target_state_id,
                };
                insert_exact(&mut rows, key.as_bytes(), value.as_bytes())?;
            }
        }
    }
    Ok(rows)
}

impl ProfileActivation {
    pub(super) fn add_binding(
        &mut self,
        binding_id: Id128V1,
        binding: &WorkloadBindingConfig,
    ) -> Result<()> {
        ensure!(
            self.generation == binding.active_profile_generation_ref_id,
            IdentityStateSnafu {
                reason: format!(
                    "profile `{}` cannot activate more than one node generation",
                    binding.profile_id
                ),
            }
        );
        ensure!(
            self.bindings
                .insert(
                    binding_id,
                    BindingActivationTarget {
                        initial_role_id: binding.initial_role_id,
                        external_role_id: binding.external_role_id,
                        requires_live_cgroup: binding.root_cgroup_path.is_some()
                            && binding.scheduled_binding_authority_id.is_none(),
                    },
                )
                .is_none(),
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` occurs more than once in one activation",
                    binding.binding_id
                ),
            }
        );
        Ok(())
    }

    pub(super) fn publish(
        &self,
        host: &KernelHost,
        profile_id: &Id128V1,
        rollback: &mut AntiRollbackStore,
        validated: &ValidatedProfileCandidateV1,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<()> {
        let descriptor_key = self.generation.to_ne_bytes();
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: format!("generation {} has no staged descriptor", self.generation),
            })?;
        let descriptor_sha256 = Sha256::digest(&descriptor).into();
        let descriptor =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("staged generation descriptor is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            descriptor.state == PolicyGenerationStateV1::Active
                && descriptor.profile_generation_ref_id == self.generation
                && descriptor.profile_id == *profile_id,
            IdentityStateSnafu {
                reason: "staged generation descriptor does not match its activation",
            }
        );
        for (map, kind) in GENERATION_REFERENCES {
            ensure_generation_reference_row(host, map, self.generation, kind)?;
        }

        let pointer_key = profile_id.as_bytes();
        let expected_pointer = host
            .lookup_map("active_profile_generations", pointer_key)
            .context(InterceptorSnafu)?;
        let expected_generation = expected_pointer
            .as_deref()
            .map(|bytes| {
                u64::read_from_bytes(bytes).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("active generation pointer is invalid: {error}"),
                    }
                    .build()
                })
            })
            .transpose()?;

        let mut targets = BTreeMap::new();
        for key in host
            .map_keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let value = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "execution-set binding disappeared during activation",
                })?;
            let binding =
                ExecutionSetBindingStateV1::try_read_from_bytes(&value).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("execution-set binding is invalid: {error}"),
                    }
                    .build()
                })?;
            if binding.profile_id != *profile_id
                || !crate::identity::binding_lifecycle_is_addressable(binding.lifecycle_state)
            {
                continue;
            }
            let target = self
                .bindings
                .get(&binding.binding_id)
                .context(IdentityStateSnafu {
                    reason: "active profile contains a binding outside this activation",
                })?;
            let mut desired = binding;
            desired.lifecycle_state = BindingLifecycleStateV1::Active;
            desired.active_profile_generation_ref_id = self.generation;
            desired.initial_role_id = target.initial_role_id;
            desired.external_role_id = target.external_role_id;
            ensure!(
                targets
                    .insert(
                        binding.binding_id,
                        StagedActivationTarget {
                            previous: None,
                            desired,
                        },
                    )
                    .is_none(),
                IdentityStateSnafu {
                    reason: "one binding identity names more than one active cgroup",
                }
            );
        }
        // Scheduled placeholders can activate before a live cgroup exists; static bindings cannot.
        ensure!(
            self.bindings.iter().all(|(binding_id, target)| {
                !target.requires_live_cgroup || targets.contains_key(binding_id)
            }),
            IdentityStateSnafu {
                reason: "not every cgroup-backed activation binding is live",
            }
        );
        for target in targets.values_mut() {
            let key = target.key();
            let previous = host
                .lookup_map("binding_activation_targets", key.as_bytes())
                .context(InterceptorSnafu)?;
            let previous_target = previous
                .as_deref()
                .map(ExecutionSetBindingStateV1::try_read_from_bytes)
                .transpose()
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("binding activation target is invalid: {error}"),
                    }
                    .build()
                })?;
            ensure!(
                previous_target.as_ref().is_none_or(|previous| {
                    WorkloadBindingOwner::activation_target_matches_desired(
                        &target.desired,
                        previous,
                    )
                }),
                IdentityStateSnafu {
                    reason: "generation-keyed binding activation target is immutable",
                }
            );
            target.previous = previous;
        }

        let stage_result = (|| {
            for target in targets.values() {
                let key = target.key();
                if target.previous.is_none() {
                    ensure!(
                        host.insert_map(
                            "binding_activation_targets",
                            key.as_bytes(),
                            target.desired.as_bytes(),
                        )
                        .context(InterceptorSnafu)?
                            == MapInsertResult::Inserted,
                        IdentityStateSnafu {
                            reason: "binding activation target changed during staging",
                        }
                    );
                }
                let observed = host
                    .lookup_map("binding_activation_targets", key.as_bytes())
                    .context(InterceptorSnafu)?
                    .context(IdentityStateSnafu {
                        reason: "binding activation target disappeared during staging",
                    })?;
                let observed = ExecutionSetBindingStateV1::try_read_from_bytes(&observed).map_err(
                    |error| {
                        IdentityStateSnafu {
                            reason: format!("binding activation target is invalid: {error}"),
                        }
                        .build()
                    },
                )?;
                ensure!(
                    WorkloadBindingOwner::activation_target_matches_desired(
                        &target.desired,
                        &observed,
                    ),
                    IdentityStateSnafu {
                        reason: "binding activation target failed readback",
                    }
                );
            }
            Ok(())
        })();
        if let Err(error) = stage_result {
            return match restore_activation_targets(host, &targets) {
                Ok(()) => Err(error),
                Err(rollback) => IdentityStateSnafu {
                    reason: format!(
                        "binding activation failed: {error}; target rollback failed: {rollback}"
                    ),
                }
                .fail(),
            };
        }

        for planned in targets.values() {
            let key = planned.key();
            let target = host
                .lookup_map("binding_activation_targets", key.as_bytes())
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "binding activation target disappeared before publication",
                })?;
            let target =
                ExecutionSetBindingStateV1::try_read_from_bytes(&target).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("binding activation target is invalid: {error}"),
                    }
                    .build()
                })?;
            ensure!(
                WorkloadBindingOwner::same_activation_identity(&planned.desired, &target)
                    && target.active_profile_generation_ref_id == self.generation,
                IdentityStateSnafu {
                    reason: "binding activation target changed before publication",
                }
            );
        }

        let observed = host
            .lookup_map("active_profile_generations", pointer_key)
            .context(InterceptorSnafu)?;
        if let Err(error) =
            ensure_active_generation_unchanged(expected_pointer.as_deref(), observed.as_deref())
        {
            return match restore_activation_targets(host, &targets) {
                Ok(()) => Err(error),
                Err(rollback) => IdentityStateSnafu {
                    reason: format!(
                        "active pointer changed: {error}; target rollback failed: {rollback}"
                    ),
                }
                .fail(),
            };
        }

        let activation_metadata = ProfileActivationMetadataV1 {
            profile_generation_ref_id: self.generation,
            node_boot_id: id_bytes(node_boot_id),
            label_epoch,
            descriptor_sha256,
        };
        if expected_generation == Some(self.generation)
            && rollback.is_current_activation(validated, &activation_metadata)
        {
            return Ok(());
        }
        let pending = rollback
            .prepare_activation(validated, activation_metadata, expected_generation)
            .context(PolicySnafu)?;
        if expected_generation == Some(self.generation) {
            rollback.finalize_pending(&pending).context(PolicySnafu)?;
            return Ok(());
        }

        let target = self.generation.to_ne_bytes();
        if let Err(error) = host
            .update_map("active_profile_generations", pointer_key, &target)
            .context(InterceptorSnafu)
        {
            let observed = host
                .lookup_map("active_profile_generations", pointer_key)
                .context(InterceptorSnafu)?;
            if observed.as_deref() == expected_pointer.as_deref() {
                return match restore_activation_targets(host, &targets) {
                    Ok(()) => Err(error),
                    Err(target_rollback) => IdentityStateSnafu {
                        reason: format!(
                            "active-generation update failed: {error}; target rollback failed: {target_rollback}"
                        ),
                    }
                    .fail(),
                };
            }
            if observed.as_deref() == Some(target.as_slice()) {
                rollback.finalize_pending(&pending).context(PolicySnafu)?;
                return Ok(());
            }
            return IdentityStateSnafu {
                reason: format!(
                    "active-generation update failed with an ambiguous committed pointer: {error}"
                ),
            }
            .fail();
        }
        let committed = host
            .lookup_map("active_profile_generations", pointer_key)
            .context(InterceptorSnafu)
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!(
                        "active-generation publication committed, but readback failed: {error}"
                    ),
                }
                .build()
            })?;
        ensure_committed_generation(&target, committed.as_deref())?;
        rollback.finalize_pending(&pending).context(PolicySnafu)
    }
}

fn ensure_generation_reference_row(
    host: &KernelHost,
    map: &str,
    generation: u64,
    kind: &str,
) -> Result<()> {
    let key = generation.to_ne_bytes();
    if let Some(references) = host.lookup_map(map, &key).context(InterceptorSnafu)? {
        u64::read_from_bytes(&references).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("generation {kind} references are invalid: {error}"),
            }
            .build()
        })?;
        return Ok(());
    }
    let zero = 0_u64.to_ne_bytes();
    host.update_map(map, &key, &zero)
        .context(InterceptorSnafu)?;
    ensure!(
        host.lookup_map(map, &key)
            .context(InterceptorSnafu)?
            .as_deref()
            == Some(zero.as_slice()),
        IdentityStateSnafu {
            reason: format!("generation {kind}-reference row failed readback"),
        }
    );
    Ok(())
}

pub(super) fn ensure_committed_generation(target: &[u8], observed: Option<&[u8]>) -> Result<()> {
    ensure!(
        observed == Some(target),
        IdentityStateSnafu {
            reason: "active-generation publication committed, but readback did not match",
        }
    );
    Ok(())
}

fn restore_activation_targets(
    host: &KernelHost,
    targets: &BTreeMap<Id128V1, StagedActivationTarget>,
) -> Result<()> {
    for target in targets.values() {
        let key = target.key();
        if target.previous.is_none()
            && host
                .lookup_map("binding_activation_targets", key.as_bytes())
                .context(InterceptorSnafu)?
                .is_some()
        {
            host.delete_map_entry("binding_activation_targets", key.as_bytes())
                .context(InterceptorSnafu)?;
        }
        ensure!(
            host.lookup_map("binding_activation_targets", key.as_bytes())
                .context(InterceptorSnafu)?
                .as_deref()
                == target.previous.as_deref(),
            IdentityStateSnafu {
                reason: "binding activation target rollback failed readback",
            }
        );
    }
    Ok(())
}

pub(super) fn ensure_active_generation_unchanged(
    expected: Option<&[u8]>,
    observed: Option<&[u8]>,
) -> Result<()> {
    ensure!(
        expected == observed,
        IdentityStateSnafu {
            reason: "active-generation handle changed during serialized publication",
        }
    );
    Ok(())
}

pub(super) fn reconcile_generation_retirement(
    host: &KernelHost,
    node_boot_id: Id128V1,
    label_epoch: u64,
) -> Result<bool> {
    let mut pending = false;
    let active_generations = host
        .map_keys("active_profile_generations")
        .context(InterceptorSnafu)?
        .into_iter()
        .map(|key| {
            host.lookup_map("active_profile_generations", &key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "active profile generation disappeared during retirement",
                })
                .and_then(|value| {
                    u64::read_from_bytes(&value).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!("active profile generation is invalid: {error}"),
                        }
                        .build()
                    })
                })
        })
        .collect::<Result<BTreeSet<_>>>()?;

    for descriptor_key in host
        .map_keys("profile_generation_descriptors")
        .context(InterceptorSnafu)?
    {
        let Some(bytes) = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let mut descriptor = read_abi_value::<ProfileGenerationDescriptorV1>(
            &bytes,
            "profile generation descriptor",
        )?;
        if descriptor.node_boot_id != node_boot_id || descriptor.label_epoch != label_epoch {
            return IdentityStateSnafu {
                reason: "profile generation survived a node boot or label epoch change".to_owned(),
            }
            .fail();
        }
        let generation = descriptor.profile_generation_ref_id;
        ensure!(
            descriptor_key.as_slice() == generation.to_ne_bytes(),
            IdentityStateSnafu {
                reason: "profile generation descriptor key does not match its value",
            }
        );
        if active_generations.contains(&generation) {
            ensure!(
                descriptor.state == PolicyGenerationStateV1::Active,
                IdentityStateSnafu {
                    reason: "active profile pointer names a non-ACTIVE generation",
                }
            );
            continue;
        }
        if descriptor.state == PolicyGenerationStateV1::Active {
            descriptor.state = PolicyGenerationStateV1::Retiring;
            descriptor.transition_version =
                descriptor
                    .transition_version
                    .checked_add(1)
                    .context(IdentityStateSnafu {
                        reason: "profile generation transition version exhausted",
                    })?;
            host.update_map(
                "profile_generation_descriptors",
                &descriptor_key,
                descriptor.as_bytes(),
            )
            .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("profile_generation_descriptors", &descriptor_key)
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(descriptor.as_bytes()),
                IdentityStateSnafu {
                    reason: "RETIRING profile generation failed readback",
                }
            );
        }
        ensure!(
            matches!(
                descriptor.state,
                PolicyGenerationStateV1::Retiring | PolicyGenerationStateV1::Tombstoned
            ),
            IdentityStateSnafu {
                reason: "inactive profile generation has an invalid lifecycle state",
            }
        );
        if descriptor.state == PolicyGenerationStateV1::Retiring
            && generation_has_retained_authority(host, generation)?
        {
            pending = true;
            continue;
        }
        retire_generation_rows(host, generation, &mut descriptor, &descriptor_key)?;
    }
    Ok(pending)
}

fn generation_has_retained_authority(host: &KernelHost, generation: u64) -> Result<bool> {
    let reference_key = generation.to_ne_bytes();
    for (map, kind) in GENERATION_REFERENCES {
        let references = host
            .lookup_map(map, &reference_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: format!("RETIRING generation lost its {kind}-reference row"),
            })?;
        if u64::read_from_bytes(&references).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("generation {kind} references are invalid: {error}"),
            }
            .build()
        })? != 0
        {
            return Ok(true);
        }
    }

    for key in host
        .map_keys("io_uring_ring_states")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("io_uring_ring_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<IoUringRingStateV1>(&value, "io_uring ring state")?
            .owner
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("io_uring_request_states")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("io_uring_request_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<IoUringRequestStateV1>(&value, "io_uring request state")?
            .actor
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }

    for key in host.map_keys("process_states").context(InterceptorSnafu)? {
        let Some(value) = host
            .lookup_map("process_states", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let process = read_abi_value::<ProcessSecurityStateV1>(&value, "process state")?;
        if process.active_profile_generation_ref_id == generation
            && (process.live_thread_refs != 0
                || process.state != ProcessSecurityStateKindV1::Reclaimable)
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("authority_domains")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("authority_domains", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let domain = read_abi_value::<AuthorityDomainStateV1>(&value, "authority domain")?;
        if domain.retained_generation_set_ref_id == generation
            && (domain.live_process_refs != 0
                || domain.response_plan_refs != 0
                || domain.reconciliation_hold_refs != 0)
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("task_reference_tombstones")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("task_reference_tombstones", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let tombstone =
            read_abi_value::<TaskReferenceTombstoneV1>(&value, "task reference tombstone")?;
        if tombstone.profile_generation_ref_id == generation
            && tombstone.state != ReferenceTombstoneStateV1::Released
            && tombstone.state != ReferenceTombstoneStateV1::Reclaimable
        {
            return Ok(true);
        }
    }
    for key in host.map_keys("pending_execs").context(InterceptorSnafu)? {
        let Some(value) = host
            .lookup_map("pending_execs", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let pending = read_abi_value::<PendingExecV1>(&value, "pending exec")?;
        if pending.source_profile_generation_ref_id == generation
            && pending_exec_retains_generation_authority(pending.state)
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("pending_execution_approvals")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("pending_execution_approvals", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        if read_abi_value::<PendingExecutionApprovalV1>(&value, "pending execution approval")?
            .profile_generation_ref_id
            == generation
        {
            return Ok(true);
        }
    }
    for key in host
        .map_keys("execution_approval_slots")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("execution_approval_slots", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let slot = read_abi_value::<ExecutionApprovalSlotV1>(&value, "execution approval slot")?;
        if slot.profile_generation_ref_id == generation
            && matches!(
                slot.state,
                ExecutionApprovalSlotStateV1::Armed | ExecutionApprovalSlotStateV1::Reserved
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn pending_exec_retains_generation_authority(state: PendingExecStateV1) -> bool {
    matches!(
        state,
        PendingExecStateV1::Unknown
            | PendingExecStateV1::Preparing
            | PendingExecStateV1::CommitPending
    )
}

pub(crate) fn generation_publication_is_absent(host: &KernelHost, generation: u64) -> Result<bool> {
    if host
        .lookup_map("profile_generation_descriptors", &generation.to_ne_bytes())
        .context(InterceptorSnafu)?
        .is_some()
    {
        return Ok(false);
    }
    for key in host
        .map_keys("binding_activation_targets")
        .context(InterceptorSnafu)?
    {
        let key = BindingActivationTargetKeyV1::try_read_from_bytes(&key).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("binding activation target key is invalid: {error}"),
            }
            .build()
        })?;
        if key.profile_generation_ref_id == generation {
            return Ok(false);
        }
    }
    for key in host
        .map_keys("execution_set_bindings")
        .context(InterceptorSnafu)?
    {
        let Some(value) = host
            .lookup_map("execution_set_bindings", &key)
            .context(InterceptorSnafu)?
        else {
            continue;
        };
        let binding = ExecutionSetBindingStateV1::try_read_from_bytes(&value).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("execution-set binding is invalid: {error}"),
            }
            .build()
        })?;
        if binding.active_profile_generation_ref_id == generation {
            return Ok(false);
        }
    }
    Ok(true)
}

fn retire_generation_rows(
    host: &KernelHost,
    generation: u64,
    descriptor: &mut ProfileGenerationDescriptorV1,
    descriptor_key: &[u8],
) -> Result<()> {
    if generation_retirement_needs_tombstone(descriptor.state)? {
        descriptor.state = PolicyGenerationStateV1::Tombstoned;
        descriptor.transition_version =
            descriptor
                .transition_version
                .checked_add(1)
                .context(IdentityStateSnafu {
                    reason: "profile generation transition version exhausted",
                })?;
        host.update_map(
            "profile_generation_descriptors",
            descriptor_key,
            descriptor.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("profile_generation_descriptors", descriptor_key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(descriptor.as_bytes()),
            IdentityStateSnafu {
                reason: "TOMBSTONED profile generation failed readback",
            }
        );
    }
    ensure!(
        descriptor.state == PolicyGenerationStateV1::Tombstoned,
        IdentityStateSnafu {
            reason: "generation row retirement requires a TOMBSTONED descriptor",
        }
    );

    // A persisted tombstone resumes deletion here after any earlier process exit.
    let mut tables = NativeTable::ALL;
    tables.sort_by_key(|table| table.retirement());
    for table in tables {
        if matches!(table.retirement(), Some((_, 0))) {
            delete_generation_prefixed_rows(host, table.map_name(), generation, 0)?;
        }
    }
    delete_process_generation_migrations(host, generation)?;
    for table in tables {
        if matches!(table.retirement(), Some((_, 8))) {
            delete_generation_prefixed_rows(host, table.map_name(), generation, 8)?;
        }
    }
    delete_generation_prefixed_rows(host, "binding_activation_targets", generation, 16)?;
    for (map, _) in GENERATION_REFERENCES {
        host.delete_map_entry(map, &generation.to_ne_bytes())
            .context(InterceptorSnafu)?;
    }
    host.delete_map_entry("profile_generation_descriptors", descriptor_key)
        .context(InterceptorSnafu)?;
    ensure!(
        host.lookup_map("profile_generation_descriptors", descriptor_key)
            .context(InterceptorSnafu)?
            .is_none(),
        IdentityStateSnafu {
            reason: "retired profile generation descriptor survived deletion",
        }
    );
    Ok(())
}

pub(super) fn generation_retirement_needs_tombstone(
    state: PolicyGenerationStateV1,
) -> Result<bool> {
    ensure!(
        matches!(
            state,
            PolicyGenerationStateV1::Retiring | PolicyGenerationStateV1::Tombstoned
        ),
        IdentityStateSnafu {
            reason: "generation row retirement has an invalid lifecycle state",
        }
    );
    Ok(state == PolicyGenerationStateV1::Retiring)
}

fn delete_generation_prefixed_rows(
    host: &KernelHost,
    map: &str,
    generation: u64,
    offset: usize,
) -> Result<()> {
    for key in host.map_keys(map).context(InterceptorSnafu)? {
        let end = offset
            .checked_add(size_of::<u64>())
            .context(IdentityStateSnafu {
                reason: "generation key offset overflow",
            })?;
        ensure!(
            key.len() >= end,
            IdentityStateSnafu {
                reason: format!("map `{map}` has a truncated generation key"),
            }
        );
        let mut bytes = [0; size_of::<u64>()];
        bytes.copy_from_slice(&key[offset..end]);
        if u64::from_ne_bytes(bytes) == generation {
            host.delete_map_entry(map, &key).context(InterceptorSnafu)?;
        }
    }
    Ok(())
}

fn delete_process_generation_migrations(host: &KernelHost, generation: u64) -> Result<()> {
    for key in host
        .map_keys("process_generation_migrations")
        .context(InterceptorSnafu)?
    {
        let migration = read_abi_value::<ProcessGenerationMigrationKeyV1>(
            &key,
            "process generation migration key",
        )?;
        if migration.source_profile_generation_ref_id == generation
            || migration.target_profile_generation_ref_id == generation
        {
            host.delete_map_entry("process_generation_migrations", &key)
                .context(InterceptorSnafu)?;
        }
    }
    Ok(())
}

pub(super) fn install_rows<'a>(
    host: &KernelHost,
    map: &str,
    rows: impl IntoIterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>,
) -> Result<()> {
    for (key, value) in rows {
        host.update_map(map, key, value).context(InterceptorSnafu)?;
        let actual = host.lookup_map(map, key).context(InterceptorSnafu)?;
        ensure!(
            actual.as_ref() == Some(value),
            IdentityStateSnafu {
                reason: row_readback_failure("install", map, key, value, actual.as_deref()),
            }
        );
    }
    Ok(())
}

pub(super) fn verify_rows<'a>(
    host: &KernelHost,
    map: &str,
    rows: impl IntoIterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>,
) -> Result<()> {
    for (key, value) in rows {
        let actual = host.lookup_map(map, key).context(InterceptorSnafu)?;
        ensure!(
            actual.as_ref() == Some(value),
            IdentityStateSnafu {
                reason: row_readback_failure("verification", map, key, value, actual.as_deref()),
            }
        );
    }
    Ok(())
}

fn row_readback_failure(
    stage: &str,
    map: &str,
    key_bytes: &[u8],
    expected_bytes: &[u8],
    actual_bytes: Option<&[u8]>,
) -> String {
    if map == "canonical_mount_roots" {
        let key = CanonicalMountRootKeyV1::try_read_from_bytes(key_bytes);
        let expected = CanonicalMountRootV1::try_read_from_bytes(expected_bytes);
        let actual =
            actual_bytes.and_then(|bytes| CanonicalMountRootV1::try_read_from_bytes(bytes).ok());
        if let (Ok(key), Ok(expected)) = (key, expected) {
            return format!(
                "candidate `{map}` row {stage} readback failed: profile_generation_ref_id={}, binding_id={:016x}{:016x}, topology_generation={}, root_inode={}, mount_namespace_inode={}, filesystem_device={}, expected_selected_mount_id_unique={}, expected_snapshot_digest_id={}, expected_graph_prefix_state_ids={:?}, expected_graph_prefix_state_count={}, actual={actual:?}",
                key.profile_generation_ref_id,
                key.binding_id.high,
                key.binding_id.low,
                key.topology_generation,
                key.root_inode,
                key.mount_namespace_inode,
                key.filesystem_device,
                expected.selected_mount_id_unique,
                expected.snapshot_digest_id,
                &expected.graph_prefix_state_ids[..expected.graph_prefix_state_count as usize],
                expected.graph_prefix_state_count,
            );
        }
    }
    format!(
        "candidate `{map}` row {stage} readback failed: key={}, expected={}, actual={}",
        hex::encode(key_bytes),
        hex::encode(expected_bytes),
        actual_bytes.map_or_else(|| "missing".to_owned(), hex::encode),
    )
}

pub(super) fn install_missing_rows<'a>(
    host: &KernelHost,
    map: &str,
    rows: impl IntoIterator<Item = (&'a Vec<u8>, &'a Vec<u8>)>,
) -> Result<()> {
    for (key, value) in rows {
        if host
            .lookup_map(map, key)
            .context(InterceptorSnafu)?
            .is_none()
        {
            host.update_map(map, key, value).context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map(map, key)
                    .context(InterceptorSnafu)?
                    .as_ref()
                    == Some(value),
                IdentityStateSnafu {
                    reason: format!("candidate `{map}` mutable row readback failed"),
                }
            );
        }
    }
    Ok(())
}

pub(super) fn mount_epoch_from(host: &KernelHost, map: &str, key: &[u8]) -> Result<u64> {
    let bytes = host
        .lookup_map(map, key)
        .context(InterceptorSnafu)?
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("mount mutation epoch `{map}` disappeared during reconciliation"),
            }
            .build()
        })?;
    u64::read_from_bytes(&bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("mount mutation epoch has an invalid ABI value: {error}"),
        }
        .build()
    })
}

pub(super) fn retire_unreachable_mount_cache_rows(host: &KernelHost) -> Result<()> {
    let global_key = 0_u32.to_ne_bytes();
    let security_view_epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)?;
    let cache_generation = mount_epoch_from(host, "canonical_mount_cache_generation", &global_key)?;
    for (map, key_size) in [
        (
            "canonical_mount_cache_states",
            CANONICAL_MOUNT_CACHE_STATE_KEY_SIZE_V1,
        ),
        ("canonical_mount_cache", CANONICAL_MOUNT_CACHE_KEY_SIZE_V1),
    ] {
        for key in host.map_keys(map).context(InterceptorSnafu)? {
            if mount_cache_row_is_unreachable(
                map,
                &key,
                key_size,
                security_view_epoch,
                cache_generation,
            )? {
                host.delete_map_entry_if_present(map, &key)
                    .context(InterceptorSnafu)?;
            }
        }
    }
    Ok(())
}

pub(super) fn mount_cache_row_is_unreachable(
    map: &str,
    key: &[u8],
    expected_key_size: usize,
    security_view_epoch: u64,
    cache_generation: u64,
) -> Result<bool> {
    ensure!(
        key.len() == expected_key_size,
        IdentityStateSnafu {
            reason: format!(
                "mount cache map `{map}` has a key of size {}, expected {expected_key_size}",
                key.len()
            ),
        }
    );
    let row_security_view_epoch = u64::from_ne_bytes(
        key[CANONICAL_MOUNT_CACHE_SECURITY_VIEW_EPOCH_OFFSET_V1
            ..CANONICAL_MOUNT_CACHE_SECURITY_VIEW_EPOCH_OFFSET_V1 + size_of::<u64>()]
            .try_into()
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!(
                        "mount cache map `{map}` has an invalid security-view epoch: {error}"
                    ),
                }
                .build()
            })?,
    );
    let row_cache_generation = u64::from_ne_bytes(
        key[CANONICAL_MOUNT_CACHE_GENERATION_OFFSET_V1
            ..CANONICAL_MOUNT_CACHE_GENERATION_OFFSET_V1 + size_of::<u64>()]
            .try_into()
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!(
                        "mount cache map `{map}` has an invalid cache generation: {error}"
                    ),
                }
                .build()
            })?,
    );
    Ok(row_security_view_epoch < security_view_epoch || row_cache_generation < cache_generation)
}

pub(super) fn read_abi_value<T: KnownLayout + TryFromBytes>(bytes: &[u8], name: &str) -> Result<T> {
    T::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{name} has an invalid ABI value: {error}"),
        }
        .build()
    })
}
