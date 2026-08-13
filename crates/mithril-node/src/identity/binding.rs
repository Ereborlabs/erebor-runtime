use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, BindingLifecycleStateV1, ExecutionSetBindingStateV1, Id128V1,
    InitialRootStateV1, PolicyGenerationStateV1, ProfileGenerationDescriptorV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu};
use crate::{ContainerRuntimeConfig, Result, WorkloadBindingConfig};

use super::runtime::{ContainerRuntimeInventory, RuntimeContainerIdentity};

#[derive(Debug)]
struct PublishedBinding {
    root_cgroup_id: u64,
    root_cgroup_path: PathBuf,
    state: ExecutionSetBindingStateV1,
    root_handle: File,
    spec: WorkloadBindingConfig,
    runtime_identity: Option<RuntimeContainerIdentity>,
}

impl PublishedBinding {
    fn validate_live_cgroup(&self) -> Result<()> {
        let handle = self.root_handle.metadata().context(IoSnafu {
            path: &self.root_cgroup_path,
        })?;
        let path = fs::metadata(&self.root_cgroup_path).context(IoSnafu {
            path: &self.root_cgroup_path,
        })?;
        ensure!(
            handle.dev() == path.dev()
                && handle.ino() == path.ino()
                && path.ino() == self.root_cgroup_id,
            IdentityStateSnafu {
                reason: format!("live cgroup changed for binding `{}`", self.spec.binding_id),
            }
        );
        Ok(())
    }
}

pub struct WorkloadBindingOwner {
    cgroup_root: PathBuf,
    node_boot_id: Id128V1,
    label_epoch: u64,
    bindings: BTreeMap<u64, PublishedBinding>,
    profile_handles: BTreeMap<u64, Id128V1>,
    runtime: Option<ContainerRuntimeInventory>,
}

impl WorkloadBindingOwner {
    pub fn system(node_boot_id: Id128V1, label_epoch: u64) -> Result<Self> {
        Self::at("/sys/fs/cgroup", node_boot_id, label_epoch)
    }

    pub async fn system_with_runtime(
        node_boot_id: Id128V1,
        label_epoch: u64,
        runtime: &ContainerRuntimeConfig,
    ) -> Result<Self> {
        let mut owner = Self::system(node_boot_id, label_epoch)?;
        owner.runtime = Some(
            ContainerRuntimeInventory::connect(&runtime.socket_path, &owner.cgroup_root).await?,
        );
        Ok(owner)
    }

    fn at(
        cgroup_root: impl Into<PathBuf>,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let root = cgroup_root.into();
        let cgroup_root = fs::canonicalize(&root).context(IoSnafu { path: &root })?;
        Ok(Self {
            cgroup_root,
            node_boot_id,
            label_epoch,
            bindings: BTreeMap::new(),
            profile_handles: BTreeMap::new(),
            runtime: None,
        })
    }

    pub async fn publish_configured(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        if self.runtime.is_some() {
            return self.reconcile_runtime(host, configured).await;
        }
        self.publish_all(host, configured)?;
        self.retain_only_configured(host)
    }

    pub fn publish_all(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        for spec in configured {
            let mut binding = self.prepare(spec)?;
            ensure!(
                !self.bindings.contains_key(&binding.root_cgroup_id)
                    && !self.bindings.values().any(|installed| {
                        installed.state.binding_id == binding.state.binding_id
                            || binding
                                .root_cgroup_path
                                .starts_with(&installed.root_cgroup_path)
                            || installed
                                .root_cgroup_path
                                .starts_with(&binding.root_cgroup_path)
                    }),
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` overlaps an installed cgroup or binding identity",
                        spec.binding_id
                    ),
                }
            );
            ensure!(
                self.profile_handles
                    .get(&binding.state.active_profile_generation_ref_id)
                    .is_none_or(|profile_id| *profile_id == binding.state.profile_id),
                IdentityStateSnafu {
                    reason: format!(
                        "profile-generation handle {} is assigned to more than one profile",
                        binding.state.active_profile_generation_ref_id
                    ),
                }
            );
            let key = binding.root_cgroup_id.to_ne_bytes();
            let existing = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?;
            let mut resume_preparing = false;
            if let Some(existing) = existing.as_deref() {
                let recovered = execution_set_binding_state(existing)?;
                ensure!(
                    !recovered.binding_nonce.is_zero(),
                    IdentityStateSnafu {
                        reason: "recovered binding has a zero nonce",
                    }
                );
                resume_preparing = recovered.lifecycle_state == BindingLifecycleStateV1::Preparing;
                ensure!(
                    matches!(
                        recovered.lifecycle_state,
                        BindingLifecycleStateV1::Preparing | BindingLifecycleStateV1::Active
                    ),
                    IdentityStateSnafu {
                        reason: format!(
                            "recovered binding `{}` is not preparing or active",
                            spec.binding_id
                        ),
                    }
                );
                ensure!(
                    same_runtime_binding(&binding.state, &recovered),
                    IdentityStateSnafu {
                        reason: format!(
                            "recovered binding `{}` differs from live runtime identity",
                            spec.binding_id
                        ),
                    }
                );
                binding.state = recovered;
            } else {
                binding.state.lifecycle_state = BindingLifecycleStateV1::Preparing;
                host.update_map("execution_set_bindings", &key, binding.state.as_bytes())
                    .context(InterceptorSnafu)?;
            }
            ensure!(
                self.profile_handles
                    .get(&binding.state.active_profile_generation_ref_id)
                    .is_none_or(|profile_id| *profile_id == binding.state.profile_id),
                IdentityStateSnafu {
                    reason: format!(
                        "recovered profile-generation handle {} is assigned to more than one profile",
                        binding.state.active_profile_generation_ref_id
                    ),
                }
            );
            let profile_key = binding.state.active_profile_generation_ref_id.to_ne_bytes();
            let profile_task_refs = host
                .lookup_map("profile_generation_task_refs", &profile_key)
                .context(InterceptorSnafu)?;
            ensure!(
                existing.is_none() || resume_preparing || profile_task_refs.is_some(),
                IdentityStateSnafu {
                    reason: "recovered binding lost its profile-generation references",
                }
            );
            if let Some(task_refs) = profile_task_refs {
                let _task_refs = u64::read_from_bytes(&task_refs).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!(
                            "profile-generation task reference count has an invalid ABI value: {error}"
                        ),
                    }
                    .build()
                })?;
            } else {
                host.update_map(
                    "profile_generation_task_refs",
                    &profile_key,
                    &0_u64.to_ne_bytes(),
                )
                .context(InterceptorSnafu)?;
            }
            if existing.is_none() || resume_preparing {
                ensure!(
                    host.lookup_map("execution_set_bindings", &key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.state.as_bytes()),
                    IdentityStateSnafu {
                        reason: format!("binding `{}` failed preparing readback", spec.binding_id),
                    }
                );
                binding.state.lifecycle_state = BindingLifecycleStateV1::Active;
                binding.state.transition_version += 1;
                host.update_map("execution_set_bindings", &key, binding.state.as_bytes())
                    .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("execution_set_bindings", &key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.state.as_bytes()),
                    IdentityStateSnafu {
                        reason: format!("binding `{}` failed active readback", spec.binding_id),
                    }
                );
            }
            self.profile_handles.insert(
                binding.state.active_profile_generation_ref_id,
                binding.state.profile_id,
            );
            self.bindings.insert(binding.root_cgroup_id, binding);
        }
        Ok(())
    }

    pub fn adopt_activated_profiles(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        for spec in configured {
            let binding = self
                .bindings
                .values_mut()
                .find(|binding| binding.spec.binding_id == spec.binding_id)
                .context(IdentityStateSnafu {
                    reason: format!("configured binding `{}` is not published", spec.binding_id),
                })?;
            binding.validate_live_cgroup()?;

            let active = host
                .lookup_map(
                    "active_profile_generations",
                    binding.state.profile_id.as_bytes(),
                )
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has no active signed generation",
                        spec.binding_id
                    ),
                })?;
            let active = u64::read_from_bytes(&active).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("active generation has an invalid ABI value: {error}"),
                }
                .build()
            })?;
            ensure!(
                active == spec.active_profile_generation_ref_id,
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` active generation does not match its verified configuration",
                        spec.binding_id
                    ),
                }
            );
            let descriptor = host
                .lookup_map("profile_generation_descriptors", &active.to_ne_bytes())
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: format!("active generation {active} has no descriptor"),
                })?;
            let descriptor = ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor)
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("active generation descriptor is invalid: {error}"),
                    }
                    .build()
                })?;
            ensure!(
                descriptor.state == PolicyGenerationStateV1::Active
                    && descriptor.profile_generation_ref_id == active
                    && descriptor.profile_id == binding.state.profile_id
                    && descriptor.node_boot_id == self.node_boot_id
                    && descriptor.label_epoch == self.label_epoch,
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` active generation descriptor does not match its live identity",
                        spec.binding_id
                    ),
                }
            );
            let target_key = BindingActivationTargetKeyV1 {
                binding_id: binding.state.binding_id,
                profile_generation_ref_id: active,
            };
            let activated = host
                .lookup_map("binding_activation_targets", target_key.as_bytes())
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has no active generation target",
                        spec.binding_id
                    ),
                })?;
            let activated = execution_set_binding_state(&activated)?;
            ensure!(
                same_activation_identity(&binding.state, &activated)
                    && activated.lifecycle_state == BindingLifecycleStateV1::Active
                    && activated.active_profile_generation_ref_id == active
                    && activated.initial_role_id == spec.initial_role_id
                    && activated.external_role_id == spec.external_role_id,
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` does not match its active profile",
                        spec.binding_id
                    ),
                }
            );
            self.profile_handles.insert(active, activated.profile_id);
        }
        Ok(())
    }

    pub async fn reconcile(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        if self.runtime.is_some() {
            return self.reconcile_runtime(host, configured).await;
        }
        if let Some(error) = self
            .bindings
            .values()
            .find_map(|binding| binding.validate_live_cgroup().err())
        {
            self.terminate_all(host)?;
            return Err(error);
        }
        Ok(())
    }

    async fn reconcile_runtime(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        let result = self.reconcile_runtime_inner(host, configured).await;
        if result.is_err() {
            self.terminate_all(host)?;
        }
        result
    }

    async fn reconcile_runtime_inner(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        let observed = self
            .runtime
            .as_mut()
            .context(IdentityStateSnafu {
                reason: "workload binding lost its CRI inventory owner",
            })?
            .snapshot(configured)
            .await?;
        let observed: BTreeMap<String, RuntimeContainerIdentity> = observed
            .into_iter()
            .map(|identity| (identity.full_container_id.clone(), identity))
            .collect();
        let (missing, new) = self.plan_runtime_reconciliation(observed)?;
        for root_id in missing {
            self.terminate(host, root_id)?;
            self.bindings.remove(&root_id);
        }
        for identity in new {
            let configured = configured
                .iter()
                .find(|binding| binding.container_id == identity.full_container_id)
                .context(IdentityStateSnafu {
                    reason: "CRI returned a container without a configured binding",
                })?;
            if let Some(expected_path) = configured.root_cgroup_path.as_ref() {
                ensure!(
                    fs::canonicalize(&identity.cgroup_path).context(IoSnafu {
                        path: &identity.cgroup_path,
                    })? == fs::canonicalize(expected_path).context(IoSnafu {
                        path: expected_path,
                    })?,
                    IdentityStateSnafu {
                        reason: format!(
                            "CRI cgroup for `{}` differs from configured expected path",
                            configured.container_id
                        ),
                    }
                );
            }
            let resolved = identity.resolve(configured);
            self.publish_all(host, std::slice::from_ref(&resolved))?;
            let binding = self
                .bindings
                .values_mut()
                .find(|binding| binding.spec.container_id == identity.full_container_id)
                .context(IdentityStateSnafu {
                    reason: "published binding lost its CRI container",
                })?;
            binding.runtime_identity = Some(identity);
        }
        self.retain_only_configured(host)
    }

    fn plan_runtime_reconciliation(
        &self,
        mut observed: BTreeMap<String, RuntimeContainerIdentity>,
    ) -> Result<(Vec<u64>, Vec<RuntimeContainerIdentity>)> {
        let mut missing = Vec::new();
        for (&root_id, binding) in &self.bindings {
            let Some(expected) = binding.runtime_identity.as_ref() else {
                binding.validate_live_cgroup()?;
                continue;
            };
            let Some(current) = observed.get(&binding.spec.container_id) else {
                missing.push(root_id);
                continue;
            };
            binding.validate_live_cgroup()?;
            ensure!(
                current.same_lifetime_as(expected),
                IdentityStateSnafu {
                    reason: format!(
                        "live CRI identity changed for `{}`",
                        binding.spec.container_id
                    ),
                }
            );
            observed.remove(&binding.spec.container_id);
        }
        Ok((missing, observed.into_values().collect()))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    fn prepare(&self, spec: &WorkloadBindingConfig) -> Result<PublishedBinding> {
        let configured_root = spec.root_cgroup_path.as_ref().context(IdentityStateSnafu {
            reason: "workload binding has no resolved cgroup path",
        })?;
        let root_cgroup_path = fs::canonicalize(configured_root).context(IoSnafu {
            path: configured_root,
        })?;
        ensure!(
            root_cgroup_path != self.cgroup_root && root_cgroup_path.starts_with(&self.cgroup_root),
            IdentityStateSnafu {
                reason: format!(
                    "cgroup `{}` is the cgroup root or outside `{}`",
                    root_cgroup_path.display(),
                    self.cgroup_root.display()
                ),
            }
        );
        let root_handle = File::open(&root_cgroup_path).context(IoSnafu {
            path: &root_cgroup_path,
        })?;
        let metadata = root_handle.metadata().context(IoSnafu {
            path: &root_cgroup_path,
        })?;
        let path_metadata = fs::metadata(&root_cgroup_path).context(IoSnafu {
            path: &root_cgroup_path,
        })?;
        ensure!(
            metadata.is_dir()
                && metadata.ino() != 0
                && metadata.dev() == path_metadata.dev()
                && metadata.ino() == path_metadata.ino(),
            IdentityStateSnafu {
                reason: format!(
                    "cgroup `{}` has no stable live kernel identity",
                    root_cgroup_path.display()
                ),
            }
        );
        if spec.arm_initial_root {
            let procs_path = root_cgroup_path.join("cgroup.procs");
            let procs = fs::read_to_string(&procs_path).context(IoSnafu { path: &procs_path })?;
            ensure!(
                procs.trim().is_empty(),
                IdentityStateSnafu {
                    reason: format!(
                        "initial-root admission for `{}` requires an empty cgroup",
                        root_cgroup_path.display()
                    ),
                }
            );
        }
        let binding_id = parse_id("binding_id", &spec.binding_id)?;
        let execution_set_id = parse_id("execution_set_id", &spec.execution_set_id)?;
        let protected_scope_id = parse_id("protected_scope_id", &spec.protected_scope_id)?;
        let profile_id = parse_id("profile_id", &spec.profile_id)?;
        let root_cgroup_live_interval_id = derive_id(&[
            root_cgroup_path.as_os_str().as_encoded_bytes(),
            &metadata.dev().to_le_bytes(),
            &metadata.ino().to_le_bytes(),
            spec.container_id.as_bytes(),
            &spec.container_generation.to_le_bytes(),
        ]);
        let binding_nonce = id_from_uuid(Uuid::new_v4());
        let binding = PublishedBinding {
            root_cgroup_id: metadata.ino(),
            root_cgroup_path,
            root_handle,
            spec: spec.clone(),
            runtime_identity: None,
            state: ExecutionSetBindingStateV1 {
                binding_id,
                binding_nonce,
                node_boot_id: self.node_boot_id,
                execution_set_id,
                protected_scope_id,
                profile_id,
                label_epoch: self.label_epoch,
                active_profile_generation_ref_id: spec.active_profile_generation_ref_id,
                root_cgroup_id: metadata.ino(),
                root_cgroup_live_interval_id,
                container_generation: spec.container_generation,
                lifecycle_generation: spec.lifecycle_generation,
                transition_version: 1,
                initial_role_id: spec.initial_role_id,
                external_role_id: spec.external_role_id,
                lifecycle_state: BindingLifecycleStateV1::Active,
                reserved: [0; 7],
                initial_root_state: if spec.arm_initial_root {
                    InitialRootStateV1::Available
                } else {
                    InitialRootStateV1::Unarmed
                },
            },
        };
        binding.validate_live_cgroup()?;
        Ok(binding)
    }

    fn terminate_all(&mut self, host: &KernelHost) -> Result<()> {
        let root_ids: Vec<u64> = self.bindings.keys().copied().collect();
        for root_id in root_ids {
            self.terminate(host, root_id)?;
        }
        Ok(())
    }

    fn terminate(&mut self, host: &KernelHost, root_id: u64) -> Result<()> {
        let binding = self.bindings.get_mut(&root_id).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("binding root {root_id} disappeared before termination"),
            }
            .build()
        })?;
        if binding.state.lifecycle_state != BindingLifecycleStateV1::Active {
            return Ok(());
        }
        binding.state.lifecycle_state = BindingLifecycleStateV1::Terminating;
        binding.state.initial_root_state = InitialRootStateV1::Consumed;
        binding.state.transition_version += 1;
        host.update_map(
            "execution_set_bindings",
            &binding.root_cgroup_id.to_ne_bytes(),
            binding.state.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map(
                "execution_set_bindings",
                &binding.root_cgroup_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .as_deref()
                == Some(binding.state.as_bytes()),
            IdentityStateSnafu {
                reason: format!(
                    "terminating binding `{}` failed kernel readback",
                    binding.spec.binding_id
                ),
            }
        );
        Ok(())
    }

    fn retain_only_configured(&self, host: &KernelHost) -> Result<()> {
        for key in host
            .map_keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let root_id = u64::read_from_bytes(&key).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("execution-set binding key has an invalid ABI value: {error}"),
                }
                .build()
            })?;
            if self.bindings.contains_key(&root_id) {
                continue;
            }
            let Some(value) = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let mut value = execution_set_binding_state(&value)?;
            if matches!(
                value.lifecycle_state,
                BindingLifecycleStateV1::Terminating | BindingLifecycleStateV1::Tombstoned
            ) {
                continue;
            }
            ensure!(
                matches!(
                    value.lifecycle_state,
                    BindingLifecycleStateV1::Preparing
                        | BindingLifecycleStateV1::Active
                        | BindingLifecycleStateV1::Draining
                ),
                IdentityStateSnafu {
                    reason: "stale execution-set binding has an invalid lifecycle state",
                }
            );
            value.lifecycle_state = BindingLifecycleStateV1::Terminating;
            value.initial_root_state = InitialRootStateV1::Consumed;
            value.transition_version =
                value.transition_version.checked_add(1).ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "stale binding transition version overflowed".to_owned(),
                    }
                    .build()
                })?;
            host.update_map("execution_set_bindings", &key, value.as_bytes())
                .context(InterceptorSnafu)?;
        }
        Ok(())
    }
}

fn parse_id(field: &str, value: &str) -> Result<Id128V1> {
    let uuid = Uuid::parse_str(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{field} `{value}` is not a UUID: {error}"),
        }
        .build()
    })?;
    let id = id_from_uuid(uuid);
    ensure!(
        !id.is_zero(),
        IdentityStateSnafu {
            reason: format!("{field} must not be the nil UUID"),
        }
    );
    Ok(id)
}

fn id_from_uuid(uuid: Uuid) -> Id128V1 {
    let value = uuid.as_u128();
    Id128V1::new((value >> 64) as u64, value as u64)
}

fn derive_id(parts: &[&[u8]]) -> Id128V1 {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    let digest = digest.finalize();
    let mut high = [0_u8; 8];
    let mut low = [0_u8; 8];
    high.copy_from_slice(&digest[0..8]);
    low.copy_from_slice(&digest[8..16]);
    let id = Id128V1::new(u64::from_be_bytes(high), u64::from_be_bytes(low));
    if id.is_zero() {
        Id128V1::new(0, 1)
    } else {
        id
    }
}

fn execution_set_binding_state(bytes: &[u8]) -> Result<ExecutionSetBindingStateV1> {
    ExecutionSetBindingStateV1::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("execution-set binding has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn same_runtime_binding(
    desired: &ExecutionSetBindingStateV1,
    recovered: &ExecutionSetBindingStateV1,
) -> bool {
    let mut desired = *desired;
    desired.binding_nonce = recovered.binding_nonce;
    desired.active_profile_generation_ref_id = recovered.active_profile_generation_ref_id;
    desired.transition_version = recovered.transition_version;
    desired.initial_role_id = recovered.initial_role_id;
    desired.external_role_id = recovered.external_role_id;
    desired.lifecycle_state = recovered.lifecycle_state;
    desired.initial_root_state = recovered.initial_root_state;
    desired == *recovered
}

fn same_activation_identity(
    live: &ExecutionSetBindingStateV1,
    target: &ExecutionSetBindingStateV1,
) -> bool {
    let mut live = *live;
    live.active_profile_generation_ref_id = target.active_profile_generation_ref_id;
    live.transition_version = target.transition_version;
    live.initial_role_id = target.initial_role_id;
    live.external_role_id = target.external_role_id;
    live.lifecycle_state = target.lifecycle_state;
    live.initial_root_state = target.initial_root_state;
    live == *target
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;

    use snafu::ResultExt as _;

    use super::{
        same_activation_identity, same_runtime_binding, RuntimeContainerIdentity,
        WorkloadBindingOwner,
    };
    use crate::error::IoSnafu;
    use crate::identity::runtime::RuntimeContainerState;
    use crate::WorkloadBindingConfig;
    use erebor_interceptor_abi::{Id128V1, InitialRootStateV1};

    fn spec(root: &Path) -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: "a".repeat(64),
            pod_uid: "pod-uid-a".to_owned(),
            sandbox_id: "sandbox-a".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: "sha256:image-a".to_owned(),
            container_kind: crate::ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: Some(root.to_path_buf()),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 7,
            initial_role_id: 10,
            external_role_id: 11,
            arm_initial_root: true,
        }
    }

    #[test]
    fn docker_style_configured_cgroup_arms_one_initial_root() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let binding = owner.prepare(&spec(&root))?;
        let second = owner.prepare(&spec(&root))?;
        assert_eq!(
            binding.state.initial_root_state,
            InitialRootStateV1::Available
        );
        assert_eq!(binding.state.root_cgroup_id, binding.root_cgroup_id);
        assert_ne!(binding.state.binding_nonce, second.state.binding_nonce);
        Ok(())
    }

    #[test]
    fn occupied_cgroup_cannot_claim_initial_root() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        assert!(owner.prepare(&spec(&root)).is_err());
        Ok(())
    }

    #[test]
    fn cgroup_root_cannot_become_a_workload_binding() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        fs::write(temporary.path().join("cgroup.procs"), "").context(IoSnafu {
            path: temporary.path(),
        })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        assert!(owner.prepare(&spec(temporary.path())).is_err());
        Ok(())
    }

    #[test]
    fn configured_binding_detects_cgroup_path_reuse() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let binding = owner.prepare(&spec(&root))?;
        binding.validate_live_cgroup()?;

        fs::remove_dir_all(&root).context(IoSnafu { path: &root })?;
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        assert!(binding.validate_live_cgroup().is_err());
        Ok(())
    }

    #[test]
    fn recovery_can_retain_an_old_generation_until_verified_activation() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let desired = owner.prepare(&spec(&root))?.state;
        let mut recovered = desired;
        recovered.binding_nonce = Id128V1::new(9, 10);
        recovered.active_profile_generation_ref_id = 6;
        recovered.initial_role_id = 8;
        recovered.external_role_id = 9;
        recovered.initial_root_state = InitialRootStateV1::Consumed;
        recovered.transition_version = 12;

        assert!(same_runtime_binding(&desired, &recovered));
        recovered.execution_set_id = Id128V1::new(11, 12);
        assert!(!same_runtime_binding(&desired, &recovered));
        Ok(())
    }

    #[test]
    fn activation_target_can_change_only_generation_roles_and_kernel_owned_state(
    ) -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let live = owner.prepare(&spec(&root))?.state;
        let mut target = live;
        target.active_profile_generation_ref_id += 1;
        target.initial_role_id += 1;
        target.external_role_id += 1;
        target.transition_version += 1;
        target.initial_root_state = InitialRootStateV1::Consumed;
        assert!(same_activation_identity(&live, &target));

        target.binding_nonce = Id128V1::new(9, 10);
        assert!(!same_activation_identity(&live, &target));
        Ok(())
    }

    #[test]
    fn runtime_inventory_keeps_or_retires_exact_container_lifetimes() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let configured = spec(&root);
        let identity = RuntimeContainerIdentity {
            full_container_id: configured.container_id.clone(),
            pod_uid: configured.pod_uid.clone(),
            sandbox_id: configured.sandbox_id.clone(),
            container_name: configured.container_name.clone(),
            image_digest: configured.image_digest.clone(),
            generation: configured.container_generation,
            cgroup_path: root,
            state: RuntimeContainerState::Created,
        };
        let mut binding = owner.prepare(&identity.resolve(&configured))?;
        let root_id = binding.root_cgroup_id;
        binding.runtime_identity = Some(identity.clone());
        owner.bindings.insert(root_id, binding);

        let running = RuntimeContainerIdentity {
            state: RuntimeContainerState::Running,
            ..identity
        };
        let observed = BTreeMap::from([(running.full_container_id.clone(), running)]);
        let (missing, new) = owner.plan_runtime_reconciliation(observed)?;
        assert!(missing.is_empty());
        assert!(new.is_empty());

        let (missing, new) = owner.plan_runtime_reconciliation(BTreeMap::new())?;
        assert_eq!(missing, vec![root_id]);
        assert!(new.is_empty());
        Ok(())
    }
}
