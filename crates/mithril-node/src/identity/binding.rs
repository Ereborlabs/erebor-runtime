use std::collections::BTreeMap;
use std::fs::{self, File};
use std::mem::{offset_of, size_of};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, ExecutionSetBindingStateV1, Id128V1, InitialRootStateV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::IntoBytes as _;

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
        let mut identities = Vec::with_capacity(configured.len());
        if let Some(runtime) = self.runtime.as_mut() {
            for spec in configured {
                let identity = runtime.validate(spec).await?;
                ensure!(
                    fs::canonicalize(&identity.cgroup_path).context(IoSnafu {
                        path: &identity.cgroup_path,
                    })? == fs::canonicalize(&spec.root_cgroup_path).context(IoSnafu {
                        path: &spec.root_cgroup_path,
                    })?,
                    IdentityStateSnafu {
                        reason: format!(
                            "CRI cgroup for `{}` differs from configured expected path",
                            spec.container_id
                        ),
                    }
                );
                identities.push(identity);
            }
        }
        self.publish_all(host, configured)?;
        for identity in identities {
            let binding = self
                .bindings
                .values_mut()
                .find(|binding| binding.spec.container_id == identity.full_container_id)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: format!(
                            "published binding lost container `{}`",
                            identity.full_container_id
                        ),
                    }
                    .build()
                })?;
            binding.runtime_identity = Some(identity);
        }
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
                ensure!(
                    existing.len() == size_of::<ExecutionSetBindingStateV1>(),
                    IdentityStateSnafu {
                        reason: "recovered execution-set binding has the wrong ABI size".to_owned(),
                    }
                );
                let initial_root_state = read_u64(
                    existing,
                    offset_of!(ExecutionSetBindingStateV1, initial_root_state),
                )?;
                binding.state.binding_nonce = read_id(
                    existing,
                    offset_of!(ExecutionSetBindingStateV1, binding_nonce),
                )?;
                ensure!(
                    !binding.state.binding_nonce.is_zero(),
                    IdentityStateSnafu {
                        reason: "recovered binding has a zero nonce",
                    }
                );
                binding.state.initial_root_state = InitialRootStateV1::from_raw(initial_root_state)
                    .context(IdentityStateSnafu {
                        reason: "recovered binding has an invalid initial-root state",
                    })?;
                binding.state.transition_version = read_u64(
                    existing,
                    offset_of!(ExecutionSetBindingStateV1, transition_version),
                )?;
                binding.state.lifecycle_state =
                    match existing[offset_of!(ExecutionSetBindingStateV1, lifecycle_state)] {
                        value if value == BindingLifecycleStateV1::Preparing as u8 => {
                            resume_preparing = true;
                            BindingLifecycleStateV1::Preparing
                        }
                        value if value == BindingLifecycleStateV1::Active as u8 => {
                            BindingLifecycleStateV1::Active
                        }
                        _ => {
                            return IdentityStateSnafu {
                                reason: format!(
                                    "recovered binding `{}` is not preparing or active",
                                    spec.binding_id
                                ),
                            }
                            .fail()
                        }
                    };
                ensure!(
                    existing == binding.state.as_bytes(),
                    IdentityStateSnafu {
                        reason: format!(
                            "recovered binding `{}` differs from live runtime identity",
                            spec.binding_id
                        ),
                    }
                );
            } else {
                binding.state.lifecycle_state = BindingLifecycleStateV1::Preparing;
                host.update_map("execution_set_bindings", &key, binding.state.as_bytes())
                    .context(InterceptorSnafu)?;
            }
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
                ensure!(
                    task_refs.len() == size_of::<u64>(),
                    IdentityStateSnafu {
                        reason: "profile-generation task reference count has the wrong ABI size",
                    }
                );
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

    pub async fn reconcile(&mut self, host: &KernelHost) -> Result<()> {
        let root_ids: Vec<u64> = self.bindings.keys().copied().collect();
        for root_id in root_ids {
            if let Err(error) = self.validate_binding(root_id).await {
                self.terminate_all(host)?;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn validate_binding(&mut self, root_id: u64) -> Result<()> {
        let binding = self.bindings.get(&root_id).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("binding root {root_id} disappeared"),
            }
            .build()
        })?;
        let spec = binding.spec.clone();
        let expected_runtime_identity = binding.runtime_identity.clone();

        let observed_runtime_identity = if expected_runtime_identity.is_some() {
            Some(
                self.runtime
                    .as_mut()
                    .context(IdentityStateSnafu {
                        reason: "live workload binding lost its CRI inventory owner",
                    })?
                    .validate(&spec)
                    .await?,
            )
        } else {
            None
        };

        let binding = self.bindings.get(&root_id).ok_or_else(|| {
            IdentityStateSnafu {
                reason: format!("binding root {root_id} disappeared"),
            }
            .build()
        })?;
        binding.validate_live_cgroup()?;
        ensure!(
            observed_runtime_identity == expected_runtime_identity,
            IdentityStateSnafu {
                reason: format!(
                    "live CRI identity changed for `{}`",
                    binding.spec.container_id
                ),
            }
        );
        Ok(())
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
        let root_cgroup_path = fs::canonicalize(&spec.root_cgroup_path).context(IoSnafu {
            path: &spec.root_cgroup_path,
        })?;
        ensure!(
            root_cgroup_path.starts_with(&self.cgroup_root),
            IdentityStateSnafu {
                reason: format!(
                    "cgroup `{}` is outside `{}`",
                    root_cgroup_path.display(),
                    self.cgroup_root.display()
                ),
            }
        );
        let metadata = fs::metadata(&root_cgroup_path).context(IoSnafu {
            path: &root_cgroup_path,
        })?;
        ensure!(
            metadata.is_dir() && metadata.ino() != 0,
            IdentityStateSnafu {
                reason: format!(
                    "cgroup `{}` has no stable kernel ID",
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
        let profile_id = parse_id("profile_id", &spec.profile_id)?;
        let root_cgroup_live_interval_id = derive_id(&[
            root_cgroup_path.as_os_str().as_encoded_bytes(),
            &metadata.dev().to_le_bytes(),
            &metadata.ino().to_le_bytes(),
            spec.container_id.as_bytes(),
            &spec.container_generation.to_le_bytes(),
        ]);
        let binding_nonce = id_from_uuid(Uuid::new_v4());
        let root_handle = File::open(&root_cgroup_path).context(IoSnafu {
            path: &root_cgroup_path,
        })?;
        Ok(PublishedBinding {
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
        })
    }

    fn terminate_all(&mut self, host: &KernelHost) -> Result<()> {
        for binding in self.bindings.values_mut() {
            if binding.state.lifecycle_state == BindingLifecycleStateV1::Active {
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
            }
        }
        Ok(())
    }

    fn retain_only_configured(&self, host: &KernelHost) -> Result<()> {
        for key in host
            .map_keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let root_id = read_u64(&key, 0)?;
            if self.bindings.contains_key(&root_id) {
                continue;
            }
            let Some(mut value) = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            ensure!(
                value.len() == size_of::<ExecutionSetBindingStateV1>(),
                IdentityStateSnafu {
                    reason: "stale execution-set binding has the wrong ABI size",
                }
            );
            value[offset_of!(ExecutionSetBindingStateV1, lifecycle_state)] =
                BindingLifecycleStateV1::Terminating as u8;
            value[offset_of!(ExecutionSetBindingStateV1, initial_root_state)
                ..offset_of!(ExecutionSetBindingStateV1, initial_root_state) + 8]
                .copy_from_slice(&(InitialRootStateV1::Consumed as u64).to_ne_bytes());
            let version_offset = offset_of!(ExecutionSetBindingStateV1, transition_version);
            let version = read_u64(&value, version_offset)?
                .checked_add(1)
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "stale binding transition version overflowed".to_owned(),
                    }
                    .build()
                })?;
            value[version_offset..version_offset + 8].copy_from_slice(&version.to_ne_bytes());
            host.update_map("execution_set_bindings", &key, &value)
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

fn read_u64(value: &[u8], offset: usize) -> Result<u64> {
    let bytes = value
        .get(offset..offset + size_of::<u64>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            IdentityStateSnafu {
                reason: "recovered binding value is truncated".to_owned(),
            }
            .build()
        })?;
    Ok(u64::from_ne_bytes(bytes))
}

fn read_id(value: &[u8], offset: usize) -> Result<Id128V1> {
    Ok(Id128V1::new(
        read_u64(value, offset)?,
        read_u64(value, offset + size_of::<u64>())?,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use snafu::ResultExt as _;

    use super::WorkloadBindingOwner;
    use crate::error::IoSnafu;
    use crate::WorkloadBindingConfig;
    use erebor_interceptor_abi::{Id128V1, InitialRootStateV1};

    fn spec(root: &Path) -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: "a".repeat(64),
            pod_uid: "pod-uid-a".to_owned(),
            sandbox_id: "sandbox-a".to_owned(),
            container_name: "worker".to_owned(),
            image_digest: "sha256:image-a".to_owned(),
            container_kind: crate::ContainerKindV1::Application,
            container_generation: 1,
            root_cgroup_path: root.to_path_buf(),
            lifecycle_generation: 1,
            active_profile_generation_ref_id: 7,
            initial_role_id: 10,
            external_role_id: 11,
            arm_initial_root: true,
        }
    }

    #[test]
    fn exact_empty_cgroup_arms_one_initial_root() -> crate::Result<()> {
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
}
