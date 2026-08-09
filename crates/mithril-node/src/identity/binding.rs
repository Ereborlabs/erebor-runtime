use std::collections::BTreeMap;
use std::fs;
use std::mem::{offset_of, size_of};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    BindingLifecycleStateV1, ExecutionSetBindingStateV1, Id128V1, InitialRootStateV1,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::IntoBytes as _;

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu};
use crate::{Result, WorkloadBindingConfig};

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedBinding {
    root_cgroup_id: u64,
    descendants: Vec<u64>,
    state: ExecutionSetBindingStateV1,
}

pub struct WorkloadBindingOwner {
    cgroup_root: PathBuf,
    node_boot_id: Id128V1,
    label_epoch: u64,
    bindings: BTreeMap<u64, PublishedBinding>,
    profile_handles: BTreeMap<u64, Id128V1>,
}

impl WorkloadBindingOwner {
    pub fn system(node_boot_id: Id128V1, label_epoch: u64) -> Result<Self> {
        Self::at("/sys/fs/cgroup", node_boot_id, label_epoch)
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
        })
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
                            || installed.descendants.contains(&binding.root_cgroup_id)
                            || binding.descendants.contains(&installed.root_cgroup_id)
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
                binding.state.initial_root_state = InitialRootStateV1::from_raw(initial_root_state)
                    .context(IdentityStateSnafu {
                        reason: "recovered binding has an invalid initial-root state",
                    })?;
                binding.state.transition_version = read_u64(
                    existing,
                    offset_of!(ExecutionSetBindingStateV1, transition_version),
                )?;
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
                existing.is_none() || profile_task_refs.is_some(),
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
            for descendant in &binding.descendants {
                host.update_map(
                    "cgroup_binding_roots",
                    &descendant.to_ne_bytes(),
                    &binding.root_cgroup_id.to_ne_bytes(),
                )
                .context(InterceptorSnafu)?;
            }
            if existing.is_none() {
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
            &metadata.ctime().to_le_bytes(),
            &metadata.ctime_nsec().to_le_bytes(),
            spec.container_id.as_bytes(),
            &spec.container_generation.to_le_bytes(),
        ]);
        let binding_nonce = derive_id(&[
            self.node_boot_id.as_bytes(),
            &self.label_epoch.to_le_bytes(),
            binding_id.as_bytes(),
            root_cgroup_live_interval_id.as_bytes(),
        ]);
        let descendants = descendant_cgroup_ids(&root_cgroup_path, metadata.ino())?;
        Ok(PublishedBinding {
            root_cgroup_id: metadata.ino(),
            descendants,
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
}

fn parse_id(field: &str, value: &str) -> Result<Id128V1> {
    let uuid = Uuid::parse_str(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{field} `{value}` is not a UUID: {error}"),
        }
        .build()
    })?;
    let value = uuid.as_u128();
    let id = Id128V1::new((value >> 64) as u64, value as u64);
    ensure!(
        !id.is_zero(),
        IdentityStateSnafu {
            reason: format!("{field} must not be the nil UUID"),
        }
    );
    Ok(id)
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

fn descendant_cgroup_ids(root: &Path, root_id: u64) -> Result<Vec<u64>> {
    let mut pending = vec![root.to_path_buf()];
    let mut descendants = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
            let entry = entry.context(IoSnafu { path: &directory })?;
            let file_type = entry.file_type().context(IoSnafu { path: entry.path() })?;
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path();
            let id = entry.metadata().context(IoSnafu { path: &path })?.ino();
            ensure!(
                id != 0 && id != root_id && !descendants.contains(&id),
                IdentityStateSnafu {
                    reason: format!(
                        "cgroup descendant `{}` has a reused or zero ID",
                        path.display()
                    ),
                }
            );
            descendants.push(id);
            pending.push(path);
        }
    }
    descendants.sort_unstable();
    Ok(descendants)
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
            container_id: "container-generation-a".to_owned(),
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
    fn exact_empty_cgroup_arms_one_initial_root_and_tracks_descendants() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        fs::create_dir(root.join("child")).context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let binding = owner.prepare(&spec(&root))?;
        assert_eq!(
            binding.state.initial_root_state,
            InitialRootStateV1::Available
        );
        assert_eq!(binding.descendants.len(), 1);
        assert_eq!(binding.state.root_cgroup_id, binding.root_cgroup_id);
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
}
