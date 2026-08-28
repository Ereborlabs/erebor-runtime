use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::mem::size_of;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, BindingLifecycleStateV1, EntryAdmissionRuleKeyV1,
    EntryAdmissionRuleV1, ExactFileObjectKeyV1, ExecutionSetBindingStateV1, Id128V1,
    InitialRootStateV1, PolicyGenerationStateV1, PreparedContainerStateV1,
    ProfileGenerationDescriptorV1, TaskCoordinateStateV1, TaskCoordinateV1, TaskLabelV1,
};
use erebor_runtime_error::{ErrorExt as _, RetryHint};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use uuid::Uuid;
use zerocopy::{FromBytes as _, IntoBytes as _, TryFromBytes as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu};
use crate::runtime_admission::{
    KubernetesRuntimeIdentityV1, RuntimeAdmissionOperationV1, RuntimeAdmissionRequestV1,
    ScheduledRuntimeBindingV1,
};
use crate::{ContainerRuntimeConfig, Result, WorkloadBindingConfig};

use super::runtime::{ContainerRuntimeInventory, RuntimeContainerIdentity};

const RUNTIME_STAGE_LIFETIME: Duration = Duration::from_secs(30);
const MAXIMUM_RUNTIME_STAGES: usize = 128;

#[derive(Debug)]
struct PublishedBinding {
    root_cgroup_id: u64,
    root_cgroup_path: PathBuf,
    state: ExecutionSetBindingStateV1,
    root_handle: File,
    spec: WorkloadBindingConfig,
    runtime_identity: Option<RuntimeContainerIdentity>,
    held_initial_pid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeBindingTargetV1 {
    pub root_cgroup_id: u64,
    pub binding_id: Id128V1,
    pub binding_nonce: Id128V1,
    pub execution_set_id: Id128V1,
    pub protected_scope_id: Id128V1,
    pub profile_id: Id128V1,
    pub profile_generation_ref_id: u64,
    pub container_generation: u64,
    pub namespace: String,
    pub pod_uid: String,
    pub container_name: String,
    pub full_container_id: String,
    pub init_pid: u32,
    pub working_directory: PathBuf,
    pub path_entries: Vec<PathBuf>,
}

impl PublishedBinding {
    fn verify_activated_profile(
        &self,
        spec: &WorkloadBindingConfig,
        activated: &ExecutionSetBindingStateV1,
    ) -> Result<()> {
        let mut desired = self.state;
        desired.active_profile_generation_ref_id = spec.active_profile_generation_ref_id;
        desired.initial_role_id = spec.initial_role_id;
        desired.external_role_id = spec.external_role_id;
        ensure!(
            WorkloadBindingOwner::activation_target_matches_desired(&desired, activated),
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` does not match its active profile",
                    spec.binding_id
                ),
            }
        );
        Ok(())
    }

    fn adopt_activated_profile(
        &mut self,
        spec: WorkloadBindingConfig,
        activated: ExecutionSetBindingStateV1,
    ) {
        self.spec = spec;
        self.state = activated;
    }

    fn prepare_container(&mut self) -> Result<()> {
        ensure!(
            self.held_initial_pid.is_some()
                && self.state.prepared_container_state == PreparedContainerStateV1::Unarmed
                && self.state.prepared_container_entry_instance_id.is_zero()
                && self.state.prepared_container_exec_task_cookie == 0
                && self.state.prepared_container_initial_host_tgid == 0
                && self.state.prepared_container_bootstrap_state == 0,
            IdentityStateSnafu {
                reason: "a container can be prepared only for one held initial task",
            }
        );
        self.state.prepared_container_initial_host_tgid =
            self.held_initial_pid.context(IdentityStateSnafu {
                reason: "prepared container has no held initial task",
            })?;
        self.state.prepared_container_state = PreparedContainerStateV1::Prepared;
        Ok(())
    }

    fn reconcile_recovered_prepared_container(&mut self) -> Result<bool> {
        let state = &mut self.state;
        match state.prepared_container_state {
            PreparedContainerStateV1::Unarmed => {
                ensure!(
                    state.prepared_container_entry_instance_id.is_zero()
                        && state.prepared_container_exec_task_cookie == 0
                        && state.prepared_container_initial_host_tgid == 0
                        && state.prepared_container_bootstrap_state == 0,
                    IdentityStateSnafu {
                        reason: "an unarmed container has prepared-state fields",
                    }
                );
                Ok(false)
            }
            PreparedContainerStateV1::Prepared => {
                ensure!(
                    state.prepared_container_initial_host_tgid != 0
                        && state.prepared_container_bootstrap_state <= 2
                        && (state.prepared_container_bootstrap_state == 1)
                            == (state.prepared_container_exec_task_cookie != 0),
                    IdentityStateSnafu {
                        reason: "prepared container has an invalid exec reservation",
                    }
                );
                IdentityStateSnafu {
                    reason: "prepared container remains active during node recovery".to_owned(),
                }
                .fail()
            }
            PreparedContainerStateV1::ExecPending => IdentityStateSnafu {
                reason: "prepared-container exec is incomplete during node recovery".to_owned(),
            }
            .fail(),
            PreparedContainerStateV1::Active => {
                ensure!(
                    !state.prepared_container_entry_instance_id.is_zero()
                        && state.prepared_container_initial_host_tgid != 0
                        && state.prepared_container_bootstrap_state == 0,
                    IdentityStateSnafu {
                        reason: "active container has incomplete prepared identity",
                    }
                );
                if state.prepared_container_exec_task_cookie == 0 {
                    return Ok(false);
                }
                // ACTIVE is written only at the successful exec commit point.
                // A remaining cookie is a crash residue, not pending authority.
                state.prepared_container_exec_task_cookie = 0;
                state.transition_version =
                    state
                        .transition_version
                        .checked_add(1)
                        .context(IdentityStateSnafu {
                            reason: "prepared-container recovery transition overflowed",
                        })?;
                Ok(true)
            }
            PreparedContainerStateV1::Expired => {
                ensure!(
                    state.prepared_container_exec_task_cookie == 0
                        && state.prepared_container_initial_host_tgid != 0
                        && state.prepared_container_bootstrap_state == 0,
                    IdentityStateSnafu {
                        reason: "expired prepared container has an exec reservation",
                    }
                );
                Ok(false)
            }
            PreparedContainerStateV1::Corrupt => IdentityStateSnafu {
                reason: "prepared-container state is corrupt".to_owned(),
            }
            .fail(),
        }
    }

    fn require_initial_root_admission(&self) -> Result<()> {
        if !self.spec.arm_initial_root {
            return Ok(());
        }
        let procs_path = self.root_cgroup_path.join("cgroup.procs");
        let procs = fs::read_to_string(&procs_path).context(IoSnafu { path: &procs_path })?;
        let live_pids = procs
            .split_whitespace()
            .map(|pid| {
                pid.parse::<u32>().map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!(
                            "initial-root admission for `{}` found invalid PID `{pid}`: {error}",
                            self.root_cgroup_path.display()
                        ),
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let admitted = self
            .held_initial_pid
            .map_or_else(|| live_pids.is_empty(), |pid| live_pids.as_slice() == [pid]);
        ensure!(
            admitted,
            IdentityStateSnafu {
                reason: format!(
                    "initial-root admission for `{}` requires an empty cgroup or its one held PID",
                    self.root_cgroup_path.display(),
                ),
            }
        );
        Ok(())
    }

    fn validate_live_cgroup(&self) -> Result<()> {
        let path = fs::metadata(&self.root_cgroup_path).context(IoSnafu {
            path: &self.root_cgroup_path,
        })?;
        self.validate_live_cgroup_metadata(&path)
    }

    fn validate_live_cgroup_metadata(&self, path: &fs::Metadata) -> Result<()> {
        let handle = self.root_handle.metadata().context(IoSnafu {
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

    fn live_runtime_cgroup_exists(&self) -> Result<bool> {
        match fs::metadata(&self.root_cgroup_path) {
            Ok(path) => {
                self.validate_live_cgroup_metadata(&path)?;
                Ok(true)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(source).context(IoSnafu {
                path: &self.root_cgroup_path,
            }),
        }
    }
}

pub struct WorkloadBindingOwner {
    cgroup_root: PathBuf,
    node_boot_id: Id128V1,
    label_epoch: u64,
    bindings: BTreeMap<u64, PublishedBinding>,
    profile_handles: BTreeMap<u64, Id128V1>,
    runtime: Option<ContainerRuntimeInventory>,
    // Keep one verified CRI identity between inspection and held-root publication.
    pending_runtime_admission: Option<RuntimeContainerIdentity>,
    staged_runtime_admissions: BTreeMap<String, StagedRuntimeAdmissionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactObjectBindingTargetV1<'a> {
    pub binding_id: &'a str,
    pub init_pid: u32,
}

struct RuntimeBindingUpdate {
    root_id: u64,
    identity: RuntimeContainerIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedRuntimeAdmissionV1 {
    authority_head_binding_id: String,
    identity: KubernetesRuntimeIdentityV1,
    cgroup_path: PathBuf,
    deadline: Instant,
}

impl StagedRuntimeAdmissionV1 {
    fn verify_preparation(
        &self,
        authority_head_binding_id: &str,
        request: &RuntimeAdmissionRequestV1,
        now: Instant,
    ) -> Result<()> {
        ensure!(
            self.deadline > now
                && authority_head_binding_id == self.authority_head_binding_id
                && request.kubernetes_identity()? == self.identity,
            IdentityStateSnafu {
                reason: "the second OCI hook differs from its immutable first stage",
            }
        );
        Ok(())
    }

    fn verify_declared_entries(
        &self,
        authority_head_binding_id: &str,
        request: &RuntimeAdmissionRequestV1,
        now: Instant,
    ) -> Result<()> {
        ensure!(
            self.deadline > now
                && authority_head_binding_id == self.authority_head_binding_id
                && request.kubernetes_identity()? == self.identity,
            IdentityStateSnafu {
                reason: "declared-entry preparation differs from its immutable runtime stage",
            }
        );
        Ok(())
    }
}

#[derive(Default)]
struct RuntimeReconciliationPlan {
    missing_root_ids: Vec<u64>,
    new_identities: Vec<RuntimeContainerIdentity>,
    retired_binding_ids: BTreeSet<String>,
    updates: Vec<RuntimeBindingUpdate>,
}

impl RuntimeReconciliationPlan {
    fn retire_binding(&mut self, root_id: u64, binding: &PublishedBinding) {
        self.missing_root_ids.push(root_id);
        if binding.spec.scheduled_binding_authority_id.is_some()
            && binding.spec.root_cgroup_path.is_some()
        {
            self.retired_binding_ids
                .insert(binding.spec.binding_id.clone());
        }
    }
}

#[derive(Default)]
pub(crate) struct RuntimeReconciliationResultV1 {
    pub retired_binding_ids: Vec<String>,
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
        owner.runtime =
            Some(ContainerRuntimeInventory::connect(runtime, &owner.cgroup_root).await?);
        Ok(owner)
    }

    pub async fn wait_for_runtime_change(&mut self) {
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.wait_for_change().await;
        } else {
            std::future::pending::<()>().await;
        }
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
            pending_runtime_admission: None,
            staged_runtime_admissions: BTreeMap::new(),
        })
    }

    pub(crate) async fn publish_configured(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<RuntimeReconciliationResultV1> {
        if self.runtime.is_some() {
            return self.reconcile_runtime(host, configured).await;
        }
        // Scheduled placeholders have no cgroup until runtime admission supplies the held task.
        self.publish(
            host,
            configured
                .iter()
                .filter(|binding| binding.root_cgroup_path.is_some())
                .map(|binding| (binding, None)),
        )?;
        self.retain_only_configured(host)?;
        Ok(RuntimeReconciliationResultV1::default())
    }

    pub fn administrative_target(
        &self,
        namespace: &[u8],
        pod_uid: &[u8],
        container_name: &[u8],
        full_container_id: &[u8],
        container_generation: u64,
    ) -> Result<AdministrativeBindingTargetV1> {
        let namespace = std::str::from_utf8(namespace).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("administrative namespace is not UTF-8: {error}"),
            }
            .build()
        })?;
        let pod_uid = std::str::from_utf8(pod_uid).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("administrative Pod UID is not UTF-8: {error}"),
            }
            .build()
        })?;
        let container_name = std::str::from_utf8(container_name).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("administrative container name is not UTF-8: {error}"),
            }
            .build()
        })?;
        let full_container_id = std::str::from_utf8(full_container_id).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("administrative container ID is not UTF-8: {error}"),
            }
            .build()
        })?;
        let matches = self
            .bindings
            .values()
            .filter(|binding| {
                binding.state.lifecycle_state == BindingLifecycleStateV1::Active
                    && binding.spec.namespace == namespace
                    && binding.spec.pod_uid == pod_uid
                    && binding.spec.container_name == container_name
                    && binding.spec.container_id == full_container_id
                    && (container_generation == 0
                        || binding.spec.container_generation == container_generation)
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            IdentityStateSnafu {
                reason: "administrative exec target does not resolve to one active binding",
            }
        );
        let binding = matches[0];
        binding.validate_live_cgroup()?;
        let runtime = binding.runtime_identity.as_ref().ok_or_else(|| {
            IdentityStateSnafu {
                reason: "administrative exec requires an authenticated live CRI identity"
                    .to_owned(),
            }
            .build()
        })?;
        ensure!(
            runtime.namespace == namespace
                && runtime.pod_uid == pod_uid
                && runtime.container_name == container_name
                && runtime.full_container_id == full_container_id
                && (container_generation == 0 || runtime.generation == container_generation)
                && runtime.state == super::runtime::RuntimeContainerState::Running
                && runtime.init_pid > 0,
            IdentityStateSnafu {
                reason: "live CRI identity changed during administrative target resolution",
            }
        );
        Ok(AdministrativeBindingTargetV1 {
            root_cgroup_id: binding.root_cgroup_id,
            binding_id: binding.state.binding_id,
            binding_nonce: binding.state.binding_nonce,
            execution_set_id: binding.state.execution_set_id,
            protected_scope_id: binding.state.protected_scope_id,
            profile_id: binding.state.profile_id,
            profile_generation_ref_id: binding.state.active_profile_generation_ref_id,
            container_generation: binding.state.container_generation,
            namespace: runtime.namespace.clone(),
            pod_uid: runtime.pod_uid.clone(),
            container_name: runtime.container_name.clone(),
            full_container_id: runtime.full_container_id.clone(),
            init_pid: runtime.init_pid,
            working_directory: runtime.working_directory.clone(),
            path_entries: runtime.path_entries.clone(),
        })
    }

    pub fn publish_all(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<()> {
        self.publish(host, configured.iter().map(|spec| (spec, None)))
    }

    pub fn publish_held_initial_roots(
        &mut self,
        host: &KernelHost,
        configured: &[(WorkloadBindingConfig, u32)],
    ) -> Result<()> {
        self.publish(
            host,
            configured.iter().map(|(spec, pid)| (spec, Some(*pid))),
        )
    }

    pub(crate) fn retire_binding_id(&mut self, host: &KernelHost, binding_id: &str) -> Result<()> {
        let roots = self
            .bindings
            .iter()
            .filter(|(_root, binding)| binding.spec.binding_id == binding_id)
            .map(|(root, _binding)| *root)
            .collect::<Vec<_>>();
        ensure!(
            roots.len() <= 1,
            IdentityStateSnafu {
                reason: "one binding identity names more than one local cgroup",
            }
        );
        // Remove kernel authority before the local owner forgets the cgroup binding.
        if let Some(root) = roots.first().copied() {
            self.retire_owned_root(host, root)?;
        }
        Ok(())
    }

    pub(crate) fn retire_profile_bindings(
        &mut self,
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<()> {
        let profile_id = parse_id("profile_id", profile_id)?;
        let roots = self
            .bindings
            .iter()
            .filter(|(_root, binding)| {
                self.terminal_binding_matches_session(
                    &binding.state,
                    profile_id,
                    profile_generation_ref_id,
                )
            })
            .map(|(root, _binding)| *root)
            .collect::<Vec<_>>();
        for root in roots {
            let binding = self.bindings.get(&root).context(IdentityStateSnafu {
                reason: "stale policy retirement lost an owned workload binding",
            })?;
            ensure!(
                self.terminal_binding_matches_session(
                    &binding.state,
                    profile_id,
                    profile_generation_ref_id,
                ),
                IdentityStateSnafu {
                    reason: "stale policy retirement binding belongs to another profile generation",
                }
            );
            self.retire_owned_root(host, root)?;
        }

        let mut observed = BTreeSet::new();
        for key in host
            .map_keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let Some(bytes) = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let mut binding = execution_set_binding_state(&bytes)?;
            if !self.terminal_binding_matches_session(
                &binding,
                profile_id,
                profile_generation_ref_id,
            ) {
                continue;
            }
            ensure!(
                observed.insert(binding.binding_id),
                IdentityStateSnafu {
                    reason: "stale policy retirement found a duplicate workload binding",
                }
            );
            if matches!(
                binding.lifecycle_state,
                BindingLifecycleStateV1::Preparing
                    | BindingLifecycleStateV1::Active
                    | BindingLifecycleStateV1::Draining
            ) {
                binding.lifecycle_state = BindingLifecycleStateV1::Terminating;
                binding.initial_root_state = InitialRootStateV1::Consumed;
                if binding.prepared_container_state != PreparedContainerStateV1::Active {
                    binding.prepared_container_state = PreparedContainerStateV1::Expired;
                }
                binding.prepared_container_exec_task_cookie = 0;
                binding.transition_version =
                    binding
                        .transition_version
                        .checked_add(1)
                        .context(IdentityStateSnafu {
                            reason: "stale policy retirement binding transition version exhausted",
                        })?;
                host.update_map("execution_set_bindings", &key, binding.as_bytes())
                    .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("execution_set_bindings", &key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "stale policy retirement binding failed terminating readback",
                    }
                );
            } else {
                ensure!(
                    matches!(
                        binding.lifecycle_state,
                        BindingLifecycleStateV1::Terminating | BindingLifecycleStateV1::Tombstoned
                    ),
                    IdentityStateSnafu {
                        reason: "stale policy retirement binding has an invalid lifecycle state",
                    }
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub fn retire_profile_bindings_for_test(
        &mut self,
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<()> {
        self.retire_profile_bindings(host, profile_id, profile_generation_ref_id)
    }

    pub(crate) fn finalize_retired_profile_bindings(
        &self,
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<()> {
        let profile_id = parse_id("profile_id", profile_id)?;
        let mut observed = BTreeSet::new();
        for key in host
            .map_keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let Some(bytes) = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
            else {
                continue;
            };
            let mut binding = execution_set_binding_state(&bytes)?;
            if !self.terminal_binding_matches_session(
                &binding,
                profile_id,
                profile_generation_ref_id,
            ) {
                continue;
            }
            ensure!(
                observed.insert(binding.binding_id)
                    && matches!(
                        binding.lifecycle_state,
                        BindingLifecycleStateV1::Terminating | BindingLifecycleStateV1::Tombstoned
                    ),
                IdentityStateSnafu {
                    reason: "stale policy retirement cannot finalize a live or mismatched binding",
                }
            );
            if binding.lifecycle_state == BindingLifecycleStateV1::Terminating {
                binding.lifecycle_state = BindingLifecycleStateV1::Tombstoned;
                binding.transition_version =
                    binding
                        .transition_version
                        .checked_add(1)
                        .context(IdentityStateSnafu {
                            reason: "stale policy retirement binding transition version exhausted",
                        })?;
                host.update_map("execution_set_bindings", &key, binding.as_bytes())
                    .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("execution_set_bindings", &key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "stale policy retirement binding failed tombstone readback",
                    }
                );
            }
            host.delete_map_entry("execution_set_bindings", &key)
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("execution_set_bindings", &key)
                    .context(InterceptorSnafu)?
                    .is_none(),
                IdentityStateSnafu {
                    reason: "stale policy retirement binding survived deletion",
                }
            );
        }
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub fn finalize_retired_profile_bindings_for_test(
        &self,
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<()> {
        self.finalize_retired_profile_bindings(host, profile_id, profile_generation_ref_id)
    }

    fn terminal_binding_matches_session(
        &self,
        binding: &ExecutionSetBindingStateV1,
        profile_id: Id128V1,
        profile_generation_ref_id: u64,
    ) -> bool {
        binding.profile_id == profile_id
            && binding.active_profile_generation_ref_id == profile_generation_ref_id
            && binding.node_boot_id == self.node_boot_id
            && binding.label_epoch == self.label_epoch
    }

    pub(crate) fn publish_held_activated_root(
        &mut self,
        host: &KernelHost,
        spec: &WorkloadBindingConfig,
        initial_pid: u32,
    ) -> Result<()> {
        if let Err(error) = self.publish_held_initial_roots(host, &[(spec.clone(), initial_pid)]) {
            self.pending_runtime_admission = None;
            return Err(error);
        }
        let root = self
            .bindings
            .iter()
            .find(|(_root, binding)| binding.spec.binding_id == spec.binding_id)
            .map(|(root, _binding)| *root)
            .context(IdentityStateSnafu {
                reason: "held runtime binding disappeared after publication",
            })?;
        // Adopt only the CRI identity that was verified for this exact container ID.
        if let Some(runtime) = self.pending_runtime_admission.take() {
            ensure!(
                runtime.full_container_id == spec.container_id,
                IdentityStateSnafu {
                    reason: "verified CRI identity changed before binding publication",
                }
            );
            let binding = self.bindings.get_mut(&root).context(IdentityStateSnafu {
                reason: "published runtime binding disappeared before CRI adoption",
            })?;
            binding.runtime_identity = Some(runtime);
        }
        // Roll back the new binding if it cannot join the already active generation.
        if let Err(error) = self.install_late_activation_target(host, root, spec) {
            let rollback = self.retire_owned_root(host, root);
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => IdentityStateSnafu {
                    reason: format!(
                        "held runtime binding activation failed: {error}; termination failed: {rollback}"
                    ),
                }
                .fail(),
            };
        }
        Ok(())
    }

    pub(crate) fn verify_prepared_initial_root(
        &self,
        host: &KernelHost,
        binding_id: &str,
        initial_pid: u32,
    ) -> Result<()> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "prepared runtime binding disappeared before identity readback",
            })?;
        let key = binding.root_cgroup_id.to_ne_bytes();
        let live = host
            .lookup_map("execution_set_bindings", &key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "prepared runtime binding is absent from the kernel",
            })?;
        let live = execution_set_binding_state(&live)?;
        ensure!(
            same_runtime_binding(&binding.state, &live)
                && live.lifecycle_state == BindingLifecycleStateV1::Active
                && live.prepared_container_state == PreparedContainerStateV1::Prepared
                && live.prepared_container_initial_host_tgid == initial_pid
                && !live.prepared_container_entry_instance_id.is_zero(),
            IdentityStateSnafu {
                reason: "prepared runtime binding has no live exact initial entry",
            }
        );

        let pid = i32::try_from(initial_pid)
            .ok()
            .and_then(Pid::from_raw)
            .context(IdentityStateSnafu {
                reason: "prepared runtime binding has an invalid initial PID",
            })?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{initial_pid}")),
            })?;
        let label = host
            .lookup_map("task_labels", &pidfd.as_raw_fd().to_ne_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "prepared initial task has no kernel identity",
            })?;
        let label = TaskLabelV1::read_from_bytes(&label).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("prepared initial task label is invalid: {error}"),
            }
            .build()
        })?;
        ensure!(
            label.node_boot_id == self.node_boot_id
                && label.label_epoch == self.label_epoch
                && label.execution_set_id == live.execution_set_id
                && label.birth_profile_generation_ref_id == live.active_profile_generation_ref_id
                && label.placement.protected_root_binding_id == live.binding_id
                && label.placement.protected_root_binding_nonce == live.binding_nonce
                && label.entry_instance_id == live.prepared_container_entry_instance_id,
            IdentityStateSnafu {
                reason: "prepared initial task does not match its runtime binding",
            }
        );
        let coordinate = host
            .lookup_map("task_coordinates", &label.task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "prepared initial task has no kernel coordinate",
            })?;
        let coordinate = TaskCoordinateV1::try_read_from_bytes(&coordinate).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("prepared initial task coordinate is invalid: {error}"),
            }
            .build()
        })?;
        ensure!(
            coordinate.task_cookie == label.task_cookie
                && coordinate.host_tid == initial_pid
                && coordinate.host_tgid == initial_pid
                && coordinate.state == TaskCoordinateStateV1::Runnable,
            IdentityStateSnafu {
                reason: "prepared initial task coordinate is not exact and runnable",
            }
        );
        Ok(())
    }

    pub(crate) fn stage_runtime_admission(
        &mut self,
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<bool> {
        ensure!(
            request.operation == RuntimeAdmissionOperationV1::StageRuntimeFacts,
            IdentityStateSnafu {
                reason: "only the first ordered OCI hook can stage runtime facts",
            }
        );
        let now = Instant::now();
        self.staged_runtime_admissions
            .retain(|_container_id, stage| stage.deadline > now);
        let scheduled = ScheduledRuntimeBindingV1::resolve_stage(configured, request)?;
        let authority_head_binding_id = configured[scheduled.binding_index].binding_id.clone();
        let stage = StagedRuntimeAdmissionV1 {
            authority_head_binding_id,
            identity: request.kubernetes_identity()?,
            cgroup_path: request.cgroup_path.clone().context(IdentityStateSnafu {
                reason: "OCI runtime-fact stage has no cgroup path",
            })?,
            deadline: now + RUNTIME_STAGE_LIFETIME,
        };
        if let Some(existing) = self.staged_runtime_admissions.get(&request.container_id) {
            ensure!(
                existing.authority_head_binding_id == stage.authority_head_binding_id
                    && existing.identity == stage.identity
                    && existing.cgroup_path == stage.cgroup_path,
                IdentityStateSnafu {
                    reason: "the first OCI hook changed an existing runtime stage",
                }
            );
            return Ok(false);
        }
        ensure!(
            self.staged_runtime_admissions.len() < MAXIMUM_RUNTIME_STAGES,
            IdentityStateSnafu {
                reason: "runtime fact stage capacity is exhausted",
            }
        );
        self.staged_runtime_admissions
            .insert(request.container_id.clone(), stage);
        Ok(true)
    }

    pub(crate) async fn verify_runtime_preparation(
        &mut self,
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<ScheduledRuntimeBindingV1> {
        ensure!(
            self.pending_runtime_admission.is_none(),
            IdentityStateSnafu {
                reason: "one runtime admission is already pending",
            }
        );
        let now = Instant::now();
        let staged = self
            .staged_runtime_admissions
            .get(&request.container_id)
            .cloned()
            .context(IdentityStateSnafu {
                reason: "runtime admission has no live first-hook stage",
            })?;
        let mut scheduled = ScheduledRuntimeBindingV1::resolve(configured, request)?;
        staged.verify_preparation(
            &configured[scheduled.binding_index].binding_id,
            request,
            now,
        )?;
        scheduled.resolved.root_cgroup_path = Some(staged.cgroup_path);
        let runtime = self.runtime.as_mut().context(IdentityStateSnafu {
            reason: "runtime admission has no CRI inventory owner",
        })?;
        // CRI must still report Created while the OCI hook holds the initial process.
        let identity = runtime
            .inspect_created_for_admission(&scheduled.resolved)
            .await?;
        scheduled.resolved.container_generation = identity.generation;
        self.pending_runtime_admission = Some(identity);
        Ok(scheduled)
    }

    pub(crate) fn verify_runtime_entry_preparation(
        &self,
        configured: &[WorkloadBindingConfig],
        request: &RuntimeAdmissionRequestV1,
    ) -> Result<(String, u32)> {
        ensure!(
            request.operation == RuntimeAdmissionOperationV1::PrepareDeclaredEntries,
            IdentityStateSnafu {
                reason: "declared-entry preparation requires the post-root OCI hook",
            }
        );
        let staged = self
            .staged_runtime_admissions
            .get(&request.container_id)
            .context(IdentityStateSnafu {
                reason: "declared-entry preparation has no live runtime stage",
            })?;
        let identity = request.kubernetes_identity()?;
        let matches = configured
            .iter()
            .filter(|binding| {
                binding.scheduled_binding_authority_id.is_some()
                    && binding.container_id == request.container_id
                    && binding.profile_id == identity.profile_id
                    && binding.namespace == identity.namespace
                    && binding.pod_uid == identity.pod_uid
                    && binding.container_name == identity.container_name
                    && binding.image_digest == identity.image_digest
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            IdentityStateSnafu {
                reason: "declared-entry preparation does not resolve to one runtime binding",
            }
        );
        let spec = matches[0];
        let authority_binding_id =
            spec.scheduled_binding_authority_id
                .as_deref()
                .context(IdentityStateSnafu {
                    reason: "runtime binding lost its scheduled authority",
                })?;
        staged.verify_declared_entries(authority_binding_id, request, Instant::now())?;
        ensure!(
            spec.binding_id
                == ScheduledRuntimeBindingV1::runtime_binding_id(
                    authority_binding_id,
                    &request.container_id,
                )
                && spec.root_cgroup_path.as_ref() == Some(&staged.cgroup_path),
            IdentityStateSnafu {
                reason: "declared-entry preparation does not match its concrete runtime binding",
            }
        );
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == spec.binding_id)
            .context(IdentityStateSnafu {
                reason: "declared-entry preparation has no published runtime binding",
            })?;
        binding.validate_live_cgroup()?;
        let held_initial_pid = binding.held_initial_pid.context(IdentityStateSnafu {
            reason: "declared-entry preparation has no held initial task",
        })?;
        ensure!(
            held_initial_pid > 0
                && binding.state.prepared_container_state == PreparedContainerStateV1::Prepared,
            IdentityStateSnafu {
                reason: "declared-entry preparation has no prepared initial task",
            }
        );
        Ok((spec.binding_id.clone(), held_initial_pid))
    }

    pub(crate) fn verify_runtime_entry_admissions(
        &self,
        host: &KernelHost,
        binding_id: &str,
    ) -> Result<()> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "declared-entry readback has no published runtime binding",
            })?;
        let mut count = 0_usize;
        let mut admitted_rules = BTreeSet::new();
        for key in host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?
        {
            let key = EntryAdmissionRuleKeyV1::try_read_from_bytes(&key).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("entry admission key has the wrong ABI: {error}"),
                }
                .build()
            })?;
            if key.profile_generation_ref_id != binding.state.active_profile_generation_ref_id
                || key.binding_id != binding.state.binding_id
            {
                continue;
            }
            let value = host
                .lookup_map("entry_admission_rules", key.as_bytes())
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "declared entry disappeared during exact readback",
                })?;
            let value = EntryAdmissionRuleV1::try_read_from_bytes(&value).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("entry admission value has the wrong ABI: {error}"),
                }
                .build()
            })?;
            ensure!(
                value.exact_object_key_id != 0
                    && value.executable_object != ExactFileObjectKeyV1::default()
                    && admitted_rules.insert(value.admitted_entry_rule_id),
                IdentityStateSnafu {
                    reason: "declared-entry table has deferred or colliding executable proof",
                }
            );
            count += 1;
        }
        ensure!(
            count > 0,
            IdentityStateSnafu {
                reason: "declared-entry table has no exact executable proof",
            }
        );
        Ok(())
    }

    pub(crate) fn cancel_runtime_admission(&mut self) {
        self.pending_runtime_admission = None;
    }

    pub(crate) fn discard_runtime_stage(&mut self, container_id: &str) {
        self.staged_runtime_admissions.remove(container_id);
    }

    fn install_runtime_entry_admissions(
        host: &KernelHost,
        binding: &PublishedBinding,
    ) -> Result<()> {
        let Some(authority_binding_id) = binding.spec.scheduled_binding_authority_id.as_deref()
        else {
            return Ok(());
        };
        let authority_binding_id =
            parse_id("scheduled_binding_authority_id", authority_binding_id)?;
        let mut rows = Vec::new();
        for source_key in host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?
        {
            let source =
                EntryAdmissionRuleKeyV1::try_read_from_bytes(&source_key).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("entry admission key has the wrong ABI: {error}"),
                    }
                    .build()
                })?;
            if source.profile_generation_ref_id != binding.state.active_profile_generation_ref_id
                || source.binding_id != authority_binding_id
            {
                continue;
            }
            let value = host
                .lookup_map("entry_admission_rules", &source_key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "scheduled entry admission disappeared during runtime publication",
                })?;
            let mut target = source;
            target.binding_id = binding.state.binding_id;
            rows.push((target.as_bytes().to_vec(), value));
        }
        ensure!(
            !rows.is_empty(),
            IdentityStateSnafu {
                reason: "scheduled runtime binding has no entry admission rows",
            }
        );

        let mut inserted = Vec::new();
        let result = (|| {
            for (key, value) in &rows {
                match host
                    .lookup_map("entry_admission_rules", key)
                    .context(InterceptorSnafu)?
                {
                    Some(existing) => ensure!(
                        existing == *value,
                        IdentityStateSnafu {
                            reason: "runtime entry admission changed during publication",
                        }
                    ),
                    None => {
                        ensure!(
                            host.insert_map("entry_admission_rules", key, value)
                                .context(InterceptorSnafu)?
                                == MapInsertResult::Inserted,
                            IdentityStateSnafu {
                                reason: "runtime entry admission changed during insertion",
                            }
                        );
                        inserted.push(key.clone());
                    }
                }
                ensure!(
                    host.lookup_map("entry_admission_rules", key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(value.as_slice()),
                    IdentityStateSnafu {
                        reason: "runtime entry admission failed readback",
                    }
                );
            }
            Ok(())
        })();
        if let Err(error) = result {
            let rollback = inserted.iter().try_for_each(|key| {
                host.delete_map_entry("entry_admission_rules", key)
                    .context(InterceptorSnafu)
            });
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => IdentityStateSnafu {
                    reason: format!(
                        "runtime entry admission publication failed: {error}; rollback failed: {rollback}"
                    ),
                }
                .fail(),
            };
        }
        Ok(())
    }

    fn remove_runtime_entry_admissions(
        host: &KernelHost,
        binding: &PublishedBinding,
    ) -> Result<()> {
        if binding.spec.scheduled_binding_authority_id.is_none() {
            return Ok(());
        }
        let keys = host
            .map_keys("entry_admission_rules")
            .context(InterceptorSnafu)?;
        for key in keys {
            let admission =
                EntryAdmissionRuleKeyV1::try_read_from_bytes(&key).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("entry admission key has the wrong ABI: {error}"),
                    }
                    .build()
                })?;
            if admission.profile_generation_ref_id != binding.state.active_profile_generation_ref_id
                || admission.binding_id != binding.state.binding_id
            {
                continue;
            }
            host.delete_map_entry("entry_admission_rules", &key)
                .context(InterceptorSnafu)?;
            ensure!(
                host.lookup_map("entry_admission_rules", &key)
                    .context(InterceptorSnafu)?
                    .is_none(),
                IdentityStateSnafu {
                    reason: "retired runtime entry admission survived deletion",
                }
            );
        }
        Ok(())
    }

    fn install_late_activation_target(
        &mut self,
        host: &KernelHost,
        root: u64,
        spec: &WorkloadBindingConfig,
    ) -> Result<()> {
        let binding = self.bindings.get(&root).context(IdentityStateSnafu {
            reason: "held runtime binding is not published",
        })?;
        binding.validate_live_cgroup()?;
        binding.require_initial_root_admission()?;
        // Read the active pointer and descriptor before adding a late cgroup target.
        let active = host
            .lookup_map(
                "active_profile_generations",
                binding.state.profile_id.as_bytes(),
            )
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "held runtime binding has no active signed profile",
            })?;
        let active = u64::read_from_bytes(&active).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("active runtime-gate generation is invalid: {error}"),
            }
            .build()
        })?;
        ensure!(
            active == spec.active_profile_generation_ref_id,
            IdentityStateSnafu {
                reason: "held runtime binding names a stale profile generation",
            }
        );
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &active.to_ne_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "held runtime binding active generation has no descriptor",
            })?;
        let descriptor =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("held runtime binding descriptor is invalid: {error}"),
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
                reason:
                    "held runtime binding descriptor is stale or belongs to another node session",
            }
        );
        let key = BindingActivationTargetKeyV1 {
            binding_id: binding.state.binding_id,
            profile_generation_ref_id: active,
        };
        let previous = host
            .lookup_map("binding_activation_targets", key.as_bytes())
            .context(InterceptorSnafu)?;
        let previous_target = previous
            .as_deref()
            .map(execution_set_binding_state)
            .transpose()?;
        ensure!(
            previous_target.as_ref().is_none_or(|target| {
                Self::activation_target_matches_desired(&binding.state, target)
            }),
            IdentityStateSnafu {
                reason: "held runtime binding activation target is not immutable",
            }
        );
        // Existing identical state is idempotent; different state is never overwritten.
        if previous.is_none() {
            ensure!(
                host.insert_map(
                    "binding_activation_targets",
                    key.as_bytes(),
                    binding.state.as_bytes(),
                )
                .context(InterceptorSnafu)?
                    == MapInsertResult::Inserted,
                IdentityStateSnafu {
                    reason: "held runtime binding activation target changed during publication",
                }
            );
        }
        let observed = host
            .lookup_map("binding_activation_targets", key.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "held runtime binding activation target disappeared",
            })?;
        let observed = execution_set_binding_state(&observed)?;
        ensure!(
            Self::activation_target_matches_desired(&binding.state, &observed),
            IdentityStateSnafu {
                reason: "held runtime binding activation target failed readback",
            }
        );
        Self::install_runtime_entry_admissions(host, binding)?;
        self.profile_handles
            .insert(active, binding.state.profile_id);
        Ok(())
    }

    fn publish<'a>(
        &mut self,
        host: &KernelHost,
        configured: impl IntoIterator<Item = (&'a WorkloadBindingConfig, Option<u32>)>,
    ) -> Result<()> {
        for (spec, held_initial_pid) in configured {
            let mut binding = self.prepare(spec)?;
            ensure!(
                held_initial_pid.is_none() || spec.arm_initial_root,
                IdentityStateSnafu {
                    reason: "runtime admission requires an armed initial root",
                }
            );
            binding.held_initial_pid = held_initial_pid;
            if held_initial_pid.is_some() {
                binding.prepare_container()?;
            }
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
                if binding.reconcile_recovered_prepared_container()? {
                    host.update_map("execution_set_bindings", &key, binding.state.as_bytes())
                        .context(InterceptorSnafu)?;
                    ensure!(
                        host.lookup_map("execution_set_bindings", &key)
                            .context(InterceptorSnafu)?
                            .as_deref()
                            == Some(binding.state.as_bytes()),
                        IdentityStateSnafu {
                            reason: "expired prepared container failed kernel readback",
                        }
                    );
                }
            } else {
                binding.require_initial_root_admission()?;
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
                if binding.held_initial_pid.is_none() {
                    reserve_live_root_task_labels(host, &binding)?;
                } else {
                    binding.require_initial_root_admission()?;
                }
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
                binding.require_initial_root_admission()?;
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
        let mut adopted = Vec::with_capacity(self.bindings.len());
        let mut profile_handles = BTreeMap::new();
        for (&root_cgroup_id, binding) in &self.bindings {
            let spec = configured
                .iter()
                .find(|spec| spec.binding_id == binding.spec.binding_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "published binding `{}` is not configured",
                        binding.spec.binding_id
                    ),
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
            binding.verify_activated_profile(spec, &activated)?;
            ensure!(
                profile_handles
                    .insert(active, activated.profile_id)
                    .is_none_or(|profile_id| profile_id == activated.profile_id),
                IdentityStateSnafu {
                    reason: format!(
                        "profile-generation handle {active} is assigned to more than one profile"
                    ),
                }
            );
            adopted.push((root_cgroup_id, spec.clone(), activated));
        }
        for (root_cgroup_id, spec, activated) in adopted {
            let binding = self
                .bindings
                .get_mut(&root_cgroup_id)
                .context(IdentityStateSnafu {
                    reason: "verified activated binding disappeared before adoption",
                })?;
            binding.adopt_activated_profile(spec, activated);
        }
        self.profile_handles = profile_handles;
        Ok(())
    }

    pub(crate) fn exact_object_binding_targets(
        &self,
    ) -> impl Iterator<Item = ExactObjectBindingTargetV1<'_>> {
        self.bindings
            .values()
            .filter(|binding| binding.state.lifecycle_state == BindingLifecycleStateV1::Active)
            .filter_map(|binding| {
                let init_pid = binding
                    .held_initial_pid
                    .filter(|pid| *pid > 0)
                    .or_else(|| {
                        let runtime = binding.runtime_identity.as_ref()?;
                        (runtime.state == super::runtime::RuntimeContainerState::Running
                            && runtime.init_pid > 0)
                            .then_some(runtime.init_pid)
                    })?;
                Some(ExactObjectBindingTargetV1 {
                    binding_id: &binding.spec.binding_id,
                    init_pid,
                })
            })
    }

    pub(crate) async fn reconcile(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<RuntimeReconciliationResultV1> {
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
        Ok(RuntimeReconciliationResultV1::default())
    }

    async fn reconcile_runtime(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<RuntimeReconciliationResultV1> {
        match self.reconcile_runtime_inner(host, configured).await {
            Ok(reconciliation) => Ok(reconciliation),
            Err(source) if source.retry_hint() == RetryHint::Retryable => Err(source),
            Err(source) => {
                self.terminate_all(host)?;
                Err(source)
            }
        }
    }

    async fn reconcile_runtime_inner(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
    ) -> Result<RuntimeReconciliationResultV1> {
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
        let mut retired_binding_ids = Self::retired_configured_binding_ids(configured, &observed);
        let plan = self.plan_runtime_reconciliation(observed)?;
        retired_binding_ids.extend(plan.retired_binding_ids.iter().cloned());
        for root_id in plan.missing_root_ids {
            self.retire_owned_root(host, root_id)?;
        }
        for update in plan.updates {
            let binding = self
                .bindings
                .get_mut(&update.root_id)
                .context(IdentityStateSnafu {
                    reason: "runtime state update lost its published binding",
                })?;
            binding.runtime_identity = Some(update.identity);
        }
        for identity in plan.new_identities {
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
        self.retain_only_configured(host)?;
        Ok(RuntimeReconciliationResultV1 {
            retired_binding_ids: retired_binding_ids.into_iter().collect(),
        })
    }

    fn plan_runtime_reconciliation(
        &self,
        mut observed: BTreeMap<String, RuntimeContainerIdentity>,
    ) -> Result<RuntimeReconciliationPlan> {
        let mut plan = RuntimeReconciliationPlan::default();
        for (&root_id, binding) in &self.bindings {
            let Some(expected) = binding.runtime_identity.as_ref() else {
                binding.validate_live_cgroup()?;
                continue;
            };
            let Some(current) = observed.remove(&binding.spec.container_id) else {
                plan.retire_binding(root_id, binding);
                continue;
            };
            if !binding.live_runtime_cgroup_exists()? {
                plan.retire_binding(root_id, binding);
                continue;
            }
            ensure!(
                expected.accepts_observed_lifetime(&current),
                IdentityStateSnafu {
                    reason: format!(
                        "live CRI identity changed for `{}`",
                        binding.spec.container_id
                    ),
                }
            );
            if current.state != expected.state {
                ensure!(
                    expected.state == super::runtime::RuntimeContainerState::Created
                        && current.state == super::runtime::RuntimeContainerState::Running,
                    IdentityStateSnafu {
                        reason: format!("CRI state regressed for `{}`", binding.spec.container_id),
                    }
                );
                plan.updates.push(RuntimeBindingUpdate {
                    root_id,
                    identity: current,
                });
            }
        }
        plan.new_identities = observed.into_values().collect();
        Ok(plan)
    }

    fn retired_configured_binding_ids(
        configured: &[WorkloadBindingConfig],
        observed: &BTreeMap<String, RuntimeContainerIdentity>,
    ) -> BTreeSet<String> {
        configured
            .iter()
            .filter(|binding| {
                binding.scheduled_binding_authority_id.is_some()
                    && binding.root_cgroup_path.is_some()
                    && !observed.contains_key(&binding.container_id)
            })
            .map(|binding| binding.binding_id.clone())
            .collect()
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
            held_initial_pid: None,
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
                prepared_container_state: PreparedContainerStateV1::Unarmed,
                prepared_container_entry_instance_id: Id128V1::ZERO,
                prepared_container_exec_task_cookie: 0,
                prepared_container_initial_host_tgid: 0,
                prepared_container_bootstrap_state: 0,
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

    fn retire_owned_root(&mut self, host: &KernelHost, root_id: u64) -> Result<()> {
        self.terminate(host, root_id)?;
        let binding = self.bindings.get(&root_id).context(IdentityStateSnafu {
            reason: "retired runtime binding disappeared before entry cleanup",
        })?;
        Self::remove_runtime_entry_admissions(host, binding)?;
        self.bindings.remove(&root_id);
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
        if binding.state.prepared_container_state != PreparedContainerStateV1::Active {
            binding.state.prepared_container_state = PreparedContainerStateV1::Expired;
        }
        binding.state.prepared_container_exec_task_cookie = 0;
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
            if value.prepared_container_state != PreparedContainerStateV1::Active {
                value.prepared_container_state = PreparedContainerStateV1::Expired;
            }
            value.prepared_container_exec_task_cookie = 0;
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

    pub(crate) fn same_activation_identity(
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
        live.prepared_container_state = target.prepared_container_state;
        live.prepared_container_entry_instance_id = target.prepared_container_entry_instance_id;
        live.prepared_container_exec_task_cookie = target.prepared_container_exec_task_cookie;
        live.prepared_container_initial_host_tgid = target.prepared_container_initial_host_tgid;
        live.prepared_container_bootstrap_state = target.prepared_container_bootstrap_state;
        live == *target
    }

    pub(crate) fn activation_target_matches_desired(
        desired: &ExecutionSetBindingStateV1,
        target: &ExecutionSetBindingStateV1,
    ) -> bool {
        Self::same_activation_identity(desired, target)
            && desired.active_profile_generation_ref_id == target.active_profile_generation_ref_id
            && desired.initial_role_id == target.initial_role_id
            && desired.external_role_id == target.external_role_id
            && desired.lifecycle_state == BindingLifecycleStateV1::Active
            && target.lifecycle_state == BindingLifecycleStateV1::Active
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

fn reserve_live_root_task_labels(host: &KernelHost, binding: &PublishedBinding) -> Result<()> {
    let tasks_path = binding.root_cgroup_path.join("cgroup.procs");
    let tasks = fs::read_to_string(&tasks_path).context(IoSnafu { path: &tasks_path })?;
    let empty_label = [0_u8; size_of::<TaskLabelV1>()];

    for raw_pid in tasks.split_whitespace() {
        let raw_pid = raw_pid.parse::<i32>().map_err(|error| {
            IdentityStateSnafu {
                reason: format!(
                    "binding `{}` has an invalid live task PID `{raw_pid}`: {error}",
                    binding.spec.binding_id
                ),
            }
            .build()
        })?;
        let pid = Pid::from_raw(raw_pid).context(IdentityStateSnafu {
            reason: format!(
                "binding `{}` has a zero live task PID",
                binding.spec.binding_id
            ),
        })?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: &tasks_path })?;
        match host
            .insert_map(
                "task_labels",
                &pidfd.as_raw_fd().to_ne_bytes(),
                &empty_label,
            )
            .context(InterceptorSnafu)?
        {
            MapInsertResult::Inserted | MapInsertResult::AlreadyExists => {}
        }
    }
    Ok(())
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
    desired.prepared_container_state = recovered.prepared_container_state;
    desired.prepared_container_entry_instance_id = recovered.prepared_container_entry_instance_id;
    desired.prepared_container_exec_task_cookie = recovered.prepared_container_exec_task_cookie;
    desired.prepared_container_initial_host_tgid = recovered.prepared_container_initial_host_tgid;
    desired.prepared_container_bootstrap_state = recovered.prepared_container_bootstrap_state;
    desired == *recovered
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use snafu::{OptionExt as _, ResultExt as _};

    use super::{
        same_runtime_binding, RuntimeContainerIdentity, StagedRuntimeAdmissionV1,
        WorkloadBindingOwner,
    };
    use crate::error::{IdentityStateSnafu, IoSnafu};
    use crate::identity::runtime::RuntimeContainerState;
    use crate::runtime_admission::ScheduledRuntimeBindingV1;
    use crate::{
        RuntimeAdmissionOperationV1, RuntimeAdmissionRequestV1, WorkloadBindingConfig,
        CONTAINER_NAME_ANNOTATION, IMAGE_NAME_ANNOTATION, POD_NAMESPACE_ANNOTATION,
        POD_UID_ANNOTATION, POLICY_SOURCE_REVISION_ANNOTATION, PROFILE_ID_ANNOTATION,
        SANDBOX_ID_ANNOTATION,
    };
    use erebor_interceptor_abi::{Id128V1, InitialRootStateV1, PreparedContainerStateV1};

    fn spec(root: &Path) -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            binding_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            scheduled_binding_authority_id: None,
            scheduled_target_digest: None,
            execution_set_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            protected_scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            workload_selector_id: "worker".to_owned(),
            profile_id: "33333333-3333-4333-8333-333333333333".to_owned(),
            container_id: "a".repeat(64),
            namespace: "default".to_owned(),
            cluster_uid: String::new(),
            namespace_uid: String::new(),
            controller_uid: String::new(),
            service_account_uid: String::new(),
            pod_labels: BTreeMap::new(),
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

    fn authorization_request(_cgroup_path: &Path) -> RuntimeAdmissionRequestV1 {
        RuntimeAdmissionRequestV1 {
            operation: RuntimeAdmissionOperationV1::PrepareContainer,
            container_id: "a".repeat(64),
            initial_pid: Some(42),
            cgroup_path: None,
            oci_bundle: None,
            annotations: BTreeMap::from([
                (POD_NAMESPACE_ANNOTATION.to_owned(), "default".to_owned()),
                (POD_UID_ANNOTATION.to_owned(), "pod-uid-a".to_owned()),
                (CONTAINER_NAME_ANNOTATION.to_owned(), "worker".to_owned()),
                (
                    IMAGE_NAME_ANNOTATION.to_owned(),
                    format!("worker@sha256:{}", "b".repeat(64)),
                ),
                (SANDBOX_ID_ANNOTATION.to_owned(), "c".repeat(64)),
                (
                    PROFILE_ID_ANNOTATION.to_owned(),
                    "33333333-3333-4333-8333-333333333333".to_owned(),
                ),
                (POLICY_SOURCE_REVISION_ANNOTATION.to_owned(), "d".repeat(64)),
            ]),
        }
    }

    #[test]
    fn preparation_must_match_the_staged_authority_head_and_runtime_facts() -> crate::Result<()> {
        let cgroup = PathBuf::from("/sys/fs/cgroup/kubepods/pod-a/container-a");
        let request = authorization_request(&cgroup);
        let stage = StagedRuntimeAdmissionV1 {
            authority_head_binding_id: "authority-head-a".to_owned(),
            identity: request.kubernetes_identity()?,
            cgroup_path: cgroup.clone(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let now = Instant::now();
        stage.verify_preparation("authority-head-a", &request, now)?;
        let mut entries = request.clone();
        entries.operation = RuntimeAdmissionOperationV1::PrepareDeclaredEntries;
        entries.initial_pid = None;
        entries.oci_bundle = Some(PathBuf::from("/run/oci/container-a"));
        stage.verify_declared_entries("authority-head-a", &entries, now)?;

        assert!(stage
            .verify_preparation("authority-head-b", &request, now)
            .is_err());
        let mut wrong_identity = authorization_request(&cgroup);
        wrong_identity
            .annotations
            .insert(POD_UID_ANNOTATION.to_owned(), "pod-uid-b".to_owned());
        assert!(stage
            .verify_preparation("authority-head-a", &wrong_identity, now)
            .is_err());
        assert!(stage
            .verify_declared_entries("authority-head-a", &wrong_identity, now)
            .is_err());
        let mut expired = stage;
        expired.deadline = now;
        assert!(expired
            .verify_preparation("authority-head-a", &request, now)
            .is_err());
        Ok(())
    }

    #[test]
    fn first_create_runtime_stage_does_not_wait_for_cri() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary runtime stage root",
        })?;
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let cgroup = PathBuf::from("/sys/fs/cgroup/kubepods/pod-a/container-a");
        let mut request = authorization_request(&cgroup);
        request.operation = RuntimeAdmissionOperationV1::StageRuntimeFacts;
        request.initial_pid = None;
        request.cgroup_path = Some(cgroup.clone());
        let authority = ScheduledRuntimeBindingV1::authority_binding_id("pod-uid-a", "worker");
        let mut scheduled = spec(temporary.path());
        scheduled.binding_id.clone_from(&authority);
        scheduled.scheduled_binding_authority_id = Some(authority);
        scheduled.container_id = "scheduled:pod-uid-a:worker".to_owned();
        scheduled.image_digest = format!("sha256:{}", "b".repeat(64));

        assert!(owner.stage_runtime_admission(&[scheduled], &request)?);
        assert!(owner.pending_runtime_admission.is_none());
        assert_eq!(
            owner
                .staged_runtime_admissions
                .get(&request.container_id)
                .map(|stage| stage.cgroup_path.as_path()),
            Some(cgroup.as_path())
        );
        Ok(())
    }

    #[tokio::test]
    async fn authorization_without_a_first_hook_stage_fails_before_cri() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary missing runtime stage root",
        })?;
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let request = authorization_request(Path::new("/sys/fs/cgroup/kubepods/pod-a/container-a"));
        let Err(error) = owner.verify_runtime_preparation(&[], &request).await else {
            return IdentityStateSnafu {
                reason: "runtime authorization without staging reached runtime inventory"
                    .to_owned(),
            }
            .fail();
        };
        assert!(error.to_string().contains("no live first-hook stage"));
        Ok(())
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
        assert!(owner
            .prepare(&spec(&root))?
            .require_initial_root_admission()
            .is_err());
        Ok(())
    }

    #[test]
    fn held_initial_pid_can_claim_initial_root() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        binding.held_initial_pid = Some(42);
        binding.require_initial_root_admission()?;

        binding.held_initial_pid = Some(43);
        assert!(binding.require_initial_root_admission().is_err());
        fs::write(root.join("cgroup.procs"), "42\n43\n").context(IoSnafu { path: &root })?;
        binding.held_initial_pid = Some(42);
        assert!(binding.require_initial_root_admission().is_err());

        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        binding.held_initial_pid = Some(42);
        let root_id = binding.root_cgroup_id;
        owner.bindings.insert(root_id, binding);
        let targets = owner.exact_object_binding_targets().collect::<Vec<_>>();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].binding_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(targets[0].init_pid, 42);
        Ok(())
    }

    #[test]
    fn only_a_held_runtime_root_prepares_the_container() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary prepared-container cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        assert_eq!(
            binding.state.prepared_container_state,
            PreparedContainerStateV1::Unarmed
        );
        assert_eq!(binding.state.prepared_container_initial_host_tgid, 0);

        binding.held_initial_pid = Some(42);
        binding.prepare_container()?;
        assert_eq!(
            binding.state.prepared_container_state,
            PreparedContainerStateV1::Prepared
        );
        assert_eq!(binding.state.prepared_container_initial_host_tgid, 42);
        assert!(binding.prepare_container().is_err());
        Ok(())
    }

    #[test]
    fn recovery_refuses_prepared_or_ambiguous_state() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary prepared-container recovery root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        binding.held_initial_pid = Some(42);
        binding.prepare_container()?;

        assert!(binding.reconcile_recovered_prepared_container().is_err());
        binding.state.prepared_container_state = PreparedContainerStateV1::Active;
        binding.state.prepared_container_entry_instance_id = Id128V1::new(9, 10);
        binding.state.prepared_container_exec_task_cookie = 42;
        assert!(binding.reconcile_recovered_prepared_container()?);
        assert_eq!(binding.state.prepared_container_exec_task_cookie, 0);
        binding.state.prepared_container_state = PreparedContainerStateV1::ExecPending;
        binding.state.prepared_container_exec_task_cookie = 42;
        assert!(binding.reconcile_recovered_prepared_container().is_err());
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
        recovered.root_cgroup_live_interval_id = Id128V1::new(11, 12);
        assert!(!same_runtime_binding(&desired, &recovered));
        recovered.root_cgroup_live_interval_id = desired.root_cgroup_live_interval_id;
        recovered.execution_set_id = Id128V1::new(11, 12);
        assert!(!same_runtime_binding(&desired, &recovered));
        Ok(())
    }

    #[test]
    fn stale_policy_retirement_rejects_a_binding_from_another_node_session() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary terminal binding session directory",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?.state;
        assert!(owner.terminal_binding_matches_session(
            &binding,
            binding.profile_id,
            binding.active_profile_generation_ref_id,
        ));
        binding.node_boot_id = Id128V1::new(9, 10);
        assert!(!owner.terminal_binding_matches_session(
            &binding,
            binding.profile_id,
            binding.active_profile_generation_ref_id,
        ));
        binding.node_boot_id = Id128V1::new(1, 2);
        binding.label_epoch = 4;
        assert!(!owner.terminal_binding_matches_session(
            &binding,
            binding.profile_id,
            binding.active_profile_generation_ref_id,
        ));
        Ok(())
    }

    #[test]
    fn stale_policy_retirement_uses_the_profile_generation_not_the_runtime_alias(
    ) -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary stale policy runtime alias directory",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?.state;
        let authority_binding_id = binding.binding_id;
        binding.binding_id = Id128V1::new(9, 10);

        assert_ne!(binding.binding_id, authority_binding_id);
        assert!(owner.terminal_binding_matches_session(
            &binding,
            binding.profile_id,
            binding.active_profile_generation_ref_id,
        ));
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
        target.transition_version += 1;
        target.initial_root_state = InitialRootStateV1::Consumed;
        target.prepared_container_state = PreparedContainerStateV1::Active;
        target.prepared_container_entry_instance_id = Id128V1::new(11, 12);
        target.prepared_container_exec_task_cookie = 13;
        target.prepared_container_initial_host_tgid = 14;
        assert!(WorkloadBindingOwner::same_activation_identity(
            &live, &target
        ));
        assert!(WorkloadBindingOwner::activation_target_matches_desired(
            &live, &target
        ));

        target.active_profile_generation_ref_id += 1;
        target.initial_role_id += 1;
        target.external_role_id += 1;
        assert!(WorkloadBindingOwner::same_activation_identity(
            &live, &target
        ));
        assert!(!WorkloadBindingOwner::activation_target_matches_desired(
            &live, &target
        ));

        target.binding_nonce = Id128V1::new(9, 10);
        assert!(!WorkloadBindingOwner::same_activation_identity(
            &live, &target
        ));
        Ok(())
    }

    #[test]
    fn live_binding_adopts_a_replacement_profile_generation() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary replacement profile root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        let previous = binding.state;
        let mut replacement = binding.spec.clone();
        replacement.active_profile_generation_ref_id += 1;
        replacement.initial_role_id += 2;
        replacement.external_role_id += 2;
        let mut activated = previous;
        activated.active_profile_generation_ref_id = replacement.active_profile_generation_ref_id;
        activated.initial_role_id = replacement.initial_role_id;
        activated.external_role_id = replacement.external_role_id;
        activated.initial_root_state = InitialRootStateV1::Consumed;
        activated.transition_version += 1;

        binding.verify_activated_profile(&replacement, &activated)?;
        binding.adopt_activated_profile(replacement.clone(), activated);

        assert_eq!(binding.spec, replacement);
        assert_eq!(binding.state, activated);
        assert_ne!(
            binding.state.active_profile_generation_ref_id,
            previous.active_profile_generation_ref_id
        );
        Ok(())
    }

    #[test]
    fn runtime_inventory_advances_running_bindings_and_retires_missing_lifetimes(
    ) -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut configured = spec(&root);
        configured.scheduled_binding_authority_id =
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned());
        configured.scheduled_target_digest = Some("a".repeat(64));
        let identity = RuntimeContainerIdentity {
            full_container_id: configured.container_id.clone(),
            namespace: configured.namespace.clone(),
            pod_uid: configured.pod_uid.clone(),
            sandbox_id: configured.sandbox_id.clone(),
            container_name: configured.container_name.clone(),
            image_digest: configured.image_digest.clone(),
            generation: configured.container_generation,
            cgroup_path: root.clone(),
            init_pid: 0,
            working_directory: PathBuf::from("/"),
            path_entries: vec![PathBuf::from("/usr/bin")],
            state: RuntimeContainerState::Created,
        };
        let mut binding = owner.prepare(&identity.resolve(&configured))?;
        let root_id = binding.root_cgroup_id;
        binding.runtime_identity = Some(identity.clone());
        owner.bindings.insert(root_id, binding);
        assert_eq!(owner.exact_object_binding_targets().count(), 0);

        let binding = owner
            .bindings
            .get_mut(&root_id)
            .context(IdentityStateSnafu {
                reason: "test binding disappeared before its held transition",
            })?;
        binding.held_initial_pid = Some(std::process::id());
        binding.prepare_container()?;
        let held = owner.exact_object_binding_targets().collect::<Vec<_>>();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].init_pid, std::process::id());

        let running = RuntimeContainerIdentity {
            init_pid: std::process::id(),
            state: RuntimeContainerState::Running,
            ..identity
        };
        let observed = BTreeMap::from([(running.full_container_id.clone(), running.clone())]);
        let plan = owner.plan_runtime_reconciliation(observed)?;
        assert!(plan.missing_root_ids.is_empty());
        assert!(plan.new_identities.is_empty());
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].root_id, root_id);
        owner
            .bindings
            .get_mut(&root_id)
            .context(IdentityStateSnafu {
                reason: "test binding disappeared before its running transition",
            })?
            .runtime_identity = Some(running.clone());
        assert_eq!(owner.exact_object_binding_targets().count(), 1);

        fs::remove_file(root.join("cgroup.procs")).context(IoSnafu { path: &root })?;
        fs::remove_dir(&root).context(IoSnafu { path: &root })?;
        let stale_observed = BTreeMap::from([(running.full_container_id.clone(), running.clone())]);
        let plan = owner.plan_runtime_reconciliation(stale_observed)?;
        assert_eq!(plan.missing_root_ids, vec![root_id]);
        assert!(plan.new_identities.is_empty());
        assert_eq!(
            plan.retired_binding_ids,
            BTreeSet::from([configured.binding_id.clone()])
        );
        assert!(plan.updates.is_empty());

        let plan = owner.plan_runtime_reconciliation(BTreeMap::new())?;
        assert_eq!(plan.missing_root_ids, vec![root_id]);
        assert!(plan.new_identities.is_empty());
        assert!(plan.updates.is_empty());

        assert_eq!(
            WorkloadBindingOwner::retired_configured_binding_ids(
                &[configured.clone()],
                &BTreeMap::new(),
            ),
            BTreeSet::from([configured.binding_id])
        );
        Ok(())
    }
}
