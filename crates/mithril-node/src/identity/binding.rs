use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::mem::size_of;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use erebor_interceptor::{KernelHost, MapInsertResult};
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, BindingLifecycleStateV1, DeclaredEntryRequestV1,
    EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExactFileObjectKeyV1,
    ExecutionSetBindingStateV1, Id128V1, InitialRootStateV1, PolicyGenerationStateV1,
    ProfileGenerationDescriptorV1, RecoveredContainerActivationPhaseV1,
    RecoveredContainerActivationV1, RecoveredContainerInitTaskV1, TaskCoordinateStateV1,
    TaskCoordinateV1, TaskLabelV1,
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

use super::runtime::{
    runtime_identities_from_observations, ContainerRuntimeInventory,
    CriRuntimeContainerObservationV1, RuntimeContainerIdentity,
};

const RUNTIME_STAGE_LIFETIME: Duration = Duration::from_secs(30);
const MAXIMUM_RUNTIME_STAGES: usize = 128;

pub(crate) fn binding_lifecycle_is_addressable(state: BindingLifecycleStateV1) -> bool {
    (BindingLifecycleStateV1::Active as u8..=BindingLifecycleStateV1::ActiveRecovered as u8)
        .contains(&(state as u8))
}

fn binding_lifecycle_allows_effects(state: BindingLifecycleStateV1) -> bool {
    binding_lifecycle_is_addressable(state) && state != BindingLifecycleStateV1::Recovering
}

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

enum InitialRootPreparationV1<'a> {
    Unarmed,
    Held(u32),
    Recovered(&'a RuntimeContainerIdentity),
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
    fn is_policy_preparation_target(&self) -> bool {
        binding_lifecycle_is_addressable(self.state.lifecycle_state)
    }

    fn install_recovery(&mut self, host: &KernelHost) -> Result<()> {
        if let Some(live) = host
            .lookup_map("execution_set_bindings", &self.root_cgroup_id.to_ne_bytes())
            .context(InterceptorSnafu)?
        {
            return self.adopt_retained_state(execution_set_binding_state(&live)?);
        }
        if self.state.lifecycle_state != BindingLifecycleStateV1::Recovering {
            return Ok(());
        }
        let runtime = self.runtime_identity.as_ref().context(IdentityStateSnafu {
            reason: "recovering binding has no authenticated runtime identity",
        })?;
        ensure!(
            runtime.state == super::runtime::RuntimeContainerState::Running
                && runtime.init_pid > 0
                && self.state.transition_guard == 0
                && self.state.prepared_container_entry_instance_id.is_zero()
                && self.state.prepared_container_exec_task_cookie == 0
                && self.state.prepared_container_initial_host_tgid == runtime.init_pid
                && self.state.prepared_container_bootstrap_state == 0,
            IdentityStateSnafu {
                reason: "running container recovery has invalid initial state",
            }
        );
        let raw_pid = i32::try_from(runtime.init_pid).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("container init PID is invalid: {error}"),
            }
            .build()
        })?;
        let pid = Pid::from_raw(raw_pid).context(IdentityStateSnafu {
            reason: "container recovery has a zero init PID",
        })?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{}", runtime.init_pid)),
            })?;
        let recovery_attempt_id = id_from_uuid(Uuid::new_v4());
        let recovering = self.state;
        let recovery = RecoveredContainerActivationV1 {
            node_boot_id: recovering.node_boot_id,
            binding_id: recovering.binding_id,
            binding_nonce: recovering.binding_nonce,
            recovery_attempt_id,
            root_cgroup_live_interval_id: recovering.root_cgroup_live_interval_id,
            application_entry_instance_id: Id128V1::ZERO,
            label_epoch: recovering.label_epoch,
            profile_generation_ref_id: recovering.active_profile_generation_ref_id,
            root_cgroup_id: recovering.root_cgroup_id,
            expected_binding_transition_version: recovering.transition_version,
            scan_generation: 1,
            scan_task_count: 0,
            scan_candidate_count: 0,
            scan_application_task_count: 0,
            scan_external_task_count: 0,
            expected_task_count: 0,
            validation_task_count: 0,
            validation_application_task_count: 0,
            validation_external_task_count: 0,
            transition_version: 1,
            init_host_tgid: runtime.init_pid,
            invalid_task_count: 0,
            phase: RecoveredContainerActivationPhaseV1::Scanning,
            reserved: [0; 7],
        };
        let init_request = RecoveredContainerInitTaskV1 {
            node_boot_id: recovery.node_boot_id,
            binding_id: recovery.binding_id,
            recovery_attempt_id,
            label_epoch: recovery.label_epoch,
            root_cgroup_id: recovery.root_cgroup_id,
            expected_binding_transition_version: recovery.expected_binding_transition_version,
            init_host_tgid: runtime.init_pid,
            reserved: 0,
        };
        let recovery_key = recovering.root_cgroup_id.to_ne_bytes();
        ensure!(
            host.lookup_map("recovered_container_activations", &recovery_key)
                .context(InterceptorSnafu)?
                .is_none(),
            IdentityStateSnafu {
                reason: "container recovery already has a transaction",
            }
        );
        host.update_map(
            "recovered_container_activations",
            &recovery_key,
            recovery.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        host.update_map(
            "recovered_container_init_tasks",
            &pidfd.as_raw_fd().to_ne_bytes(),
            init_request.as_bytes(),
        )
        .context(InterceptorSnafu)?;
        ensure!(
            host.lookup_map("recovered_container_activations", &recovery_key)
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(recovery.as_bytes())
                && host
                    .lookup_map(
                        "recovered_container_init_tasks",
                        &pidfd.as_raw_fd().to_ne_bytes()
                    )
                    .context(InterceptorSnafu)?
                    .as_deref()
                    == Some(init_request.as_bytes()),
            IdentityStateSnafu {
                reason: "container recovery inputs failed exact readback",
            }
        );
        ensure!(
            host.insert_map(
                "execution_set_bindings",
                &recovery_key,
                recovering.as_bytes()
            )
            .context(InterceptorSnafu)?
                == MapInsertResult::Inserted,
            IdentityStateSnafu {
                reason: "container binding appeared during recovery publication",
            }
        );
        let live = host
            .lookup_map("execution_set_bindings", &recovery_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "container recovery binding disappeared after publication",
            })?;
        self.adopt_retained_state(execution_set_binding_state(&live)?)?;
        Ok(())
    }

    fn verify_activated_profile(
        &self,
        spec: &WorkloadBindingConfig,
        activated: &ExecutionSetBindingStateV1,
    ) -> Result<()> {
        let mut desired = self.state;
        desired.lifecycle_state = BindingLifecycleStateV1::Active;
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
        let lifecycle_state = self.state.lifecycle_state;
        self.spec = spec;
        self.state = activated;
        if lifecycle_state == BindingLifecycleStateV1::Recovering {
            self.state.lifecycle_state = lifecycle_state;
        }
    }

    fn prepare_initial_root(&mut self, preparation: InitialRootPreparationV1<'_>) -> Result<()> {
        ensure!(
            self.state.lifecycle_state == BindingLifecycleStateV1::Preparing
                && self.state.transition_guard == 0
                && self.state.prepared_container_entry_instance_id.is_zero()
                && self.state.prepared_container_exec_task_cookie == 0
                && self.state.prepared_container_initial_host_tgid == 0
                && self.state.prepared_container_bootstrap_state == 0,
            IdentityStateSnafu {
                reason: "an initial root can be prepared only once",
            }
        );
        match preparation {
            InitialRootPreparationV1::Unarmed => {
                self.state.lifecycle_state = BindingLifecycleStateV1::Unarmed;
                Ok(())
            }
            InitialRootPreparationV1::Held(initial_pid) => {
                ensure!(
                    initial_pid > 0,
                    IdentityStateSnafu {
                        reason: "held initial-root preparation is not exact",
                    }
                );
                self.held_initial_pid = Some(initial_pid);
                self.state.initial_root_state = InitialRootStateV1::Available;
                self.state.prepared_container_initial_host_tgid = initial_pid;
                self.state.lifecycle_state = BindingLifecycleStateV1::Prepared;
                Ok(())
            }
            InitialRootPreparationV1::Recovered(runtime) => {
                ensure!(
                    runtime.state == super::runtime::RuntimeContainerState::Running
                        && runtime.init_pid > 0
                        && runtime.full_container_id == self.spec.container_id
                        && runtime.cgroup_path == self.root_cgroup_path,
                    IdentityStateSnafu {
                        reason: "recovered initial-root preparation is not exact",
                    }
                );
                self.runtime_identity = Some(runtime.clone());
                self.state.initial_root_state = InitialRootStateV1::Consumed;
                self.state.prepared_container_initial_host_tgid = runtime.init_pid;
                self.state.lifecycle_state = BindingLifecycleStateV1::Recovering;
                self.state.task_set_generation = [1, 0, 0, 0, 0, 0, 0];
                Ok(())
            }
        }
    }

    fn adopt_retained_state(&mut self, live: ExecutionSetBindingStateV1) -> Result<()> {
        ensure!(
            live.lifecycle_state != BindingLifecycleStateV1::Unknown
                && !live.binding_nonce.is_zero()
                && same_runtime_binding(&self.state, &live),
            IdentityStateSnafu {
                reason: "retained binding is unknown or differs from the current runtime identity",
            }
        );
        self.state = live;
        Ok(())
    }

    fn require_initial_root_admission(&self) -> Result<()> {
        if self.state.initial_root_state != InitialRootStateV1::Available {
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

    fn validate_initial_root_preparation(&self) -> Result<()> {
        if self.state.lifecycle_state != BindingLifecycleStateV1::Recovering {
            return self.require_initial_root_admission();
        }
        let runtime = self.runtime_identity.as_ref().context(IdentityStateSnafu {
            reason: "recovered initial-root preparation has no CRI identity",
        })?;
        ensure!(
            self.held_initial_pid.is_none()
                && runtime.state == super::runtime::RuntimeContainerState::Running
                && runtime.init_pid > 0
                && self.state.prepared_container_initial_host_tgid == runtime.init_pid
                && runtime.full_container_id == self.spec.container_id
                && runtime.cgroup_path == self.root_cgroup_path,
            IdentityStateSnafu {
                reason: "recovered initial-root preparation changed before publication",
            }
        );
        self.validate_live_cgroup()
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

    fn runtime_inventory_absence_proves_retirement(&self) -> Result<bool> {
        if !self.live_runtime_cgroup_exists()? {
            return Ok(true);
        }
        Ok(!live_cgroup_population(&self.root_cgroup_path)?.unwrap_or_default())
    }
}

fn live_cgroup_population(path: &Path) -> Result<Option<bool>> {
    let events_path = path.join("cgroup.events");
    let events = match fs::read_to_string(&events_path) {
        Ok(events) => events,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return match fs::metadata(path) {
                Ok(_) => Err(source).context(IoSnafu { path: events_path }),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(source) => Err(source).context(IoSnafu {
                    path: path.to_path_buf(),
                }),
            };
        }
        Err(source) => return Err(source).context(IoSnafu { path: events_path }),
    };
    let populated = events
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(name, _value)| *name == "populated")
        .map(|(_name, value)| value)
        .collect::<Vec<_>>();
    ensure!(
        populated.len() == 1 && matches!(populated[0], "0" | "1"),
        IdentityStateSnafu {
            reason: format!(
                "live cgroup `{}` has invalid population state",
                path.display()
            ),
        }
    );
    Ok(Some(populated[0] == "1"))
}

pub struct WorkloadBindingOwner {
    cgroup_root: PathBuf,
    node_boot_id: Id128V1,
    label_epoch: u64,
    bindings: BTreeMap<u64, PublishedBinding>,
    profile_handles: BTreeMap<u64, Id128V1>,
    runtime: Option<ContainerRuntimeInventory>,
    // Keep one verified CRI identity between inspection and held-root publication.
    staged_runtime_admissions: BTreeMap<String, StagedRuntimeAdmissionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactObjectBindingTargetV1<'a> {
    pub binding_id: &'a str,
    pub init_pid: u32,
    pub process_path_view_allowed: bool,
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
    oci_bundle: Option<PathBuf>,
    declared_entries_staged: bool,
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
pub struct RuntimeReconciliationResultV1 {
    pub retired_binding_ids: Vec<String>,
    pub recovered_bindings: Vec<WorkloadBindingConfig>,
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
                .map(|binding| (binding, InitialRootPreparationV1::Unarmed)),
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
                binding_lifecycle_allows_effects(binding.state.lifecycle_state)
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
        self.publish(
            host,
            configured
                .iter()
                .map(|spec| (spec, InitialRootPreparationV1::Unarmed)),
        )
    }

    pub fn publish_held_initial_roots(
        &mut self,
        host: &KernelHost,
        configured: &[(WorkloadBindingConfig, u32)],
    ) -> Result<()> {
        self.publish(
            host,
            configured
                .iter()
                .map(|(spec, pid)| (spec, InitialRootPreparationV1::Held(*pid))),
        )
    }

    pub(crate) fn read_back_recovered_activations(&mut self, host: &KernelHost) -> Result<()> {
        for (&root_cgroup_id, binding) in &mut self.bindings {
            if binding.state.lifecycle_state != BindingLifecycleStateV1::Recovering {
                continue;
            }
            let key = root_cgroup_id.to_ne_bytes();
            let live = host
                .lookup_map("execution_set_bindings", &key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "recovered binding disappeared before readback",
                })?;
            let live = execution_set_binding_state(&live)?;
            binding.adopt_retained_state(live)?;
            if live.lifecycle_state != BindingLifecycleStateV1::ActiveRecovered {
                continue;
            }
            let recovery = host
                .lookup_map("recovered_container_activations", &key)
                .context(InterceptorSnafu)?
                .context(IdentityStateSnafu {
                    reason: "recovered binding has no BPF recovery result",
                })?;
            let recovery = RecoveredContainerActivationV1::try_read_from_bytes(&recovery).map_err(
                |error| {
                    IdentityStateSnafu {
                        reason: format!("BPF recovery result has an invalid ABI: {error}"),
                    }
                    .build()
                },
            )?;
            ensure!(
                completed_recovery_matches_binding(&recovery, &live),
                IdentityStateSnafu {
                    reason: "BPF recovery result does not match its active binding",
                }
            );
            binding.state = live;
        }
        Ok(())
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

    #[cfg(feature = "test-support")]
    pub fn retire_binding_id_for_test(
        &mut self,
        host: &KernelHost,
        binding_id: &str,
    ) -> Result<()> {
        self.retire_binding_id(host, binding_id)
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
            if binding.lifecycle_state == BindingLifecycleStateV1::Preparing
                || binding_lifecycle_is_addressable(binding.lifecycle_state)
                || binding.lifecycle_state == BindingLifecycleStateV1::Draining
            {
                binding.lifecycle_state = BindingLifecycleStateV1::Terminating;
                binding.initial_root_state = InitialRootStateV1::Consumed;
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

    /// Verifies CRI Created coordinates and publishes the held binding under the active policy.
    pub fn publish_held_activated_root(
        &mut self,
        host: &KernelHost,
        spec: &WorkloadBindingConfig,
        initial_pid: u32,
        observation: &CriRuntimeContainerObservationV1,
    ) -> Result<()> {
        let runtime = observation.created_identity(spec, &self.cgroup_root)?;
        ensure!(
            runtime.generation == spec.container_generation,
            IdentityStateSnafu {
                reason: "verified CRI generation changed before binding publication",
            }
        );
        self.publish_held_initial_roots(host, &[(spec.clone(), initial_pid)])?;
        let root = self
            .bindings
            .iter()
            .find(|(_root, binding)| binding.spec.binding_id == spec.binding_id)
            .map(|(root, _binding)| *root)
            .context(IdentityStateSnafu {
                reason: "held runtime binding disappeared after publication",
            })?;
        let binding = self.bindings.get_mut(&root).context(IdentityStateSnafu {
            reason: "published runtime binding disappeared before CRI adoption",
        })?;
        binding.runtime_identity = Some(runtime);
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
                && live.lifecycle_state == BindingLifecycleStateV1::Prepared
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
            oci_bundle: None,
            declared_entries_staged: false,
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
    ) -> Result<(ScheduledRuntimeBindingV1, CriRuntimeContainerObservationV1)> {
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
        let (identity, observation) = runtime
            .inspect_created_for_admission(&scheduled.resolved)
            .await?;
        scheduled.resolved.container_generation = identity.generation;
        Ok((scheduled, observation))
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
                && binding.state.lifecycle_state == BindingLifecycleStateV1::Prepared,
            IdentityStateSnafu {
                reason: "declared-entry preparation has no prepared initial task",
            }
        );
        Ok((spec.binding_id.clone(), held_initial_pid))
    }

    pub(crate) fn mark_runtime_entries_staged(
        &mut self,
        container_id: &str,
        oci_bundle: &Path,
    ) -> Result<()> {
        let staged = self
            .staged_runtime_admissions
            .get_mut(container_id)
            .context(IdentityStateSnafu {
                reason: "declared-entry staging lost its immutable runtime stage",
            })?;
        ensure!(
            staged.deadline > Instant::now() && oci_bundle.is_absolute(),
            IdentityStateSnafu {
                reason: "declared-entry staging exceeded its runtime-stage lifetime",
            }
        );
        staged.oci_bundle = Some(oci_bundle.to_owned());
        staged.declared_entries_staged = true;
        Ok(())
    }

    pub(crate) fn verify_runtime_entry_staging(
        &self,
        host: &KernelHost,
        binding_id: &str,
    ) -> Result<()> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "declared-entry staging has no published runtime binding",
            })?;
        let mut entries = 0_usize;
        let mut admitted_rules = BTreeSet::new();
        binding.held_initial_pid.context(IdentityStateSnafu {
            reason: "declared-entry staging has no held initial task",
        })?;
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
                    reason: "staged declared entry disappeared during readback",
                })?;
            let value = EntryAdmissionRuleV1::try_read_from_bytes(&value).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("staged declared entry has the wrong ABI: {error}"),
                }
                .build()
            })?;
            ensure!(
                matches!(
                    key.source_role_id,
                    source if source == binding.state.initial_role_id
                        || source == binding.state.external_role_id
                ) && value.target_role_id != 0
                    && value.target_process_state_vector_id != 0
                    && value.admitted_entry_rule_id != 0
                    && value.reserved == 0
                    && value.exact_object_key_id == 0
                    && value.executable_object == ExactFileObjectKeyV1::default()
                    && admitted_rules.insert(value.admitted_entry_rule_id),
                IdentityStateSnafu {
                    reason: "declared-entry staging has invalid or colliding signed authority",
                }
            );
            entries += 1;
        }
        ensure!(
            entries > 0,
            IdentityStateSnafu {
                reason: "declared-entry staging has no signed entry authority",
            }
        );
        Ok(())
    }

    pub(crate) async fn verify_runtime_exec_notification(
        &mut self,
        configured: &[WorkloadBindingConfig],
        process: &crate::runtime_seccomp::OciContainerProcessStateV1,
        notification_pid: u32,
        initial_exec: bool,
    ) -> Result<String> {
        let request = RuntimeAdmissionRequestV1 {
            operation: RuntimeAdmissionOperationV1::PrepareContainer,
            container_id: process.container_id().to_owned(),
            initial_pid: Some(notification_pid),
            cgroup_path: None,
            oci_bundle: None,
            oci_root_fd: None,
            annotations: process.annotations().clone(),
        };
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
                reason: "runtime exec notification does not resolve to one exact binding",
            }
        );
        let spec = matches[0];
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == spec.binding_id)
            .context(IdentityStateSnafu {
                reason: "runtime exec notification has no published binding",
            })?;
        binding.validate_live_cgroup()?;
        self.verify_notification_pid_cgroup(binding, notification_pid)?;
        if initial_exec {
            ensure!(
                binding.held_initial_pid == Some(notification_pid)
                    && binding.state.lifecycle_state == BindingLifecycleStateV1::Prepared
                    && self
                        .staged_runtime_admissions
                        .get(process.container_id())
                        .is_some_and(|staged| {
                            staged.deadline > Instant::now()
                                && staged.declared_entries_staged
                                && staged.oci_bundle.as_deref() == Some(process.bundle())
                        }),
                IdentityStateSnafu {
                    reason: "initial exec notification has no staged prepared binding",
                }
            );
        }
        let expected_runtime = binding
            .runtime_identity
            .clone()
            .context(IdentityStateSnafu {
                reason: "runtime exec notification has no verified CRI identity",
            })?;
        let runtime = self.runtime.as_mut().context(IdentityStateSnafu {
            reason: "runtime exec notification has no CRI inventory owner",
        })?;
        let observed = runtime.snapshot(std::slice::from_ref(spec)).await?;
        ensure!(
            observed.len() == 1 && expected_runtime.accepts_observed_lifetime(&observed[0]),
            IdentityStateSnafu {
                reason: "CRI identity changed before the runtime exec",
            }
        );
        Ok(spec.binding_id.clone())
    }

    fn verify_notification_pid_cgroup(
        &self,
        binding: &PublishedBinding,
        notification_pid: u32,
    ) -> Result<()> {
        let proc_path = PathBuf::from(format!("/proc/{notification_pid}/cgroup"));
        let cgroups = fs::read_to_string(&proc_path).context(IoSnafu { path: &proc_path })?;
        let relative = cgroups
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .and_then(|path| path.strip_prefix('/'))
            .context(IdentityStateSnafu {
                reason: "runtime exec notification PID has no absolute unified cgroup",
            })?;
        ensure!(
            !relative.is_empty()
                && Path::new(relative)
                    .components()
                    .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
            IdentityStateSnafu {
                reason: "runtime exec notification PID has a non-canonical cgroup",
            }
        );
        let cgroup_path = fs::canonicalize(self.cgroup_root.join(relative)).context(IoSnafu {
            path: self.cgroup_root.join(relative),
        })?;
        let metadata = fs::metadata(&cgroup_path).context(IoSnafu { path: &cgroup_path })?;
        binding.validate_live_cgroup_metadata(&metadata)
    }

    pub(crate) fn revoke_runtime_entry_admissions(
        &self,
        host: &KernelHost,
        binding_id: &str,
    ) -> Result<()> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "runtime entry revocation has no published binding",
            })?;
        Self::remove_runtime_entry_admissions(host, binding)
    }

    pub(crate) fn verify_runtime_entry_admissions(
        &self,
        host: &KernelHost,
        binding_id: &str,
        _initial_pid: u32,
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
                value.exact_object_key_id == 0
                    && value.executable_object == ExactFileObjectKeyV1::default()
                    && admitted_rules.insert(value.admitted_entry_rule_id),
                IdentityStateSnafu {
                    reason: "declared-entry table has inode authority or a colliding rule",
                }
            );
            count += 1;
        }
        ensure!(
            count > 0,
            IdentityStateSnafu {
                reason: "declared-entry table has no signed path-and-argument authority",
            }
        );
        Ok(())
    }

    pub(crate) fn verify_runtime_initial_entry_admission(
        &self,
        host: &KernelHost,
        binding_id: &str,
        executable_path: &Path,
    ) -> Result<()> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "initial entry readback has no published runtime binding",
            })?;
        let request = DeclaredEntryRequestV1::from_path(executable_path.as_os_str().as_bytes())
            .context(IdentityStateSnafu {
                reason: "initial executable request exceeds its kernel ABI bound",
            })?;
        let declared = host
            .lookup_map("declared_entry_requests", request.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "initial executable request is not declared by signed policy",
            })?;
        ensure!(
            declared_entry_request_is_present(&declared),
            IdentityStateSnafu {
                reason: "declared entry request has an invalid membership value",
            }
        );
        let mut matches = 0_usize;
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
            if key.profile_generation_ref_id == binding.state.active_profile_generation_ref_id
                && key.binding_id == binding.state.binding_id
                && key.source_role_id == binding.state.initial_role_id
            {
                matches += 1;
            }
        }
        ensure!(
            matches == 1,
            IdentityStateSnafu {
                reason: "initial executable request does not match one application entry",
            }
        );
        Ok(())
    }

    pub(crate) fn discard_runtime_stage(&mut self, container_id: &str) {
        self.staged_runtime_admissions.remove(container_id);
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
        binding.validate_initial_root_preparation()?;
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
        let mut desired = binding.state;
        desired.lifecycle_state = BindingLifecycleStateV1::Active;
        let previous = host
            .lookup_map("binding_activation_targets", key.as_bytes())
            .context(InterceptorSnafu)?;
        let previous_target = previous
            .as_deref()
            .map(execution_set_binding_state)
            .transpose()?;
        ensure!(
            previous_target
                .as_ref()
                .is_none_or(|target| { Self::activation_target_matches_desired(&desired, target) }),
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
                    desired.as_bytes(),
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
            Self::activation_target_matches_desired(&desired, &observed),
            IdentityStateSnafu {
                reason: "held runtime binding activation target failed readback",
            }
        );
        self.profile_handles
            .insert(active, binding.state.profile_id);
        Ok(())
    }

    fn publish<'a>(
        &mut self,
        host: &KernelHost,
        configured: impl IntoIterator<Item = (&'a WorkloadBindingConfig, InitialRootPreparationV1<'a>)>,
    ) -> Result<()> {
        for (spec, initial_root) in configured {
            let mut binding = self.prepare(spec)?;
            let recovering = matches!(initial_root, InitialRootPreparationV1::Recovered(_));
            if let InitialRootPreparationV1::Recovered(runtime) = &initial_root {
                binding.runtime_identity = Some((*runtime).clone());
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
            if let Some(existing) = existing.as_deref() {
                binding.adopt_retained_state(execution_set_binding_state(existing)?)?;
                ensure!(
                    self.profile_handles
                        .get(&binding.state.active_profile_generation_ref_id)
                        .is_none_or(|profile_id| *profile_id == binding.state.profile_id),
                    IdentityStateSnafu {
                        reason: "retained profile-generation handle belongs to another profile",
                    }
                );
                self.profile_handles.insert(
                    binding.state.active_profile_generation_ref_id,
                    binding.state.profile_id,
                );
                self.bindings.insert(binding.root_cgroup_id, binding);
                continue;
            }
            binding.prepare_initial_root(initial_root)?;
            let desired_lifecycle = binding.state.lifecycle_state;
            if recovering {
                self.bindings.insert(binding.root_cgroup_id, binding);
                continue;
            }
            binding.require_initial_root_admission()?;
            binding.state.lifecycle_state = BindingLifecycleStateV1::Preparing;
            host.update_map("execution_set_bindings", &key, binding.state.as_bytes())
                .context(InterceptorSnafu)?;
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
            {
                ensure!(
                    host.lookup_map("execution_set_bindings", &key)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.state.as_bytes()),
                    IdentityStateSnafu {
                        reason: format!("binding `{}` failed preparing readback", spec.binding_id),
                    }
                );
                if binding.held_initial_pid.is_none() && !recovering {
                    reserve_live_root_task_labels(host, &binding)?;
                } else {
                    binding.require_initial_root_admission()?;
                }
                binding.state.lifecycle_state = desired_lifecycle;
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
        let staged_recoveries = self
            .bindings
            .iter()
            .filter(|(_root, binding)| {
                binding.state.lifecycle_state == BindingLifecycleStateV1::Recovering
            })
            .map(|(root, binding)| (*root, binding.spec.clone()))
            .collect::<Vec<_>>();
        for (root, spec) in staged_recoveries {
            self.install_late_activation_target(host, root, &spec)?;
        }
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
            let live = host
                .lookup_map("execution_set_bindings", &root_cgroup_id.to_ne_bytes())
                .context(InterceptorSnafu)?;
            let live = match live.as_deref() {
                Some(live) => execution_set_binding_state(live)?,
                None if binding.state.lifecycle_state == BindingLifecycleStateV1::Recovering => {
                    binding.state
                }
                None => {
                    return IdentityStateSnafu {
                        reason: "activated binding disappeared before adoption".to_owned(),
                    }
                    .fail()
                }
            };
            ensure!(
                Self::same_activation_identity(&live, &activated),
                IdentityStateSnafu {
                    reason: "live binding differs from its activated policy target",
                }
            );
            let mut adopted_live = live;
            adopted_live.active_profile_generation_ref_id =
                activated.active_profile_generation_ref_id;
            adopted_live.initial_role_id = activated.initial_role_id;
            adopted_live.external_role_id = activated.external_role_id;
            if adopted_live != live
                && host
                    .lookup_map("execution_set_bindings", &root_cgroup_id.to_ne_bytes())
                    .context(InterceptorSnafu)?
                    .is_some()
            {
                adopted_live.transition_version =
                    live.transition_version
                        .checked_add(1)
                        .context(IdentityStateSnafu {
                            reason: "activated binding transition overflowed",
                        })?;
                host.update_map(
                    "execution_set_bindings",
                    &root_cgroup_id.to_ne_bytes(),
                    adopted_live.as_bytes(),
                )
                .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("execution_set_bindings", &root_cgroup_id.to_ne_bytes(),)
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(adopted_live.as_bytes()),
                    IdentityStateSnafu {
                        reason: "activated binding policy facts failed exact readback",
                    }
                );
            }
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
            adopted.push((root_cgroup_id, spec.clone(), adopted_live));
        }
        for (root_cgroup_id, spec, activated) in adopted {
            let binding = self
                .bindings
                .get_mut(&root_cgroup_id)
                .context(IdentityStateSnafu {
                    reason: "verified activated binding disappeared before adoption",
                })?;
            binding.adopt_activated_profile(spec, activated);
            binding.install_recovery(host)?;
        }
        self.profile_handles = profile_handles;
        Ok(())
    }

    pub(crate) fn exact_object_binding_targets(
        &self,
    ) -> impl Iterator<Item = ExactObjectBindingTargetV1<'_>> {
        self.bindings
            .values()
            .filter(|binding| binding.is_policy_preparation_target())
            .filter(|binding| binding.state.lifecycle_state != BindingLifecycleStateV1::Recovering)
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
                    process_path_view_allowed: binding.state.lifecycle_state
                        != BindingLifecycleStateV1::Prepared,
                })
            })
    }

    pub(crate) fn active_binding_ids(&self) -> impl Iterator<Item = &str> {
        self.bindings
            .values()
            .filter(|binding| binding.is_policy_preparation_target())
            .map(|binding| binding.spec.binding_id.as_str())
    }

    pub(crate) fn held_binding_ids(&self) -> impl Iterator<Item = &str> {
        self.bindings
            .values()
            .filter(|binding| binding.state.lifecycle_state == BindingLifecycleStateV1::Prepared)
            .map(|binding| binding.spec.binding_id.as_str())
    }

    pub(crate) fn has_recovering_binding(&self) -> bool {
        self.bindings.values().any(|binding| {
            binding.state.lifecycle_state == BindingLifecycleStateV1::Recovering
                && binding.state.prepared_container_entry_instance_id.is_zero()
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
        self.reconcile_runtime_identities(host, configured, observed)
    }

    pub fn reconcile_runtime_observations(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
        observations: Vec<CriRuntimeContainerObservationV1>,
    ) -> Result<RuntimeReconciliationResultV1> {
        let observed =
            runtime_identities_from_observations(observations, configured, &self.cgroup_root)?;
        self.reconcile_runtime_identities(host, configured, observed)
    }

    fn reconcile_runtime_identities(
        &mut self,
        host: &KernelHost,
        configured: &[WorkloadBindingConfig],
        observed: Vec<RuntimeContainerIdentity>,
    ) -> Result<RuntimeReconciliationResultV1> {
        let observed: BTreeMap<String, RuntimeContainerIdentity> = observed
            .into_iter()
            .map(|identity| (identity.full_container_id.clone(), identity))
            .collect();
        let recovered_bindings = observed
            .values()
            .filter_map(|identity| {
                configured
                    .iter()
                    .find(|binding| identity.matches_scheduled(binding))
                    .map(|binding| identity.resolve(binding))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut retired_binding_ids = self.retired_configured_binding_ids(configured, &observed)?;
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
                .find(|binding| {
                    binding.container_id == identity.full_container_id
                        || identity.matches_scheduled(binding)
                })
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
            let resolved = identity.resolve(configured)?;
            self.publish(
                host,
                [(&resolved, InitialRootPreparationV1::Recovered(&identity))],
            )?;
        }
        self.retain_only_configured(host)?;
        Ok(RuntimeReconciliationResultV1 {
            retired_binding_ids: retired_binding_ids.into_iter().collect(),
            recovered_bindings,
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
                if let Some(current) = observed.remove(&binding.spec.container_id) {
                    ensure!(
                        current.cgroup_path == binding.root_cgroup_path,
                        IdentityStateSnafu {
                            reason: format!(
                                "CRI cgroup differs from restored binding `{}`",
                                binding.spec.container_id
                            ),
                        }
                    );
                    plan.updates.push(RuntimeBindingUpdate {
                        root_id,
                        identity: current,
                    });
                }
                continue;
            };
            let Some(current) = observed.remove(&binding.spec.container_id) else {
                if binding.runtime_inventory_absence_proves_retirement()? {
                    plan.retire_binding(root_id, binding);
                }
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

    #[cfg(feature = "test-support")]
    pub fn runtime_inventory_absence_proves_retirement_for_test(
        &self,
        binding_id: &str,
    ) -> Result<bool> {
        let binding = self
            .bindings
            .values()
            .find(|binding| binding.spec.binding_id == binding_id)
            .context(IdentityStateSnafu {
                reason: "runtime absence probe has no matching binding",
            })?;
        binding.runtime_inventory_absence_proves_retirement()
    }

    fn retired_configured_binding_ids(
        &self,
        configured: &[WorkloadBindingConfig],
        observed: &BTreeMap<String, RuntimeContainerIdentity>,
    ) -> Result<BTreeSet<String>> {
        let mut retired = BTreeSet::new();
        for binding in configured.iter().filter(|binding| {
            binding.scheduled_binding_authority_id.is_some()
                && binding.root_cgroup_path.is_some()
                && !observed.contains_key(&binding.container_id)
        }) {
            let absence_proven = if let Some(published) = self
                .bindings
                .values()
                .find(|published| published.spec.binding_id == binding.binding_id)
            {
                published.runtime_inventory_absence_proves_retirement()?
            } else {
                !live_cgroup_population(binding.root_cgroup_path.as_deref().context(
                    IdentityStateSnafu {
                        reason: "resolved runtime binding lost its cgroup path",
                    },
                )?)?
                .unwrap_or_default()
            };
            if absence_proven {
                retired.insert(binding.binding_id.clone());
            }
        }
        Ok(retired)
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
                lifecycle_state: BindingLifecycleStateV1::Preparing,
                task_set_generation: [0; 7],
                initial_root_state: InitialRootStateV1::Unarmed,
                transition_guard: 0,
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
        if !binding_lifecycle_is_addressable(binding.state.lifecycle_state) {
            return Ok(());
        }
        binding.state.lifecycle_state = BindingLifecycleStateV1::Terminating;
        binding.state.initial_root_state = InitialRootStateV1::Consumed;
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
                value.lifecycle_state == BindingLifecycleStateV1::Preparing
                    || binding_lifecycle_is_addressable(value.lifecycle_state)
                    || value.lifecycle_state == BindingLifecycleStateV1::Draining,
                IdentityStateSnafu {
                    reason: "stale execution-set binding has an invalid lifecycle state",
                }
            );
            value.lifecycle_state = BindingLifecycleStateV1::Terminating;
            value.initial_root_state = InitialRootStateV1::Consumed;
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
        live.transition_guard = target.transition_guard;
        live.initial_role_id = target.initial_role_id;
        live.external_role_id = target.external_role_id;
        live.lifecycle_state = target.lifecycle_state;
        live.task_set_generation = target.task_set_generation;
        live.initial_root_state = target.initial_root_state;
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

fn declared_entry_request_is_present(bytes: &[u8]) -> bool {
    bytes == [1]
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
    desired.transition_guard = recovered.transition_guard;
    desired.initial_role_id = recovered.initial_role_id;
    desired.external_role_id = recovered.external_role_id;
    desired.lifecycle_state = recovered.lifecycle_state;
    desired.task_set_generation = recovered.task_set_generation;
    desired.initial_root_state = recovered.initial_root_state;
    desired.prepared_container_entry_instance_id = recovered.prepared_container_entry_instance_id;
    desired.prepared_container_exec_task_cookie = recovered.prepared_container_exec_task_cookie;
    desired.prepared_container_initial_host_tgid = recovered.prepared_container_initial_host_tgid;
    desired.prepared_container_bootstrap_state = recovered.prepared_container_bootstrap_state;
    desired == *recovered
}

fn completed_recovery_matches_binding(
    recovery: &RecoveredContainerActivationV1,
    binding: &ExecutionSetBindingStateV1,
) -> bool {
    recovery.phase == RecoveredContainerActivationPhaseV1::Complete
        && binding.transition_guard == 0
        && recovery.node_boot_id == binding.node_boot_id
        && recovery.label_epoch == binding.label_epoch
        && recovery.binding_id == binding.binding_id
        && recovery.binding_nonce == binding.binding_nonce
        && recovery.root_cgroup_id == binding.root_cgroup_id
        && recovery.root_cgroup_live_interval_id == binding.root_cgroup_live_interval_id
        && recovery.profile_generation_ref_id == binding.active_profile_generation_ref_id
        && recovery.expected_binding_transition_version == binding.transition_version
        && recovery.init_host_tgid == binding.prepared_container_initial_host_tgid
        && recovery.application_entry_instance_id == binding.prepared_container_entry_instance_id
        && !recovery.recovery_attempt_id.is_zero()
        && !recovery.application_entry_instance_id.is_zero()
        && recovery.scan_generation > 0
        && recovery.expected_task_count > 0
        && recovery.validation_task_count == recovery.expected_task_count
        && recovery.validation_application_task_count > 0
        && recovery.validation_task_count
            == recovery.validation_application_task_count + recovery.validation_external_task_count
        && binding.lifecycle_state == BindingLifecycleStateV1::ActiveRecovered
        && binding.prepared_container_exec_task_cookie == 0
        && binding.prepared_container_bootstrap_state == 0
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use snafu::{OptionExt as _, ResultExt as _};
    use zerocopy::TryFromBytes as _;

    use super::{
        completed_recovery_matches_binding, declared_entry_request_is_present,
        same_runtime_binding, InitialRootPreparationV1, RuntimeContainerIdentity,
        StagedRuntimeAdmissionV1, WorkloadBindingOwner,
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
    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, Id128V1, InitialRootStateV1, RecoveredContainerActivationPhaseV1,
        RecoveredContainerActivationV1,
    };

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

    #[test]
    fn fresh_declared_entry_map_uses_one_byte_membership() {
        assert!(declared_entry_request_is_present(&[1]));
        assert!(!declared_entry_request_is_present(&[0]));
        assert!(!declared_entry_request_is_present(&1_u64.to_ne_bytes()));
    }

    fn authorization_request(_cgroup_path: &Path) -> RuntimeAdmissionRequestV1 {
        RuntimeAdmissionRequestV1 {
            operation: RuntimeAdmissionOperationV1::PrepareContainer,
            container_id: "a".repeat(64),
            initial_pid: Some(42),
            cgroup_path: None,
            oci_bundle: None,
            oci_root_fd: None,
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
            oci_bundle: None,
            declared_entries_staged: false,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let now = Instant::now();
        stage.verify_preparation("authority-head-a", &request, now)?;
        let mut entries = request.clone();
        entries.operation = RuntimeAdmissionOperationV1::PrepareDeclaredEntries;
        entries.initial_pid = None;
        entries.oci_bundle = Some(PathBuf::from("/run/oci/container-a"));
        entries.oci_root_fd = Some(3);
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
    fn display_flag_does_not_arm_a_configured_cgroup() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let binding = owner.prepare(&spec(&root))?;
        let mut display_only = spec(&root);
        display_only.arm_initial_root = false;
        let second = owner.prepare(&display_only)?;
        assert_eq!(
            binding.state.initial_root_state,
            InitialRootStateV1::Unarmed
        );
        assert_eq!(binding.state.root_cgroup_id, binding.root_cgroup_id);
        assert_ne!(binding.state.binding_nonce, second.state.binding_nonce);
        assert!(same_runtime_binding(&binding.state, &second.state));
        Ok(())
    }

    #[test]
    fn occupied_cgroup_cannot_claim_another_held_root() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary cgroup root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "42\n").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        binding.prepare_initial_root(InitialRootPreparationV1::Held(43))?;
        assert!(binding.require_initial_root_admission().is_err());
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
        binding.prepare_initial_root(InitialRootPreparationV1::Held(42))?;
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
        let mut owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?;
        assert_eq!(
            binding.state.lifecycle_state,
            BindingLifecycleStateV1::Preparing
        );
        assert_eq!(binding.state.prepared_container_initial_host_tgid, 0);

        binding.prepare_initial_root(InitialRootPreparationV1::Held(42))?;
        assert_eq!(
            binding.state.lifecycle_state,
            BindingLifecycleStateV1::Prepared
        );
        assert_eq!(binding.state.prepared_container_initial_host_tgid, 42);
        assert!(binding
            .prepare_initial_root(InitialRootPreparationV1::Held(42))
            .is_err());
        let root_id = binding.root_cgroup_id;
        owner.bindings.insert(root_id, binding);
        let targets = owner.exact_object_binding_targets().collect::<Vec<_>>();
        assert_eq!(targets.len(), 1);
        assert!(!targets[0].process_path_view_allowed);
        Ok(())
    }

    #[test]
    fn retained_bpf_state_is_preserved_except_unknown() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary retained binding root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        for value in 0..=u8::MAX {
            let Ok(state) = BindingLifecycleStateV1::try_read_from_bytes(&[value]) else {
                continue;
            };
            let mut binding = owner.prepare(&spec(&root))?;
            let mut retained = binding.state;
            retained.lifecycle_state = state;
            retained.transition_guard = 1;
            retained.prepared_container_exec_task_cookie = 42;
            retained.prepared_container_initial_host_tgid = 42;
            retained.prepared_container_entry_instance_id = Id128V1::new(9, 10);
            if state == BindingLifecycleStateV1::Unknown {
                assert!(binding.adopt_retained_state(retained).is_err());
                continue;
            }
            binding.adopt_retained_state(retained)?;
            assert_eq!(binding.state, retained);
            let mut wrong_boot = retained;
            wrong_boot.node_boot_id = Id128V1::new(3, 4);
            assert!(binding.adopt_retained_state(wrong_boot).is_err());
            let mut wrong_lifetime = retained;
            wrong_lifetime.container_generation += 1;
            assert!(binding.adopt_retained_state(wrong_lifetime).is_err());
            assert_eq!(binding.state, retained);
        }
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
        recovered.task_set_generation = [17, 0, 0, 0, 0, 0, 0];

        assert!(same_runtime_binding(&desired, &recovered));
        let mut changed = desired;
        changed.task_set_generation = recovered.task_set_generation;
        assert!(WorkloadBindingOwner::same_activation_identity(
            &desired, &changed
        ));
        recovered.root_cgroup_live_interval_id = Id128V1::new(11, 12);
        assert!(!same_runtime_binding(&desired, &recovered));
        recovered.root_cgroup_live_interval_id = desired.root_cgroup_live_interval_id;
        recovered.execution_set_id = Id128V1::new(11, 12);
        assert!(!same_runtime_binding(&desired, &recovered));
        Ok(())
    }

    #[test]
    fn completed_recovery_readback_requires_the_bpf_committed_anchor() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            path: "temporary recovered binding root",
        })?;
        let root = temporary.path().join("workload");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        fs::write(root.join("cgroup.procs"), "").context(IoSnafu { path: &root })?;
        let owner = WorkloadBindingOwner::at(temporary.path(), Id128V1::new(1, 2), 3)?;
        let mut binding = owner.prepare(&spec(&root))?.state;
        binding.initial_root_state = InitialRootStateV1::Consumed;
        binding.lifecycle_state = BindingLifecycleStateV1::ActiveRecovered;
        binding.prepared_container_entry_instance_id = Id128V1::new(9, 10);
        binding.prepared_container_initial_host_tgid = 42;
        binding.transition_version = 8;
        let mut recovery = RecoveredContainerActivationV1 {
            node_boot_id: binding.node_boot_id,
            binding_id: binding.binding_id,
            binding_nonce: binding.binding_nonce,
            recovery_attempt_id: Id128V1::new(11, 12),
            root_cgroup_live_interval_id: binding.root_cgroup_live_interval_id,
            application_entry_instance_id: binding.prepared_container_entry_instance_id,
            label_epoch: binding.label_epoch,
            profile_generation_ref_id: binding.active_profile_generation_ref_id,
            root_cgroup_id: binding.root_cgroup_id,
            expected_binding_transition_version: binding.transition_version,
            scan_generation: 4,
            scan_task_count: 2,
            scan_candidate_count: 2,
            scan_application_task_count: 1,
            scan_external_task_count: 1,
            expected_task_count: 2,
            validation_task_count: 2,
            validation_application_task_count: 1,
            validation_external_task_count: 1,
            transition_version: 5,
            init_host_tgid: binding.prepared_container_initial_host_tgid,
            invalid_task_count: 0,
            phase: RecoveredContainerActivationPhaseV1::Complete,
            reserved: [0; 7],
        };

        assert!(completed_recovery_matches_binding(&recovery, &binding));
        recovery.application_entry_instance_id = Id128V1::new(13, 14);
        assert!(!completed_recovery_matches_binding(&recovery, &binding));
        recovery.application_entry_instance_id = binding.prepared_container_entry_instance_id;
        binding.lifecycle_state = BindingLifecycleStateV1::Recovering;
        assert!(!completed_recovery_matches_binding(&recovery, &binding));
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
        target.lifecycle_state = BindingLifecycleStateV1::Active;
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
        activated.lifecycle_state = BindingLifecycleStateV1::Active;
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
        fs::write(root.join("cgroup.events"), "populated 1\nfrozen 0\n")
            .context(IoSnafu { path: &root })?;
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
        let mut binding = owner.prepare(&identity.resolve(&configured)?)?;
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
        binding.prepare_initial_root(InitialRootPreparationV1::Held(std::process::id()))?;
        fs::write(
            root.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .context(IoSnafu { path: &root })?;
        binding.validate_initial_root_preparation()?;
        assert_eq!(
            binding.state.lifecycle_state,
            BindingLifecycleStateV1::Prepared
        );
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
                reason: "the runtime lifetime test lost its binding",
            })?
            .runtime_identity = None;
        let restored = owner.plan_runtime_reconciliation(BTreeMap::from([(
            running.full_container_id.clone(),
            running.clone(),
        )]))?;
        assert!(restored.missing_root_ids.is_empty());
        assert!(restored.new_identities.is_empty());
        assert_eq!(restored.updates.len(), 1);
        let mut wrong_cgroup = running.clone();
        wrong_cgroup.cgroup_path = temporary.path().join("another-workload");
        assert!(owner
            .plan_runtime_reconciliation(BTreeMap::from([(
                wrong_cgroup.full_container_id.clone(),
                wrong_cgroup,
            )]))
            .is_err());
        owner
            .bindings
            .get_mut(&root_id)
            .context(IdentityStateSnafu {
                reason: "test binding disappeared before its running transition",
            })?
            .runtime_identity = Some(running.clone());
        assert_eq!(owner.exact_object_binding_targets().count(), 1);

        let plan = owner.plan_runtime_reconciliation(BTreeMap::new())?;
        assert!(plan.missing_root_ids.is_empty());
        assert!(plan.retired_binding_ids.is_empty());
        assert!(owner
            .retired_configured_binding_ids(&[configured.clone()], &BTreeMap::new())?
            .is_empty());

        fs::remove_file(root.join("cgroup.procs")).context(IoSnafu { path: &root })?;
        fs::remove_file(root.join("cgroup.events")).context(IoSnafu { path: &root })?;
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
            owner.retired_configured_binding_ids(&[configured.clone()], &BTreeMap::new(),)?,
            BTreeSet::from([configured.binding_id])
        );
        Ok(())
    }
}
