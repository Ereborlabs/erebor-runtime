use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{
    CreatedByEdgeV1, EntrySecurityStateV1, ExecutionSetBindingStateV1, ExternalRootClassV1,
    ExternalRootClassificationV1, Id128V1, ImageProvenanceV1, InstalledRoleClassV1,
    KernelRealParentIntervalKeyV1, KernelRealParentIntervalV1, PreparedContainerStateV1,
    ProcessExecutionInstanceV1, ProcessSecurityStateV1, ProcessStateVectorV1, TaskCoordinateV1,
    TaskLabelV1,
};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, ResultExt as _};
use zerocopy::{IntoBytes as _, KnownLayout, TryFromBytes};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeTaskSnapshotV1 {
    pub task_cookie: u64,
    #[serde(default)]
    pub execution_set_id: Option<String>,
    pub entry_instance_id: String,
    #[serde(default)]
    pub admitted_entry_rule_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_binding: Option<NativeRuntimeBindingSnapshotV1>,
    pub creator_task_cookie: Option<u64>,
    pub root_class: Option<String>,
    pub installed_role_class: Option<String>,
    pub real_parent_task_cookie: u64,
    pub real_parent_interval_sequence: u64,
    pub real_parent_host_tid: u32,
    pub real_parent_host_tgid: u32,
    pub real_parent_pid_namespace_inode: u32,
    pub real_parent_start_boottime_ns: u64,
    pub process_state_id: String,
    pub active_execution_id: String,
    pub image_provenance_id: String,
    pub image_candidate_count: u16,
    pub process_execution_state: u8,
    pub process_state_vector_state: u8,
    pub process_state_bits: u64,
    pub active_role_id: u32,
    pub host_tid: u32,
    pub host_tgid: u32,
    pub coordinate_state: u8,
    pub exec_guard_state: u8,
    pub profile_generation_ref_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeRuntimeBindingSnapshotV1 {
    pub binding_id: String,
    pub root_cgroup_id: u64,
    pub prepared_container_state: String,
    pub prepared_container_entry_instance_id: String,
    pub prepared_container_exec_task_cookie: u64,
    pub prepared_container_initial_host_tgid: u32,
}

pub struct NativeIdentityInspector {
    state: KernelStateReader,
}

impl NativeIdentityInspector {
    #[must_use]
    pub fn new(pin_root: impl Into<PathBuf>) -> Self {
        Self {
            state: KernelStateReader::new(pin_root),
        }
    }

    pub fn snapshot(&self, host_pid: u32) -> Result<Option<NativeTaskSnapshotV1>> {
        let raw_pid = i32::try_from(host_pid).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("host PID {host_pid} is invalid: {error}"),
            }
            .build()
        })?;
        let pid = Pid::from_raw(raw_pid).context(IdentityStateSnafu {
            reason: "host PID zero cannot identify a task",
        })?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: PathBuf::from(format!("/proc/{host_pid}")),
            })?;
        let Some(label) = self
            .state
            .lookup("task_labels", &pidfd.as_raw_fd().to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        let label = read_abi_value::<TaskLabelV1>(&label, "task label")?;
        let task_cookie = label.task_cookie;
        let process_state_id = label.process_state_id;
        let profile_generation_ref_id = label.birth_profile_generation_ref_id;
        let entry = self.required(
            "entry_states",
            label.entry_instance_id.as_bytes(),
            "entry state",
        )?;
        let entry = read_abi_value::<EntrySecurityStateV1>(&entry, "entry state")?;
        let runtime_binding = self.runtime_binding(host_pid, label.execution_set_id)?.map(
            |(root_cgroup_id, binding)| NativeRuntimeBindingSnapshotV1 {
                binding_id: id_string(binding.binding_id),
                root_cgroup_id,
                prepared_container_state: prepared_container_state_name(
                    binding.prepared_container_state,
                )
                .to_owned(),
                prepared_container_entry_instance_id: id_string(
                    binding.prepared_container_entry_instance_id,
                ),
                prepared_container_exec_task_cookie: binding.prepared_container_exec_task_cookie,
                prepared_container_initial_host_tgid: binding.prepared_container_initial_host_tgid,
            },
        );
        let process = self.required(
            "process_states",
            process_state_id.as_bytes(),
            "process state",
        )?;
        let process = read_abi_value::<ProcessSecurityStateV1>(&process, "process state")?;
        let process_vector = self.required(
            "process_state_vectors",
            process_state_id.as_bytes(),
            "process state vector",
        )?;
        let process_vector =
            read_abi_value::<ProcessStateVectorV1>(&process_vector, "process state vector")?;
        let active_execution_id = process.active_execution_id;
        let execution = self.required(
            "process_execution_instances",
            active_execution_id.as_bytes(),
            "process execution",
        )?;
        let execution =
            read_abi_value::<ProcessExecutionInstanceV1>(&execution, "process execution")?;
        let image_provenance_id = execution.image_provenance_id;
        let image = self.required(
            "image_provenance",
            image_provenance_id.as_bytes(),
            "image provenance",
        )?;
        let image = read_abi_value::<ImageProvenanceV1>(&image, "image provenance")?;
        let coordinate = self.required(
            "task_coordinates",
            &task_cookie.to_ne_bytes(),
            "task coordinate",
        )?;
        let coordinate = read_abi_value::<TaskCoordinateV1>(&coordinate, "task coordinate")?;
        let real_parent_interval_sequence = coordinate.real_parent_interval_sequence;
        let real_parent_key = KernelRealParentIntervalKeyV1 {
            child_task_cookie: task_cookie,
            interval_sequence: real_parent_interval_sequence,
        };
        let real_parent = self.required(
            "kernel_real_parent_intervals",
            real_parent_key.as_bytes(),
            "kernel real-parent interval",
        )?;
        let real_parent = read_abi_value::<KernelRealParentIntervalV1>(
            &real_parent,
            "kernel real-parent interval",
        )?;
        let creator_task_cookie = self
            .state
            .lookup("created_by_edges", &task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?
            .map(|edge| {
                read_abi_value::<CreatedByEdgeV1>(&edge, "created-by edge")
                    .map(|edge| edge.creator_task_cookie)
            })
            .transpose()?;
        let classification = self
            .state
            .lookup("external_root_classifications", &task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?
            .map(|classification| {
                read_abi_value::<ExternalRootClassificationV1>(
                    &classification,
                    "external-root classification",
                )
            })
            .transpose()?;
        let (root_class, installed_role_class) = classification.map_or((None, None), |value| {
            (
                Some(root_class_name(value.root_class).to_owned()),
                Some(installed_role_class_name(value.installed_role_class).to_owned()),
            )
        });
        Ok(Some(NativeTaskSnapshotV1 {
            task_cookie,
            execution_set_id: Some(id_string(label.execution_set_id)),
            entry_instance_id: id_string(label.entry_instance_id),
            admitted_entry_rule_id: entry.admitted_entry_rule_id,
            runtime_binding,
            creator_task_cookie,
            root_class,
            installed_role_class,
            real_parent_task_cookie: real_parent.real_parent_task_cookie,
            real_parent_interval_sequence,
            real_parent_host_tid: real_parent.real_parent_host_tid,
            real_parent_host_tgid: real_parent.real_parent_host_tgid,
            real_parent_pid_namespace_inode: real_parent.real_parent_pid_namespace_inode,
            real_parent_start_boottime_ns: real_parent.real_parent_start_boottime_ns,
            process_state_id: id_string(process_state_id),
            active_execution_id: id_string(active_execution_id),
            image_provenance_id: id_string(image_provenance_id),
            image_candidate_count: image.candidate_count,
            process_execution_state: execution.state as u8,
            process_state_vector_state: process_vector.state as u8,
            process_state_bits: process_vector.state_bits,
            active_role_id: process.active_role_id,
            host_tid: coordinate.host_tid,
            host_tgid: coordinate.host_tgid,
            coordinate_state: coordinate.state as u8,
            exec_guard_state: process.exec_guard_state as u8,
            profile_generation_ref_id,
        }))
    }

    pub fn snapshot_json(&self, host_pid: u32) -> Result<String> {
        let snapshot = self.snapshot(host_pid)?.context(IdentityStateSnafu {
            reason: format!("host PID {host_pid} has no Mithril task identity"),
        })?;
        serde_json::to_string_pretty(&snapshot).context(JsonSnafu {
            path: "native task snapshot",
        })
    }

    fn required(&self, map: &str, key: &[u8], name: &str) -> Result<Vec<u8>> {
        self.state
            .lookup(map, key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: format!("{name} is missing"),
            })
    }

    fn runtime_binding(
        &self,
        host_pid: u32,
        execution_set_id: Id128V1,
    ) -> Result<Option<(u64, ExecutionSetBindingStateV1)>> {
        let proc_path = PathBuf::from(format!("/proc/{host_pid}/cgroup"));
        let cgroups = fs::read_to_string(&proc_path).context(IoSnafu { path: &proc_path })?;
        let Some(relative) = crate::config::unified_cgroup_path(&cgroups) else {
            return Ok(None);
        };
        let candidate = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        let cgroup_path = fs::canonicalize(&candidate).context(IoSnafu { path: &candidate })?;
        ensure_cgroup_path(&cgroup_path)?;
        let root_cgroup_id = fs::metadata(&cgroup_path)
            .context(IoSnafu { path: &cgroup_path })?
            .ino();

        // The live cgroup inode is the binding key. An execution-set ID alone
        // could select a retired container lifetime with the same policy.
        let Some(binding) = self
            .state
            .lookup("execution_set_bindings", &root_cgroup_id.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        let binding =
            read_abi_value::<ExecutionSetBindingStateV1>(&binding, "execution-set binding")?;
        if binding.root_cgroup_id != root_cgroup_id || binding.execution_set_id != execution_set_id
        {
            return IdentityStateSnafu {
                reason: "live task and execution-set binding identity differ".to_owned(),
            }
            .fail();
        }
        Ok(Some((root_cgroup_id, binding)))
    }
}

fn ensure_cgroup_path(path: &Path) -> Result<()> {
    if path != Path::new("/sys/fs/cgroup") && path.starts_with("/sys/fs/cgroup/") {
        return Ok(());
    }
    IdentityStateSnafu {
        reason: format!("live task cgroup `{}` is outside cgroup2", path.display()),
    }
    .fail()
}

fn read_abi_value<T: KnownLayout + TryFromBytes>(bytes: &[u8], name: &str) -> Result<T> {
    T::try_read_from_bytes(bytes).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("{name} has an invalid ABI value: {error}"),
        }
        .build()
    })
}

fn id_string(id: Id128V1) -> String {
    format!("{:016x}{:016x}", id.high, id.low)
}

fn root_class_name(value: ExternalRootClassV1) -> &'static str {
    match value {
        ExternalRootClassV1::InitialContainerRoot => "initial_container_root",
        ExternalRootClassV1::ExternalRuntimeRoot => "external_runtime_root",
        ExternalRootClassV1::RestoredOrUnknownRoot => "restored_or_unknown_root",
        ExternalRootClassV1::UnresolvedProtected => "unresolved_protected",
        ExternalRootClassV1::Unknown => "unknown",
    }
}

fn installed_role_class_name(value: InstalledRoleClassV1) -> &'static str {
    match value {
        InstalledRoleClassV1::InitialRole => "initial_role",
        InstalledRoleClassV1::RuntimeExternalRestricted => "runtime_external_restricted",
        InstalledRoleClassV1::FailClosedUnknown => "fail_closed_unknown",
        InstalledRoleClassV1::QualifiedRegisteredRole => "qualified_registered_role",
        InstalledRoleClassV1::ApprovedAdministrativeRole => "approved_administrative_role",
        InstalledRoleClassV1::Unknown => "unknown",
    }
}

fn prepared_container_state_name(value: PreparedContainerStateV1) -> &'static str {
    match value {
        PreparedContainerStateV1::Unarmed => "unarmed",
        PreparedContainerStateV1::Prepared => "prepared",
        PreparedContainerStateV1::ExecPending => "exec_pending",
        PreparedContainerStateV1::Active => "active",
        PreparedContainerStateV1::Expired => "expired",
        PreparedContainerStateV1::Corrupt => "corrupt",
    }
}
