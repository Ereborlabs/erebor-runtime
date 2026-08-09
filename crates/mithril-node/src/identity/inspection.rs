use std::mem::{offset_of, size_of};
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{
    CreatedByEdgeV1, ExternalRootClassV1, ExternalRootClassificationV1, Id128V1, ImageProvenanceV1,
    InstalledRoleClassV1, KernelRealParentIntervalKeyV1, KernelRealParentIntervalV1,
    ProcessExecutionInstanceV1, ProcessSecurityStateV1, ProcessStateVectorV1, TaskCoordinateV1,
    TaskLabelV1,
};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde::Serialize;
use snafu::{OptionExt as _, ResultExt as _};

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeTaskSnapshotV1 {
    pub task_cookie: u64,
    pub creator_task_cookie: Option<u64>,
    pub root_class: Option<&'static str>,
    pub installed_role_class: Option<&'static str>,
    pub real_parent_task_cookie: u64,
    pub real_parent_interval_sequence: u64,
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
        require_size::<TaskLabelV1>(&label, "task label")?;
        let task_cookie = read_u64(&label, offset_of!(TaskLabelV1, task_cookie), "task cookie")?;
        let process_state_id = read_id(
            &label,
            offset_of!(TaskLabelV1, process_state_id),
            "process state ID",
        )?;
        let profile_generation_ref_id = read_u64(
            &label,
            offset_of!(TaskLabelV1, birth_profile_generation_ref_id),
            "profile generation reference",
        )?;
        let process =
            self.required("process_states", &id_key(process_state_id), "process state")?;
        require_size::<ProcessSecurityStateV1>(&process, "process state")?;
        let process_vector = self.required(
            "process_state_vectors",
            &id_key(process_state_id),
            "process state vector",
        )?;
        require_size::<ProcessStateVectorV1>(&process_vector, "process state vector")?;
        let active_execution_id = read_id(
            &process,
            offset_of!(ProcessSecurityStateV1, active_execution_id),
            "active execution ID",
        )?;
        let execution = self.required(
            "process_execution_instances",
            &id_key(active_execution_id),
            "process execution",
        )?;
        require_size::<ProcessExecutionInstanceV1>(&execution, "process execution")?;
        let image_provenance_id = read_id(
            &execution,
            offset_of!(ProcessExecutionInstanceV1, image_provenance_id),
            "image provenance ID",
        )?;
        let image = self.required(
            "image_provenance",
            &id_key(image_provenance_id),
            "image provenance",
        )?;
        require_size::<ImageProvenanceV1>(&image, "image provenance")?;
        let coordinate = self.required(
            "task_coordinates",
            &task_cookie.to_ne_bytes(),
            "task coordinate",
        )?;
        require_size::<TaskCoordinateV1>(&coordinate, "task coordinate")?;
        let real_parent_interval_sequence = read_u64(
            &coordinate,
            offset_of!(TaskCoordinateV1, real_parent_interval_sequence),
            "real-parent interval sequence",
        )?;
        let mut real_parent_key = [0_u8; size_of::<KernelRealParentIntervalKeyV1>()];
        real_parent_key[..8].copy_from_slice(&task_cookie.to_ne_bytes());
        real_parent_key[8..].copy_from_slice(&real_parent_interval_sequence.to_ne_bytes());
        let real_parent = self.required(
            "kernel_real_parent_intervals",
            &real_parent_key,
            "kernel real-parent interval",
        )?;
        require_size::<KernelRealParentIntervalV1>(&real_parent, "kernel real-parent interval")?;
        let creator_task_cookie = self
            .state
            .lookup("created_by_edges", &task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?
            .map(|edge| {
                require_size::<CreatedByEdgeV1>(&edge, "created-by edge")?;
                read_u64(
                    &edge,
                    offset_of!(CreatedByEdgeV1, creator_task_cookie),
                    "creator task cookie",
                )
            })
            .transpose()?;
        let classification = self
            .state
            .lookup("external_root_classifications", &task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?;
        let (root_class, installed_role_class) = match classification {
            Some(classification) => {
                require_size::<ExternalRootClassificationV1>(
                    &classification,
                    "external-root classification",
                )?;
                (
                    Some(root_class_name(read_u8(
                        &classification,
                        offset_of!(ExternalRootClassificationV1, root_class),
                        "external-root class",
                    )?)?),
                    Some(installed_role_class_name(read_u8(
                        &classification,
                        offset_of!(ExternalRootClassificationV1, installed_role_class),
                        "installed role class",
                    )?)?),
                )
            }
            None => (None, None),
        };
        Ok(Some(NativeTaskSnapshotV1 {
            task_cookie,
            creator_task_cookie,
            root_class,
            installed_role_class,
            real_parent_task_cookie: read_u64(
                &real_parent,
                offset_of!(KernelRealParentIntervalV1, real_parent_task_cookie),
                "real-parent task cookie",
            )?,
            real_parent_interval_sequence,
            process_state_id: id_string(process_state_id),
            active_execution_id: id_string(active_execution_id),
            image_provenance_id: id_string(image_provenance_id),
            image_candidate_count: read_u16(
                &image,
                offset_of!(ImageProvenanceV1, candidate_count),
                "image candidate count",
            )?,
            process_execution_state: read_u8(
                &execution,
                offset_of!(ProcessExecutionInstanceV1, state),
                "process execution state",
            )?,
            process_state_vector_state: read_u8(
                &process_vector,
                offset_of!(ProcessStateVectorV1, state),
                "process state vector state",
            )?,
            process_state_bits: read_u64(
                &process_vector,
                offset_of!(ProcessStateVectorV1, state_bits),
                "process state bits",
            )?,
            active_role_id: read_u32(
                &process,
                offset_of!(ProcessSecurityStateV1, active_role_id),
                "active role ID",
            )?,
            host_tid: read_u32(
                &coordinate,
                offset_of!(TaskCoordinateV1, host_tid),
                "host TID",
            )?,
            host_tgid: read_u32(
                &coordinate,
                offset_of!(TaskCoordinateV1, host_tgid),
                "host TGID",
            )?,
            coordinate_state: read_u8(
                &coordinate,
                offset_of!(TaskCoordinateV1, state),
                "coordinate state",
            )?,
            exec_guard_state: read_u8(
                &process,
                offset_of!(ProcessSecurityStateV1, exec_guard_state),
                "exec guard state",
            )?,
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
}

fn require_size<T>(bytes: &[u8], name: &str) -> Result<()> {
    if bytes.len() < size_of::<T>() {
        return IdentityStateSnafu {
            reason: format!("{name} is truncated"),
        }
        .fail();
    }
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize, name: &str) -> Result<u64> {
    let value = bytes
        .get(offset..offset + size_of::<u64>())
        .and_then(|value| value.try_into().ok())
        .context(IdentityStateSnafu {
            reason: format!("{name} is truncated"),
        })?;
    Ok(u64::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize, name: &str) -> Result<u32> {
    let value = bytes
        .get(offset..offset + size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .context(IdentityStateSnafu {
            reason: format!("{name} is truncated"),
        })?;
    Ok(u32::from_ne_bytes(value))
}

fn read_u16(bytes: &[u8], offset: usize, name: &str) -> Result<u16> {
    let value = bytes
        .get(offset..offset + size_of::<u16>())
        .and_then(|value| value.try_into().ok())
        .context(IdentityStateSnafu {
            reason: format!("{name} is truncated"),
        })?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u8(bytes: &[u8], offset: usize, name: &str) -> Result<u8> {
    bytes.get(offset).copied().context(IdentityStateSnafu {
        reason: format!("{name} is truncated"),
    })
}

fn read_id(bytes: &[u8], offset: usize, name: &str) -> Result<Id128V1> {
    Ok(Id128V1::new(
        read_u64(bytes, offset, name)?,
        read_u64(bytes, offset + size_of::<u64>(), name)?,
    ))
}

fn id_key(id: Id128V1) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&id.high.to_ne_bytes());
    bytes[8..].copy_from_slice(&id.low.to_ne_bytes());
    bytes
}

fn id_string(id: Id128V1) -> String {
    format!("{:016x}{:016x}", id.high, id.low)
}

fn root_class_name(value: u8) -> Result<&'static str> {
    match value {
        value if value == ExternalRootClassV1::InitialContainerRoot as u8 => {
            Ok("initial_container_root")
        }
        value if value == ExternalRootClassV1::ExternalRuntimeRoot as u8 => {
            Ok("external_runtime_root")
        }
        value if value == ExternalRootClassV1::RestoredOrUnknownRoot as u8 => {
            Ok("restored_or_unknown_root")
        }
        value if value == ExternalRootClassV1::UnresolvedProtected as u8 => {
            Ok("unresolved_protected")
        }
        value if value == ExternalRootClassV1::Unknown as u8 => Ok("unknown"),
        value => IdentityStateSnafu {
            reason: format!("external-root class {value} is invalid"),
        }
        .fail(),
    }
}

fn installed_role_class_name(value: u8) -> Result<&'static str> {
    match value {
        value if value == InstalledRoleClassV1::InitialRole as u8 => Ok("initial_role"),
        value if value == InstalledRoleClassV1::RuntimeExternalRestricted as u8 => {
            Ok("runtime_external_restricted")
        }
        value if value == InstalledRoleClassV1::FailClosedUnknown as u8 => {
            Ok("fail_closed_unknown")
        }
        value if value == InstalledRoleClassV1::QualifiedRegisteredRole as u8 => {
            Ok("qualified_registered_role")
        }
        value if value == InstalledRoleClassV1::ApprovedAdministrativeRole as u8 => {
            Ok("approved_administrative_role")
        }
        value if value == InstalledRoleClassV1::Unknown as u8 => Ok("unknown"),
        value => IdentityStateSnafu {
            reason: format!("installed role class {value} is invalid"),
        }
        .fail(),
    }
}
