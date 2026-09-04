use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use erebor_interceptor_abi::{
    ExactFileMeasurementStateV1, ExactFileMeasurementV1, ExecutionApprovalSlotKeyV1, Id128V1,
    PhysicalDecisionKindV1, PhysicalDecisionV1, PolicyActivationProbeMapKindV1,
    PolicyActivationProbeV1, MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1,
};
use libbpf_rs::{
    query::{LinkInfoIter, MapInfoIter, ProgInfoIter, ProgInfoQueryOptions},
    Iter, Link, Map, MapCore as _, MapFlags, MapHandle, Object, ObjectBuilder, OpenObject, Program,
    ProgramHandle, ProgramInput, ProgramMut, ProgramType, RingBuffer, RingBufferBuilder,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, OptionExt as _, ResultExt as _};
use zerocopy::{IntoBytes as _, TryFromBytes as _};

use crate::error::{
    InvalidConfigurationSnafu, IoSnafu, LibbpfSnafu, ManifestMismatchSnafu, RetainedLsmLinkSnafu,
    StalePinRootSnafu,
};
use crate::lease::KernelHostLease;
use crate::{
    bundled_bpf_sha256, KernelLinkManifestV1, KernelMapLayoutV1, KernelMapManifestV1,
    KernelObjectLayoutV1, KernelObjectManifestV1, KernelPlatformProbe, KernelPreflightV1,
    KernelProgramLayoutV1, Result, BUNDLED_BPF_OBJECT,
};

const BUNDLED_OBJECT_NAME: &str = "embedded erebor-interceptor.bpf.o";
const KERNEL_PROGRAM_NAME_BYTES: usize = libbpf_rs::libbpf_sys::BPF_OBJ_NAME_LEN as usize - 1;
const RETAINED_LINK_UPGRADE_SUFFIX: &str = "-mithril-upgrade";

pub struct EffectObservationReader {
    ring: RingBuffer<'static>,
}

impl EffectObservationReader {
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        poll_until_complete(|| self.ring.poll(timeout)).context(LibbpfSnafu {
            action: "poll effect observation ring",
            path: Path::new("effect_observations"),
        })
    }
}

fn poll_until_complete(mut poll: impl FnMut() -> libbpf_rs::Result<()>) -> libbpf_rs::Result<()> {
    loop {
        match poll() {
            Err(error) if error.kind() == libbpf_rs::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

pub const REQUIRED_QUALIFICATION_LSM_PROGRAMS: [&str; 48] = [
    "qualification_task_alloc",
    "qualification_file_open",
    "qualification_bprm_check_security",
    "qualification_file_receive",
    "qualification_file_permission",
    "qualification_file_ioctl",
    "qualification_mmap_file",
    "qualification_file_mprotect",
    "qualification_socket_post_create",
    "qualification_socket_create",
    "qualification_socket_bind",
    "qualification_socket_listen",
    "qualification_socket_accept",
    "qualification_socket_setsockopt",
    "qualification_socket_shutdown",
    "qualification_unix_stream_connect",
    "qualification_ipc_permission",
    "qualification_socket_connect",
    "qualification_socket_sendmsg",
    "qualification_socket_recvmsg",
    "qualification_socket_socketpair",
    "qualification_unix_may_send",
    "qualification_shm_shmat",
    "qualification_ptrace_access_check",
    "qualification_task_kill",
    "qualification_path_unlink",
    "qualification_path_mknod",
    "qualification_path_mkdir",
    "qualification_path_symlink",
    "qualification_path_rmdir",
    "qualification_path_chmod",
    "qualification_path_chown",
    "qualification_path_truncate",
    "qualification_file_truncate",
    "qualification_path_link",
    "qualification_path_rename",
    "qualification_sb_kern_mount",
    "qualification_sb_mount",
    "qualification_sb_umount",
    "qualification_sb_pivotroot",
    "qualification_move_mount",
    "qualification_capable",
    "qualification_bpf",
    "qualification_inode_init_security_anon",
    "qualification_inode_free_security",
    "qualification_uring_sqpoll",
    "qualification_uring_override_creds",
    "qualification_uring_cmd",
];

pub const REQUIRED_QUALIFICATION_PROGRAMS: [&str; 55] = [
    "qualification_task_alloc",
    "qualification_file_open",
    "qualification_bprm_check_security",
    "qualification_file_receive",
    "qualification_file_permission",
    "qualification_file_ioctl",
    "qualification_mmap_file",
    "qualification_file_mprotect",
    "qualification_socket_post_create",
    "qualification_socket_create",
    "qualification_socket_bind",
    "qualification_socket_listen",
    "qualification_socket_accept",
    "qualification_socket_setsockopt",
    "qualification_socket_shutdown",
    "qualification_socket_release",
    "qualification_inet_csk_accept",
    "qualification_unix_stream_connect",
    "qualification_ipc_permission",
    "qualification_socket_connect",
    "qualification_socket_sendmsg",
    "qualification_socket_recvmsg",
    "qualification_socket_socketpair",
    "qualification_unix_may_send",
    "qualification_shm_shmat",
    "qualification_ptrace_access_check",
    "qualification_task_kill",
    "qualification_path_unlink",
    "qualification_path_mknod",
    "qualification_path_mkdir",
    "qualification_path_symlink",
    "qualification_path_rmdir",
    "qualification_path_chmod",
    "qualification_path_chown",
    "qualification_path_truncate",
    "qualification_file_truncate",
    "qualification_path_link",
    "qualification_path_rename",
    "qualification_sb_kern_mount",
    "qualification_sb_mount",
    "qualification_sb_umount",
    "qualification_sb_pivotroot",
    "qualification_move_mount",
    "qualification_mount_sys_enter_open_tree",
    "qualification_mount_sys_enter_fsconfig",
    "qualification_mount_sys_enter_fsmount",
    "qualification_mount_sys_enter_mount_setattr",
    "qualification_capable",
    "qualification_bpf",
    "qualification_inode_init_security_anon",
    "qualification_inode_free_security",
    "qualification_uring_sqpoll",
    "qualification_uring_override_creds",
    "qualification_uring_cmd",
    "qualification_final_flow",
];

pub const REQUIRED_IDENTITY_PROGRAMS: [&str; 78] = [
    "erebor_task_alloc",
    "erebor_policy_activation_probe",
    "erebor_cgroup_attach_task",
    "erebor_cgroup_release",
    "erebor_wake_up_new_task",
    "erebor_sys_enter_execve",
    "erebor_sys_enter_execveat",
    "erebor_bprm_check_security",
    "erebor_bprm_committing_creds",
    "erebor_sys_exit_execve",
    "erebor_sys_exit_execveat",
    "erebor_exception_sys_enter",
    "erebor_exception_sys_exit",
    "erebor_mount_mutation_sys_exit",
    "erebor_sched_process_exec",
    "erebor_identity_measure_file_open",
    "erebor_identity_inode_free_security",
    "erebor_identity_file_open",
    "erebor_identity_file_receive",
    "erebor_identity_file_permission",
    "erebor_identity_file_ioctl",
    "erebor_identity_mmap_file",
    "erebor_identity_file_mprotect",
    "erebor_identity_socket_post_create",
    "erebor_identity_socket_create",
    "erebor_identity_socket_bind",
    "erebor_identity_socket_listen",
    "erebor_identity_socket_accept",
    "erebor_identity_socket_setsockopt",
    "erebor_identity_socket_shutdown",
    "erebor_network_socket_release",
    "erebor_network_inet_csk_accept",
    "erebor_network_final_flow",
    "erebor_identity_unix_stream_connect",
    "erebor_identity_ipc_permission",
    "erebor_identity_socket_connect",
    "erebor_identity_socket_sendmsg",
    "erebor_identity_socket_recvmsg",
    "erebor_identity_socket_socketpair",
    "erebor_identity_unix_may_send",
    "erebor_identity_shm_shmat",
    "erebor_identity_ptrace_access_check",
    "erebor_identity_task_kill",
    "erebor_identity_path_unlink",
    "erebor_identity_path_mknod",
    "erebor_identity_path_mkdir",
    "erebor_identity_path_symlink",
    "erebor_identity_path_rmdir",
    "erebor_identity_path_chmod",
    "erebor_identity_path_chown",
    "erebor_identity_path_truncate",
    "erebor_identity_file_truncate",
    "erebor_identity_path_link",
    "erebor_identity_path_rename",
    "erebor_identity_sb_mount",
    "erebor_identity_sb_umount",
    "erebor_identity_sb_pivotroot",
    "erebor_identity_move_mount",
    "erebor_mount_sys_enter_open_tree",
    "erebor_mount_sys_enter_fsconfig",
    "erebor_mount_sys_enter_fsmount",
    "erebor_mount_sys_enter_mount_setattr",
    "erebor_identity_capable",
    "erebor_identity_bpf",
    "erebor_io_uring_setup_enter",
    "erebor_identity_inode_init_security_anon",
    "erebor_io_uring_create",
    "erebor_io_uring_register",
    "erebor_io_uring_submit_req",
    "erebor_io_uring_issue_enter",
    "erebor_io_uring_issue_exit",
    "erebor_io_uring_complete",
    "erebor_io_uring_context_free",
    "erebor_identity_uring_sqpoll",
    "erebor_identity_uring_override_creds",
    "erebor_identity_uring_cmd",
    "erebor_sched_process_exit",
    "erebor_reconcile_tasks",
];

pub const EXCEPTION_USE_RECEIPT_CAPACITY: u64 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapInsertResult {
    Inserted,
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionApprovalSlotCancelResult {
    Cancelled,
    Consumed,
    Closed,
    Missing,
}

#[derive(Clone)]
pub struct KernelStateReader {
    maps_root: PathBuf,
}

impl KernelStateReader {
    #[must_use]
    pub fn new(pin_root: impl Into<PathBuf>) -> Self {
        Self {
            maps_root: pin_root.into().join("maps"),
        }
    }

    pub fn lookup(&self, name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure!(
            !name.is_empty() && !name.contains('/'),
            InvalidConfigurationSnafu {
                path: &self.maps_root,
                reason: format!("invalid pinned map name `{name}`"),
            }
        );
        let path = self.maps_root.join(name);
        let map = MapHandle::from_pinned_path(&path).context(LibbpfSnafu {
            action: "open pinned BPF map for read",
            path: &path,
        })?;
        if map.map_type().is_percpu() {
            map.lookup_percpu(key, MapFlags::ANY)
                .map(|values| values.map(|values| values.concat()))
                .context(LibbpfSnafu {
                    action: "read pinned per-CPU BPF map",
                    path: &path,
                })
        } else {
            map.lookup(key, MapFlags::ANY).context(LibbpfSnafu {
                action: "read pinned BPF map",
                path: &path,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelObjectKind {
    Qualification,
    Identity,
}

impl KernelObjectKind {
    const fn required_programs(self) -> &'static [&'static str] {
        match self {
            Self::Qualification => &REQUIRED_QUALIFICATION_PROGRAMS,
            Self::Identity => &REQUIRED_IDENTITY_PROGRAMS,
        }
    }

    fn includes(self, name: &str, _section: &str) -> bool {
        self.required_programs().contains(&name)
    }

    fn attaches(self, name: &str, section: &str) -> bool {
        self.includes(name, section) && self.attaches_name(name)
    }

    fn attaches_name(self, name: &str) -> bool {
        self != Self::Identity
            || !matches!(
                name,
                "erebor_reconcile_tasks" | "erebor_policy_activation_probe"
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelHostConfig {
    pub object_kind: KernelObjectKind,
    object_source: KernelObjectSource,
    pub runtime_btf_path: PathBuf,
    pub lease_path: PathBuf,
    pub pin_root: Option<PathBuf>,
    pub node_boot_id: String,
    pub label_epoch: u64,
    pub network_cgroup_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KernelObjectSource {
    File {
        path: PathBuf,
        expected_sha256: String,
    },
    BundledIdentity,
}

impl KernelHostConfig {
    #[must_use]
    pub fn qualification(
        object_path: impl Into<PathBuf>,
        expected_object_sha256: impl Into<String>,
        runtime_btf_path: impl Into<PathBuf>,
        lease_path: impl Into<PathBuf>,
        pin_root: Option<PathBuf>,
        node_boot_id: impl Into<String>,
        label_epoch: u64,
    ) -> Self {
        Self {
            object_kind: KernelObjectKind::Qualification,
            object_source: KernelObjectSource::File {
                path: object_path.into(),
                expected_sha256: expected_object_sha256.into(),
            },
            runtime_btf_path: runtime_btf_path.into(),
            lease_path: lease_path.into(),
            pin_root,
            node_boot_id: node_boot_id.into(),
            label_epoch,
            network_cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        }
    }

    #[must_use]
    pub fn identity(
        runtime_btf_path: impl Into<PathBuf>,
        lease_path: impl Into<PathBuf>,
        pin_root: Option<PathBuf>,
        node_boot_id: impl Into<String>,
        label_epoch: u64,
    ) -> Self {
        Self {
            object_kind: KernelObjectKind::Identity,
            object_source: KernelObjectSource::BundledIdentity,
            runtime_btf_path: runtime_btf_path.into(),
            lease_path: lease_path.into(),
            pin_root,
            node_boot_id: node_boot_id.into(),
            label_epoch,
            network_cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        }
    }

    #[must_use]
    pub fn retained_identity_qualification(
        object_path: impl Into<PathBuf>,
        expected_object_sha256: impl Into<String>,
        runtime_btf_path: impl Into<PathBuf>,
        lease_path: impl Into<PathBuf>,
        pin_root: Option<PathBuf>,
        node_boot_id: impl Into<String>,
        label_epoch: u64,
    ) -> Self {
        Self {
            object_kind: KernelObjectKind::Identity,
            object_source: KernelObjectSource::File {
                path: object_path.into(),
                expected_sha256: expected_object_sha256.into(),
            },
            runtime_btf_path: runtime_btf_path.into(),
            lease_path: lease_path.into(),
            pin_root,
            node_boot_id: node_boot_id.into(),
            label_epoch,
            network_cgroup_root: PathBuf::from("/sys/fs/cgroup"),
        }
    }

    fn object_path(&self) -> &Path {
        match &self.object_source {
            KernelObjectSource::File { path, .. } => path,
            KernelObjectSource::BundledIdentity => Path::new(BUNDLED_OBJECT_NAME),
        }
    }

    fn expected_sha256(&self) -> Option<&str> {
        match &self.object_source {
            KernelObjectSource::File {
                expected_sha256, ..
            } => Some(expected_sha256),
            KernelObjectSource::BundledIdentity => None,
        }
    }
}

pub struct KernelHostOwner {
    config: KernelHostConfig,
}

pub struct KernelHost {
    lease: KernelHostLease,
    object: Object,
    links: Vec<Link>,
    pinned_paths: Vec<PathBuf>,
    pinned_directories: Vec<PathBuf>,
    remove_pins_on_shutdown: bool,
    manifest: KernelObjectManifestV1,
}

struct PinRollback {
    paths: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    committed: bool,
}

impl KernelHostOwner {
    #[must_use]
    pub fn new(config: KernelHostConfig) -> Self {
        Self { config }
    }

    pub fn inspect(&self) -> Result<KernelObjectLayoutV1> {
        self.validate_config()?;
        let mut builder = ObjectBuilder::default();
        let open = self.open_object(&mut builder, "inspect BPF object")?;
        self.inspect_open_object(&open)
    }

    pub fn start(&self) -> Result<KernelHost> {
        self.validate_config()?;
        let preflight = self.preflight()?;
        let object_sha256 = self.object_sha256()?;
        if let Some(expected) = self.config.expected_sha256() {
            ensure!(
                object_sha256 == expected,
                ManifestMismatchSnafu {
                    path: self.config.object_path(),
                    reason: format!("object digest is {object_sha256}, expected {expected}"),
                }
            );
        }
        let mut builder = ObjectBuilder::default();
        builder
            .btf_custom_path(&self.config.runtime_btf_path)
            .context(LibbpfSnafu {
                action: "set runtime BTF",
                path: &self.config.runtime_btf_path,
            })?;
        let mut open = self.open_object(&mut builder, "open BPF object")?;
        let layout = self.inspect_open_object(&open)?;
        self.configure_autoload(&mut open);
        let retained_pin_root = self.retained_pin_root()?;
        let lease = KernelHostLease::acquire(&self.config.lease_path)?;
        let retained_pin_root = match retained_pin_root {
            Some(pin_root) => Some(pin_root),
            None => self.retained_pin_root()?,
        };
        if let Some(pin_root) = retained_pin_root {
            return self.recover(pin_root, layout, lease, preflight, object_sha256, open);
        }

        self.reject_retained_lsm_links(&BTreeSet::new())?;
        let mut rollback = PinRollback {
            paths: Vec::new(),
            directories: Vec::new(),
            committed: false,
        };
        let pin_directories = self.prepare_fresh_pin_directories(&mut rollback)?;

        let mut object = open.load().context(LibbpfSnafu {
            action: "load BPF object",
            path: self.config.object_path(),
        })?;

        let mut links = Vec::new();
        let mut link_records = Vec::new();
        for program in object.progs_mut() {
            let name = program.name().to_string_lossy().into_owned();
            let section = program.section().to_string_lossy();
            if !self.config.object_kind.attaches(&name, &section) {
                continue;
            }
            let link = self.attach_program(&program)?;
            let info = link.info().context(LibbpfSnafu {
                action: "read attached LSM link",
                path: self.config.object_path(),
            })?;
            ensure!(
                info.id != 0 && info.prog_id != 0,
                ManifestMismatchSnafu {
                    path: self.config.object_path(),
                    reason: format!("program `{name}` attached without readable IDs"),
                }
            );
            let program_tag = ProgramHandle::from_prog_id(info.prog_id)
                .context(LibbpfSnafu {
                    action: "read attached BPF program",
                    path: self.config.object_path(),
                })?
                .tag();
            link_records.push(KernelLinkManifestV1 {
                program: name,
                link_id: info.id,
                program_id: info.prog_id,
                program_tag,
                pin_path: None,
            });
            links.push(link);
        }
        self.validate_attached_set(&link_records)?;

        let mut map_records = object
            .maps()
            .map(|map| {
                let info = map.info().context(LibbpfSnafu {
                    action: "read loaded BPF map",
                    path: self.config.object_path(),
                })?;
                Ok(KernelMapManifestV1 {
                    name: map.name().to_string_lossy().into_owned(),
                    map_type: format!("{:?}", map.map_type()),
                    id: info.info.id,
                    key_size: map.key_size(),
                    value_size: map.value_size(),
                    max_entries: map.max_entries(),
                    pin_path: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some((maps_root, links_root)) = pin_directories {
            for (mut map, record) in object.maps_mut().zip(map_records.iter_mut()) {
                let path = maps_root.join(&record.name);
                map.pin(&path).context(LibbpfSnafu {
                    action: "pin BPF map",
                    path: &path,
                })?;
                rollback.paths.push(path.clone());
                let readback = MapHandle::from_pinned_path(&path).context(LibbpfSnafu {
                    action: "open pinned BPF map",
                    path: &path,
                })?;
                let info = readback.info().context(LibbpfSnafu {
                    action: "read pinned BPF map",
                    path: &path,
                })?;
                ensure!(
                    info.info.id == record.id,
                    ManifestMismatchSnafu {
                        path: &path,
                        reason: format!(
                            "map ID changed from {} to {} during pin readback",
                            record.id, info.info.id
                        ),
                    }
                );
                record.pin_path = Some(path);
            }
            for (link, record) in links.iter_mut().zip(link_records.iter_mut()) {
                let path = links_root.join(&record.program);
                link.pin(&path).context(LibbpfSnafu {
                    action: "pin BPF link",
                    path: &path,
                })?;
                rollback.paths.push(path.clone());
                let readback = Link::open(&path).context(LibbpfSnafu {
                    action: "open pinned BPF link",
                    path: &path,
                })?;
                let info = readback.info().context(LibbpfSnafu {
                    action: "read pinned BPF link",
                    path: &path,
                })?;
                ensure!(
                    info.id == record.link_id && info.prog_id == record.program_id,
                    ManifestMismatchSnafu {
                        path: &path,
                        reason: "link/program IDs changed during pin readback".to_owned(),
                    }
                );
                record.pin_path = Some(path);
            }
        }
        rollback.committed = true;
        let pinned_paths = std::mem::take(&mut rollback.paths);
        let pinned_directories = std::mem::take(&mut rollback.directories);
        map_records.sort_by(|left, right| left.name.cmp(&right.name));
        link_records.sort_by(|left, right| left.program.cmp(&right.program));
        Ok(KernelHost {
            lease,
            object,
            links,
            pinned_paths,
            pinned_directories,
            remove_pins_on_shutdown: self.config.object_kind == KernelObjectKind::Qualification,
            manifest: KernelObjectManifestV1 {
                schema_version: 1,
                node_boot_id: self.config.node_boot_id.clone(),
                label_epoch: self.config.label_epoch,
                preflight,
                object_sha256,
                maps: map_records,
                links: link_records,
                ready: true,
            },
        })
    }

    fn recover(
        &self,
        pin_root: &Path,
        layout: KernelObjectLayoutV1,
        lease: KernelHostLease,
        preflight: KernelPreflightV1,
        object_sha256: String,
        mut open: OpenObject,
    ) -> Result<KernelHost> {
        let maps_root = pin_root.join("maps");
        let links_root = pin_root.join("links");
        let expected_maps = layout
            .maps
            .iter()
            .map(|map| map.name.clone())
            .collect::<BTreeSet<_>>();
        let expected_links = self
            .config
            .object_kind
            .required_programs()
            .iter()
            .copied()
            .filter(|name| self.config.object_kind.attaches_name(name))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        self.clear_interrupted_link_upgrades(&links_root, &expected_links)?;
        ensure!(
            directory_entry_names(&maps_root)? == expected_maps
                && directory_entry_names(&links_root)? == expected_links,
            StalePinRootSnafu { path: pin_root }
        );
        let allowed_link_ids = expected_links
            .iter()
            .map(|name| {
                let path = links_root.join(name);
                let link = Link::open(&path).context(LibbpfSnafu {
                    action: "open retained BPF link",
                    path: &path,
                })?;
                link.info()
                    .context(LibbpfSnafu {
                        action: "read retained BPF link",
                        path: &path,
                    })
                    .map(|info| info.id)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        self.reject_retained_lsm_links(&allowed_link_ids)?;

        for mut map in open.maps_mut() {
            let path = maps_root.join(map.name());
            map.reuse_pinned_map(&path).context(LibbpfSnafu {
                action: "reuse pinned BPF map",
                path: &path,
            })?;
        }
        let object = open.load().context(LibbpfSnafu {
            action: "load BPF object with recovered maps",
            path: self.config.object_path(),
        })?;
        let program_map_ids =
            ProgInfoIter::with_query_opts(ProgInfoQueryOptions::default().include_map_ids(true))
                .map(|program| {
                    (
                        program.id,
                        program.map_ids.into_iter().collect::<BTreeSet<_>>(),
                    )
                })
                .collect::<BTreeMap<_, _>>();

        let mut links = Vec::with_capacity(expected_links.len());
        let mut link_records = Vec::with_capacity(expected_links.len());
        for name in expected_links {
            let path = links_root.join(&name);
            let link = Link::open(&path).context(LibbpfSnafu {
                action: "open pinned BPF link",
                path: &path,
            })?;
            let info = link.info().context(LibbpfSnafu {
                action: "read recovered BPF link",
                path: &path,
            })?;
            let old_program = ProgramHandle::from_prog_id(info.prog_id).context(LibbpfSnafu {
                action: "read recovered BPF program",
                path: &path,
            })?;
            let replacement_program = object
                .progs_mut()
                .find(|program| program.name().to_string_lossy() == name)
                .ok_or_else(|| {
                    ManifestMismatchSnafu {
                        path: self.config.object_path(),
                        reason: format!("recovery object has no program `{name}`"),
                    }
                    .build()
                })?;
            let replacement_program_id =
                Program::id_from_fd(replacement_program.as_fd()).context(LibbpfSnafu {
                    action: "read replacement BPF program ID",
                    path: self.config.object_path(),
                })?;
            let replacement_program_handle = ProgramHandle::from_prog_id(replacement_program_id)
                .context(LibbpfSnafu {
                    action: "read replacement BPF program",
                    path: self.config.object_path(),
                })?;
            let old_map_ids = program_map_ids.get(&info.prog_id).ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: &path,
                    reason: format!("kernel program {} has no readable map-ID set", info.prog_id),
                }
                .build()
            })?;
            let replacement_map_ids = program_map_ids
                .get(&replacement_program_id)
                .ok_or_else(|| {
                    ManifestMismatchSnafu {
                        path: self.config.object_path(),
                        reason: format!(
                            "replacement kernel program {replacement_program_id} has no readable map-ID set"
                        ),
                    }
                    .build()
                })?;
            ensure!(
                old_map_ids == replacement_map_ids,
                ManifestMismatchSnafu {
                    path: &path,
                    reason: format!("pinned program `{name}` does not use the recovered map set"),
                }
            );
            let recovered_link = if old_program.tag() == replacement_program_handle.tag() {
                link
            } else {
                let mut replacement_link = self.attach_program(&replacement_program)?;
                let replacement_info = replacement_link.info().context(LibbpfSnafu {
                    action: "read replacement BPF link",
                    path: self.config.object_path(),
                })?;
                ensure!(
                    replacement_info.prog_id == replacement_program_id,
                    ManifestMismatchSnafu {
                        path: self.config.object_path(),
                        reason: format!(
                            "replacement link for `{name}` attached program {}, expected {replacement_program_id}",
                            replacement_info.prog_id
                        ),
                    }
                );
                let upgrade_path = links_root.join(format!("{name}{RETAINED_LINK_UPGRADE_SUFFIX}"));
                replacement_link.pin(&upgrade_path).context(LibbpfSnafu {
                    action: "pin replacement BPF link",
                    path: &upgrade_path,
                })?;
                // The old link stays attached until the new durable pin replaces its canonical pin.
                fs::rename(&upgrade_path, &path).context(IoSnafu {
                    action: "publish replacement BPF link pin",
                    path: &path,
                })?;
                replacement_link
            };
            let recovered_info = recovered_link.info().context(LibbpfSnafu {
                action: "read upgraded BPF link",
                path: &path,
            })?;
            let recovered_program =
                ProgramHandle::from_prog_id(recovered_info.prog_id).context(LibbpfSnafu {
                    action: "read upgraded BPF program",
                    path: &path,
                })?;
            let pinned_readback = Link::open(&path).context(LibbpfSnafu {
                action: "open upgraded BPF link pin",
                path: &path,
            })?;
            let pinned_info = pinned_readback.info().context(LibbpfSnafu {
                action: "read upgraded BPF link pin",
                path: &path,
            })?;
            ensure!(
                recovered_info.id != 0
                    && recovered_info.id == pinned_info.id
                    && recovered_info.prog_id == pinned_info.prog_id
                    && recovered_program.tag() == replacement_program_handle.tag()
                    && program_map_ids.get(&recovered_info.prog_id) == Some(replacement_map_ids),
                ManifestMismatchSnafu {
                    path: &path,
                    reason: format!(
                        "pinned program `{name}` did not converge to the configured object"
                    ),
                }
            );
            link_records.push(KernelLinkManifestV1 {
                program: name.to_owned(),
                link_id: recovered_info.id,
                program_id: recovered_info.prog_id,
                program_tag: recovered_program.tag(),
                pin_path: Some(path),
            });
            links.push(recovered_link);
        }
        self.validate_attached_set(&link_records)?;

        let mut map_records = object
            .maps()
            .map(|map| {
                let path = maps_root.join(map.name());
                let info = map.info().context(LibbpfSnafu {
                    action: "read recovered BPF map",
                    path: &path,
                })?;
                Ok(KernelMapManifestV1 {
                    name: map.name().to_string_lossy().into_owned(),
                    map_type: format!("{:?}", map.map_type()),
                    id: info.info.id,
                    key_size: map.key_size(),
                    value_size: map.value_size(),
                    max_entries: map.max_entries(),
                    pin_path: Some(path),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        map_records.sort_by(|left, right| left.name.cmp(&right.name));
        link_records.sort_by(|left, right| left.program.cmp(&right.program));
        Ok(KernelHost {
            lease,
            object,
            links,
            pinned_paths: Vec::new(),
            pinned_directories: Vec::new(),
            remove_pins_on_shutdown: false,
            manifest: KernelObjectManifestV1 {
                schema_version: 1,
                node_boot_id: self.config.node_boot_id.clone(),
                label_epoch: self.config.label_epoch,
                preflight,
                object_sha256,
                maps: map_records,
                links: link_records,
                ready: true,
            },
        })
    }

    fn validate_config(&self) -> Result<()> {
        if let KernelObjectSource::File {
            path,
            expected_sha256,
        } = &self.config.object_source
        {
            ensure!(
                path.is_file(),
                InvalidConfigurationSnafu {
                    path,
                    reason: "BPF object is not a regular file".to_owned(),
                }
            );
            ensure!(
                expected_sha256.len() == 64
                    && expected_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                InvalidConfigurationSnafu {
                    path,
                    reason: "expected object digest must be lowercase SHA-256 hex".to_owned(),
                }
            );
        }
        ensure!(
            self.config.runtime_btf_path.is_file(),
            InvalidConfigurationSnafu {
                path: &self.config.runtime_btf_path,
                reason: "runtime BTF is not a regular file".to_owned(),
            }
        );
        ensure!(
            !self.config.node_boot_id.is_empty() && self.config.label_epoch > 0,
            InvalidConfigurationSnafu {
                path: self.config.object_path(),
                reason: "node boot ID must be present and label epoch must be nonzero".to_owned(),
            }
        );
        Ok(())
    }

    fn attach_program(&self, program: &ProgramMut<'_>) -> Result<Link> {
        let name = program.name().to_string_lossy();
        let section = program.section().to_string_lossy();
        if section.starts_with("lsm/") {
            ensure!(
                program.prog_type() == ProgramType::Lsm,
                ManifestMismatchSnafu {
                    path: self.config.object_path(),
                    reason: format!(
                        "program `{name}` has an LSM section but type {:?}",
                        program.prog_type()
                    ),
                }
            );
        }
        if section.starts_with("cgroup_skb/") {
            ensure!(
                program.prog_type() == ProgramType::CgroupSkb,
                ManifestMismatchSnafu {
                    path: self.config.object_path(),
                    reason: format!(
                        "program `{name}` has a cgroup_skb section but type {:?}",
                        program.prog_type()
                    ),
                }
            );
            let cgroup = fs::File::open(&self.config.network_cgroup_root).context(IoSnafu {
                action: "open network cgroup attach root",
                path: &self.config.network_cgroup_root,
            })?;
            return program
                .attach_cgroup(cgroup.as_raw_fd())
                .context(LibbpfSnafu {
                    action: "attach BPF program",
                    path: self.config.object_path(),
                });
        }
        program.attach().context(LibbpfSnafu {
            action: "attach BPF program",
            path: self.config.object_path(),
        })
    }

    fn clear_interrupted_link_upgrades(
        &self,
        links_root: &Path,
        expected_links: &BTreeSet<String>,
    ) -> Result<()> {
        for name in expected_links {
            let canonical_path = links_root.join(name);
            let upgrade_path = links_root.join(format!("{name}{RETAINED_LINK_UPGRADE_SUFFIX}"));
            if !upgrade_path.exists() {
                continue;
            }
            ensure!(
                canonical_path.exists(),
                StalePinRootSnafu { path: links_root }
            );
            fs::remove_file(&upgrade_path).context(IoSnafu {
                action: "remove interrupted BPF link upgrade pin",
                path: &upgrade_path,
            })?;
        }
        Ok(())
    }

    pub fn preflight(&self) -> Result<KernelPreflightV1> {
        self.validate_config()?;
        let platform = KernelPlatformProbe::inspect(&self.config.runtime_btf_path)?;
        let mounts_path = Path::new("/proc/mounts");
        ensure!(
            platform.cgroup_v2,
            InvalidConfigurationSnafu {
                path: mounts_path,
                reason: "cgroup v2 is not mounted".to_owned(),
            }
        );
        let runtime_btf_sha256 = platform.runtime_btf_sha256.ok_or_else(|| {
            InvalidConfigurationSnafu {
                path: &self.config.runtime_btf_path,
                reason: "runtime BTF is not available".to_owned(),
            }
            .build()
        })?;
        Ok(KernelPreflightV1 {
            kernel_release: platform.kernel_release,
            active_lsm_order: platform.active_lsm_order,
            runtime_btf_sha256,
            cgroup_v2: platform.cgroup_v2,
        })
    }

    fn object_sha256(&self) -> Result<String> {
        match &self.config.object_source {
            KernelObjectSource::File { path, .. } => {
                let bytes = fs::read(path).context(IoSnafu {
                    action: "read BPF object",
                    path,
                })?;
                Ok(format!("{:x}", Sha256::digest(bytes)))
            }
            KernelObjectSource::BundledIdentity => Ok(bundled_bpf_sha256()),
        }
    }

    fn open_object(&self, builder: &mut ObjectBuilder, action: &'static str) -> Result<OpenObject> {
        let opened = match &self.config.object_source {
            KernelObjectSource::File { path, .. } => builder.open_file(path),
            KernelObjectSource::BundledIdentity => builder.open_memory(BUNDLED_BPF_OBJECT),
        };
        opened.context(LibbpfSnafu {
            action,
            path: self.config.object_path(),
        })
    }

    fn inspect_open_object(&self, open: &OpenObject) -> Result<KernelObjectLayoutV1> {
        let mut maps = open
            .maps()
            .map(|map| KernelMapLayoutV1 {
                name: map.name().to_string_lossy().into_owned(),
                map_type: format!("{:?}", map.map_type()),
                key_size: map.key_size(),
                value_size: map.value_size(),
                max_entries: map.max_entries(),
            })
            .collect::<Vec<_>>();
        let mut programs = open
            .progs()
            .map(|program| KernelProgramLayoutV1 {
                name: program.name().to_string_lossy().into_owned(),
                section: program.section().to_string_lossy().into_owned(),
                program_type: format!("{:?}", program.prog_type()),
            })
            .collect::<Vec<_>>();
        maps.sort_by(|left, right| left.name.cmp(&right.name));
        programs.sort_by(|left, right| left.name.cmp(&right.name));
        self.validate_program_set(&programs)?;
        Ok(KernelObjectLayoutV1 { maps, programs })
    }

    fn configure_autoload(&self, open: &mut OpenObject) {
        for mut program in open.progs_mut() {
            let name = program.name().to_string_lossy();
            let section = program.section().to_string_lossy();
            program.set_autoload(self.config.object_kind.includes(&name, &section));
        }
    }

    fn prepare_fresh_pin_directories(
        &self,
        rollback: &mut PinRollback,
    ) -> Result<Option<(PathBuf, PathBuf)>> {
        let Some(pin_root) = self.config.pin_root.as_deref() else {
            return Ok(None);
        };
        let maps_root = pin_root.join("maps");
        let links_root = pin_root.join("links");
        if !pin_root.exists() {
            fs::create_dir_all(pin_root).context(IoSnafu {
                action: "create pin root",
                path: pin_root,
            })?;
            rollback.directories.push(pin_root.to_path_buf());
        }
        fs::create_dir(&maps_root).context(IoSnafu {
            action: "create map pin directory",
            path: &maps_root,
        })?;
        rollback.directories.push(maps_root.clone());
        fs::create_dir(&links_root).context(IoSnafu {
            action: "create link pin directory",
            path: &links_root,
        })?;
        rollback.directories.push(links_root.clone());
        Ok(Some((maps_root, links_root)))
    }

    fn retained_pin_root(&self) -> Result<Option<&Path>> {
        let Some(pin_root) = self.config.pin_root.as_deref() else {
            return Ok(None);
        };
        let has_entries = pin_root.exists()
            && fs::read_dir(pin_root)
                .context(IoSnafu {
                    action: "inspect pin root",
                    path: pin_root,
                })?
                .next()
                .is_some();
        if !has_entries {
            return Ok(None);
        }
        ensure!(
            self.config.object_kind == KernelObjectKind::Identity,
            StalePinRootSnafu { path: pin_root }
        );
        Ok(Some(pin_root))
    }

    fn reject_retained_lsm_links(&self, allowed_link_ids: &BTreeSet<u32>) -> Result<()> {
        let known_names = REQUIRED_IDENTITY_PROGRAMS
            .iter()
            .chain(REQUIRED_QUALIFICATION_LSM_PROGRAMS.iter())
            .map(|name| kernel_program_name(name))
            .collect::<BTreeSet<_>>();
        let known_programs = ProgInfoIter::default()
            .filter(|program| program.ty == ProgramType::Lsm)
            .filter_map(|program| {
                let name = program.name.to_string_lossy();
                known_names
                    .contains(name.as_bytes())
                    .then(|| (program.id, name.into_owned()))
            })
            .collect::<BTreeMap<_, _>>();

        for link in LinkInfoIter::default() {
            if let Some(program) = known_programs.get(&link.prog_id) {
                ensure!(
                    allowed_link_ids.contains(&link.id),
                    RetainedLsmLinkSnafu {
                        program,
                        link_id: link.id,
                        program_id: link.prog_id,
                    }
                );
            }
        }
        Ok(())
    }

    fn validate_program_set(&self, programs: &[KernelProgramLayoutV1]) -> Result<()> {
        let mut actual = programs
            .iter()
            .filter(|program| {
                self.config
                    .object_kind
                    .includes(&program.name, &program.section)
            })
            .map(|program| program.name.as_str())
            .collect::<Vec<_>>();
        let mut expected = self.config.object_kind.required_programs().to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        ensure!(
            actual == expected,
            ManifestMismatchSnafu {
                path: self.config.object_path(),
                reason: format!("required program set is {actual:?}, expected {expected:?}"),
            }
        );
        Ok(())
    }

    fn validate_attached_set(&self, links: &[KernelLinkManifestV1]) -> Result<()> {
        let mut actual = links
            .iter()
            .map(|link| link.program.as_str())
            .collect::<Vec<_>>();
        let mut expected = self
            .config
            .object_kind
            .required_programs()
            .iter()
            .copied()
            .filter(|name| self.config.object_kind.attaches_name(name))
            .collect::<Vec<_>>();
        actual.sort_unstable();
        expected.sort_unstable();
        ensure!(
            actual == expected,
            ManifestMismatchSnafu {
                path: self.config.object_path(),
                reason: format!("attached program set is {actual:?}, expected {expected:?}"),
            }
        );
        Ok(())
    }
}

fn kernel_program_name(name: &str) -> Vec<u8> {
    name.as_bytes()
        .iter()
        .copied()
        .take(KERNEL_PROGRAM_NAME_BYTES)
        .collect()
}

impl KernelHost {
    #[must_use]
    pub const fn manifest(&self) -> &KernelObjectManifestV1 {
        &self.manifest
    }

    pub fn verify_live_manifest(&self) -> Result<()> {
        self.lease.verify()?;
        Self::verify_manifest_pins(&self.manifest)
    }

    fn verify_manifest_pins(manifest: &KernelObjectManifestV1) -> Result<()> {
        for record in &manifest.maps {
            let path = record.pin_path.as_deref().context(ManifestMismatchSnafu {
                path: Path::new(&record.name),
                reason: "live map manifest has no pin path",
            })?;
            let map = MapHandle::from_pinned_path(path).context(LibbpfSnafu {
                action: "open live pinned BPF map",
                path,
            })?;
            let info = map.info().context(LibbpfSnafu {
                action: "read live pinned BPF map",
                path,
            })?;
            ensure!(
                info.info.id == record.id
                    && format!("{:?}", map.map_type()) == record.map_type
                    && map.key_size() == record.key_size
                    && map.value_size() == record.value_size
                    && map.max_entries() == record.max_entries,
                ManifestMismatchSnafu {
                    path,
                    reason: "live map ID or layout differs from its manifest".to_owned(),
                }
            );
        }
        for record in &manifest.links {
            let path = record.pin_path.as_deref().context(ManifestMismatchSnafu {
                path: Path::new(&record.program),
                reason: "live link manifest has no pin path",
            })?;
            let link = Link::open(path).context(LibbpfSnafu {
                action: "open live pinned BPF link",
                path,
            })?;
            let info = link.info().context(LibbpfSnafu {
                action: "read live pinned BPF link",
                path,
            })?;
            let program = ProgramHandle::from_prog_id(info.prog_id).context(LibbpfSnafu {
                action: "read live BPF program",
                path,
            })?;
            ensure!(
                info.id == record.link_id
                    && info.prog_id == record.program_id
                    && program.tag() == record.program_tag,
                ManifestMismatchSnafu {
                    path,
                    reason: format!(
                        "live link/program IDs are {}/{}, expected {}/{}",
                        info.id, info.prog_id, record.link_id, record.program_id
                    ),
                }
            );
        }
        Ok(())
    }

    fn map(&self, name: &str) -> Result<Map<'_>> {
        self.object
            .maps()
            .find(|map| map.name().to_string_lossy() == name)
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from(name),
                    reason: "loaded object has no such map".to_owned(),
                }
                .build()
            })
    }

    pub fn update_map(&self, name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let map = self.map(name)?;
        map.update(key, value, MapFlags::ANY).context(LibbpfSnafu {
            action: "update BPF map",
            path: Path::new(name),
        })
    }

    pub fn insert_map(&self, name: &str, key: &[u8], value: &[u8]) -> Result<MapInsertResult> {
        match self.map(name)?.update(key, value, MapFlags::NO_EXIST) {
            Ok(()) => Ok(MapInsertResult::Inserted),
            Err(error) if error.kind() == libbpf_rs::ErrorKind::AlreadyExists => {
                Ok(MapInsertResult::AlreadyExists)
            }
            Err(source) => Err(crate::Error::Libbpf {
                action: "insert BPF map entry",
                path: PathBuf::from(name),
                source,
                location: snafu::Location::default(),
            }),
        }
    }

    pub fn lookup_map(&self, name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let map = self.map(name)?;
        if map.map_type().is_percpu() {
            map.lookup_percpu(key, MapFlags::ANY)
                .map(|values| values.map(|values| values.concat()))
                .context(LibbpfSnafu {
                    action: "read per-CPU BPF map",
                    path: Path::new(name),
                })
        } else {
            map.lookup(key, MapFlags::ANY).context(LibbpfSnafu {
                action: "read BPF map",
                path: Path::new(name),
            })
        }
    }

    pub fn lookup_map_locked(&self, name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.map(name)?
            .lookup(key, MapFlags::LOCK)
            .context(LibbpfSnafu {
                action: "read spin-locked BPF map",
                path: Path::new(name),
            })
    }

    pub fn delete_map_entry(&self, name: &str, key: &[u8]) -> Result<()> {
        let map = self.map(name)?;
        map.delete(key).context(LibbpfSnafu {
            action: "delete BPF map entry",
            path: Path::new(name),
        })
    }

    pub fn stage_exact_file_measurement(&self, pid_tgid: u64, request_nonce: u64) -> Result<()> {
        ensure!(
            pid_tgid != 0 && request_nonce != 0,
            ManifestMismatchSnafu {
                path: Path::new("exact_file_measurements"),
                reason: "exact file measurement needs a nonzero task and request nonce".to_owned(),
            }
        );
        let request = ExactFileMeasurementV1 {
            request_nonce,
            state: ExactFileMeasurementStateV1::Requested,
            ..Default::default()
        };
        let key = pid_tgid.to_ne_bytes();
        self.update_map("exact_file_measurements", &key, request.as_bytes())?;
        ensure!(
            self.lookup_map("exact_file_measurements", &key)?.as_deref()
                == Some(request.as_bytes()),
            ManifestMismatchSnafu {
                path: Path::new("exact_file_measurements"),
                reason: "exact file measurement request failed readback".to_owned(),
            }
        );
        Ok(())
    }

    pub fn take_exact_file_measurement(
        &self,
        pid_tgid: u64,
        request_nonce: u64,
    ) -> Result<ExactFileMeasurementV1> {
        let key = pid_tgid.to_ne_bytes();
        let bytes =
            self.lookup_map("exact_file_measurements", &key)?
                .context(ManifestMismatchSnafu {
                    path: Path::new("exact_file_measurements"),
                    reason: "exact file measurement result is missing".to_owned(),
                })?;
        self.delete_map_entry("exact_file_measurements", &key)?;
        ensure!(
            self.lookup_map("exact_file_measurements", &key)?.is_none(),
            ManifestMismatchSnafu {
                path: Path::new("exact_file_measurements"),
                reason: "exact file measurement request remained after use".to_owned(),
            }
        );
        let measurement = ExactFileMeasurementV1::try_read_from_bytes(&bytes).map_err(|error| {
            ManifestMismatchSnafu {
                path: PathBuf::from("exact_file_measurements"),
                reason: format!("exact file measurement has an invalid ABI value: {error}"),
            }
            .build()
        })?;
        ensure!(
            measurement.request_nonce == request_nonce
                && measurement.state == ExactFileMeasurementStateV1::Measured
                && measurement.reserved == [0; 7]
                && measurement.mount_namespace_inode != 0
                && measurement.mount_id_unique != 0
                && measurement.inode != 0,
            ManifestMismatchSnafu {
                path: Path::new("exact_file_measurements"),
                reason: "exact file measurement result is incomplete or belongs to another request"
                    .to_owned(),
            }
        );
        Ok(measurement)
    }

    pub fn discard_exact_file_measurement(&self, pid_tgid: u64) -> Result<()> {
        let key = pid_tgid.to_ne_bytes();
        if self.lookup_map("exact_file_measurements", &key)?.is_some() {
            self.delete_map_entry("exact_file_measurements", &key)?;
        }
        ensure!(
            self.lookup_map("exact_file_measurements", &key)?.is_none(),
            ManifestMismatchSnafu {
                path: Path::new("exact_file_measurements"),
                reason: "cancelled exact file measurement request remained installed".to_owned(),
            }
        );
        Ok(())
    }

    pub fn map_keys(&self, name: &str) -> Result<Vec<Vec<u8>>> {
        let map = self.map(name)?;
        Ok(map.keys().collect())
    }

    pub fn effect_observation_reader<F>(&self, callback: F) -> Result<EffectObservationReader>
    where
        F: FnMut(&[u8]) -> i32 + 'static,
    {
        let map = self
            .object
            .maps()
            .find(|map| map.name().to_string_lossy() == "effect_observations")
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from("effect_observations"),
                    reason: "loaded object has no effect observation ring".to_owned(),
                }
                .build()
            })?;
        let mut builder = RingBufferBuilder::new();
        builder.add(&map, callback).context(LibbpfSnafu {
            action: "register effect observation callback",
            path: Path::new("effect_observations"),
        })?;
        let ring = builder.build().context(LibbpfSnafu {
            action: "build effect observation reader",
            path: Path::new("effect_observations"),
        })?;
        Ok(EffectObservationReader { ring })
    }

    pub fn reconcile_tasks(&mut self) -> Result<()> {
        let program = self
            .object
            .progs_mut()
            .find(|program| program.name().to_string_lossy() == "erebor_reconcile_tasks")
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from("erebor_reconcile_tasks"),
                    reason: "loaded object has no task reconciliation iterator".to_owned(),
                }
                .build()
            })?;
        let link = program.attach().context(LibbpfSnafu {
            action: "attach task reconciliation iterator",
            path: Path::new("erebor_reconcile_tasks"),
        })?;
        let mut iterator = Iter::new(&link).context(LibbpfSnafu {
            action: "open task reconciliation iterator",
            path: Path::new("erebor_reconcile_tasks"),
        })?;
        io::copy(&mut iterator, &mut io::sink()).context(IoSnafu {
            action: "run task reconciliation iterator",
            path: Path::new("erebor_reconcile_tasks"),
        })?;
        Ok(())
    }

    pub fn run_policy_activation_probe(&mut self, request: &[u8]) -> Result<()> {
        let return_value = self.run_policy_activation_command(request)?;
        ensure!(
            return_value == 1,
            ManifestMismatchSnafu {
                path: Path::new("erebor_policy_activation_probe"),
                reason: format!(
                    "staged policy row did not match the BPF lookup result; probe code was {return_value}"
                ),
            }
        );
        Ok(())
    }

    pub fn apply_mount_reconciliation_proposal(
        &mut self,
        mount_namespace_inode: u32,
    ) -> Result<bool> {
        ensure!(
            mount_namespace_inode != 0,
            ManifestMismatchSnafu {
                path: PathBuf::from("mount_reconciliation_proposals"),
                reason: "mount reconciliation needs a nonzero mount namespace".to_owned(),
            }
        );
        let namespace = mount_namespace_inode.to_ne_bytes();
        let mut key = [0_u8; MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1];
        key[..namespace.len()].copy_from_slice(&namespace);
        let request = PolicyActivationProbeV1 {
            map_kind: PolicyActivationProbeMapKindV1::MountReconciliation,
            reserved: [0; 7],
            key_size: namespace.len() as u32,
            reserved_alignment: 0,
            key,
            expected: PhysicalDecisionV1 {
                decision: PhysicalDecisionKindV1::Allow,
                reserved: 0,
                errno: 0,
                evidence_class_id: 0,
                transition_id: 0,
                exception_numeric_handle: 0,
            },
        };
        let return_value = self.run_policy_activation_command(request.as_bytes())?;
        if return_value == 1 {
            return Ok(true);
        }
        if return_value == 12 {
            return Ok(false);
        }
        Err(ManifestMismatchSnafu {
            path: PathBuf::from("mount_reconciliation_proposals"),
            reason: format!(
                "kernel mount reconciliation command is invalid; probe code {return_value}"
            ),
        }
        .build())
    }

    pub fn cancel_execution_approval_slot(
        &mut self,
        key: ExecutionApprovalSlotKeyV1,
        proof_id: Id128V1,
        claim_slot_id: Id128V1,
    ) -> Result<ExecutionApprovalSlotCancelResult> {
        let mut probe_key = [0_u8; MAX_POLICY_ACTIVATION_PROBE_KEY_BYTES_V1];
        let mut offset = 0;
        for value in [
            key.as_bytes(),
            proof_id.as_bytes(),
            claim_slot_id.as_bytes(),
        ] {
            let end = offset + value.len();
            probe_key[offset..end].copy_from_slice(value);
            offset = end;
        }
        let request = PolicyActivationProbeV1 {
            map_kind: PolicyActivationProbeMapKindV1::ExecutionApprovalSlotCancel,
            reserved: [0; 7],
            key_size: u32::try_from(offset).map_err(|error| {
                ManifestMismatchSnafu {
                    path: PathBuf::from("execution_approval_slots"),
                    reason: format!("administrative cancellation key exceeds u32: {error}"),
                }
                .build()
            })?,
            reserved_alignment: 0,
            key: probe_key,
            expected: PhysicalDecisionV1 {
                decision: PhysicalDecisionKindV1::Allow,
                reserved: 0,
                errno: 0,
                evidence_class_id: 0,
                transition_id: 0,
                exception_numeric_handle: 0,
            },
        };
        match self.run_policy_activation_command(request.as_bytes())? {
            1 => Ok(ExecutionApprovalSlotCancelResult::Cancelled),
            7 => Ok(ExecutionApprovalSlotCancelResult::Missing),
            9 => Ok(ExecutionApprovalSlotCancelResult::Consumed),
            10 => Ok(ExecutionApprovalSlotCancelResult::Closed),
            code => ManifestMismatchSnafu {
                path: PathBuf::from("execution_approval_slots"),
                reason: format!(
                    "execution approval slot cancellation failed closed with probe code {code}"
                ),
            }
            .fail(),
        }
    }

    fn run_policy_activation_command(&mut self, request: &[u8]) -> Result<u32> {
        let request_key = 0_u32.to_ne_bytes();
        self.update_map("policy_activation_probe_requests", &request_key, request)?;
        ensure!(
            self.lookup_map("policy_activation_probe_requests", &request_key)?
                .as_deref()
                == Some(request),
            ManifestMismatchSnafu {
                path: Path::new("policy_activation_probe_requests"),
                reason: "policy activation probe request failed readback".to_owned(),
            }
        );
        let program = self
            .object
            .progs_mut()
            .find(|program| program.name().to_string_lossy() == "erebor_policy_activation_probe")
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from("erebor_policy_activation_probe"),
                    reason: "loaded object has no policy activation probe".to_owned(),
                }
                .build()
            })?;
        let packet = [0_u8; 14];
        let output = program
            .test_run(ProgramInput {
                data_in: Some(&packet),
                ..Default::default()
            })
            .context(LibbpfSnafu {
                action: "run policy activation probe",
                path: Path::new("erebor_policy_activation_probe"),
            })?;
        Ok(output.return_value)
    }

    pub fn shutdown(mut self) -> Result<()> {
        if self.remove_pins_on_shutdown {
            self.remove_pins()?;
        }
        self.links.clear();
        Ok(())
    }

    pub fn decommission(mut self) -> Result<()> {
        let link_ids = self
            .manifest
            .links
            .iter()
            .map(|link| (link.link_id, link.program_id))
            .collect::<BTreeSet<_>>();
        let map_ids = self
            .manifest
            .maps
            .iter()
            .map(|map| map.id)
            .collect::<BTreeSet<_>>();
        let link_paths = self
            .manifest
            .links
            .iter()
            .map(|link| link.pin_path.clone())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: Path::new("BPF link pins"),
                    reason: "decommission requires every BPF link to have an owned pin".to_owned(),
                }
                .build()
            })?;
        let map_paths = self
            .manifest
            .maps
            .iter()
            .map(|map| map.pin_path.clone())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: Path::new("BPF map pins"),
                    reason: "decommission requires every BPF map to have an owned pin".to_owned(),
                }
                .build()
            })?;
        ensure!(
            !link_paths.is_empty() && !map_paths.is_empty(),
            ManifestMismatchSnafu {
                path: Path::new("BPF pins"),
                reason: "decommission requires a nonempty pinned link and map set".to_owned(),
            }
        );
        for path in link_paths.iter().chain(map_paths.iter()) {
            fs::remove_file(path).context(IoSnafu {
                action: "remove decommissioned BPF pin",
                path,
            })?;
        }
        self.links.clear();
        let mut directories = link_paths
            .iter()
            .chain(map_paths.iter())
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect::<BTreeSet<_>>();
        if let Some(root) = directories
            .iter()
            .next()
            .and_then(|directory| directory.parent())
            .map(Path::to_path_buf)
        {
            directories.insert(root);
        }
        for directory in directories.iter().rev() {
            fs::remove_dir(directory).context(IoSnafu {
                action: "remove empty decommissioned BPF pin directory",
                path: directory,
            })?;
        }
        self.pinned_paths.clear();
        self.pinned_directories.clear();
        self.remove_pins_on_shutdown = false;
        drop(self);

        ensure!(
            link_paths
                .iter()
                .chain(map_paths.iter())
                .all(|path| !path.exists())
                && directories.iter().all(|path| !path.exists())
                && LinkInfoIter::default().all(|link| !link_ids.contains(&(link.id, link.prog_id)))
                && MapInfoIter::default().all(|map| !map_ids.contains(&map.id)),
            ManifestMismatchSnafu {
                path: Path::new("BPF decommission readback"),
                reason: "decommissioned BPF links, maps, or pins remain present".to_owned(),
            }
        );
        Ok(())
    }

    fn remove_pins(&mut self) -> Result<()> {
        while let Some(path) = self.pinned_paths.pop() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(crate::Error::Io {
                        action: "remove BPF pin",
                        path,
                        source,
                        location: snafu::Location::default(),
                    })
                }
            }
        }
        while let Some(path) = self.pinned_directories.pop() {
            match fs::remove_dir(&path) {
                Ok(()) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(crate::Error::Io {
                        action: "remove empty BPF pin directory",
                        path,
                        source,
                        location: snafu::Location::default(),
                    })
                }
            }
        }
        Ok(())
    }
}

impl Drop for KernelHost {
    fn drop(&mut self) {
        if self.remove_pins_on_shutdown {
            while let Some(path) = self.pinned_paths.pop() {
                let _result = fs::remove_file(path);
            }
            while let Some(path) = self.pinned_directories.pop() {
                let _result = fs::remove_dir(path);
            }
        }
        self.links.clear();
    }
}

fn directory_entry_names(path: &Path) -> Result<BTreeSet<String>> {
    let entries = fs::read_dir(path).context(IoSnafu {
        action: "inspect pinned BPF directory",
        path,
    })?;
    entries
        .map(|entry| {
            let entry = entry.context(IoSnafu {
                action: "read pinned BPF directory entry",
                path,
            })?;
            entry.file_name().into_string().map_err(|_| {
                ManifestMismatchSnafu {
                    path,
                    reason: "pinned BPF entry name is not UTF-8".to_owned(),
                }
                .build()
            })
        })
        .collect()
}

impl Drop for PinRollback {
    fn drop(&mut self) {
        if !self.committed {
            while let Some(path) = self.paths.pop() {
                let _result = fs::remove_file(path);
            }
            while let Some(path) = self.directories.pop() {
                let _result = fs::remove_dir(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use snafu::{OptionExt as _, ResultExt as _};
    use std::{fs, io};

    use super::{
        kernel_program_name, poll_until_complete, KernelHost, KernelHostConfig, KernelHostOwner,
        KernelObjectKind, KernelProgramLayoutV1, PinRollback, REQUIRED_QUALIFICATION_LSM_PROGRAMS,
    };
    use crate::error::{InvalidConfigurationSnafu, IoSnafu};
    use crate::{
        KernelLinkManifestV1, KernelMapManifestV1, KernelObjectManifestV1, KernelPreflightV1,
        BUNDLED_BPF_OBJECT,
    };

    #[test]
    fn effect_reader_retries_an_interrupted_poll() {
        let mut attempts = 0;
        let result = poll_until_complete(|| {
            attempts += 1;
            if attempts == 1 {
                Err(libbpf_rs::Error::from(io::Error::from(
                    io::ErrorKind::Interrupted,
                )))
            } else {
                Ok(())
            }
        });

        assert!(result.is_ok(), "the second poll must complete");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn missing_required_hook_cannot_validate() {
        let owner = KernelHostOwner::new(KernelHostConfig::qualification(
            "object",
            "0".repeat(64),
            "btf",
            "lease",
            None,
            "boot",
            1,
        ));
        let programs = REQUIRED_QUALIFICATION_LSM_PROGRAMS
            [..REQUIRED_QUALIFICATION_LSM_PROGRAMS.len() - 1]
            .iter()
            .map(|name| KernelProgramLayoutV1 {
                name: (*name).to_owned(),
                section: format!("lsm/{name}"),
                program_type: "Lsm".to_owned(),
            })
            .collect::<Vec<_>>();
        assert!(owner.validate_program_set(&programs).is_err());
    }

    #[test]
    fn duplicate_required_hook_cannot_validate() {
        let owner = KernelHostOwner::new(KernelHostConfig::qualification(
            "object",
            "0".repeat(64),
            "btf",
            "lease",
            None,
            "boot",
            1,
        ));
        let mut programs = REQUIRED_QUALIFICATION_LSM_PROGRAMS
            .iter()
            .map(|name| KernelProgramLayoutV1 {
                name: (*name).to_owned(),
                section: format!("lsm/{name}"),
                program_type: "Lsm".to_owned(),
            })
            .collect::<Vec<_>>();
        programs.push(programs[0].clone());

        assert!(owner.validate_program_set(&programs).is_err());
    }

    #[test]
    fn live_manifest_requires_every_map_and_link_pin() {
        let preflight = KernelPreflightV1 {
            kernel_release: "test".to_owned(),
            active_lsm_order: "bpf".to_owned(),
            runtime_btf_sha256: "0".repeat(64),
            cgroup_v2: true,
        };
        let map_without_pin = KernelObjectManifestV1 {
            schema_version: 1,
            node_boot_id: "boot".to_owned(),
            label_epoch: 1,
            preflight: preflight.clone(),
            object_sha256: "0".repeat(64),
            maps: vec![KernelMapManifestV1 {
                name: "map".to_owned(),
                map_type: "Hash".to_owned(),
                id: 1,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
                pin_path: None,
            }],
            links: Vec::new(),
            ready: true,
        };
        assert!(KernelHost::verify_manifest_pins(&map_without_pin)
            .is_err_and(|error| error.to_string().contains("no pin path")));

        let link_without_pin = KernelObjectManifestV1 {
            maps: Vec::new(),
            links: vec![KernelLinkManifestV1 {
                program: "program".to_owned(),
                link_id: 1,
                program_id: 2,
                program_tag: [0; 8],
                pin_path: None,
            }],
            preflight,
            ..map_without_pin
        };
        assert!(KernelHost::verify_manifest_pins(&link_without_pin)
            .is_err_and(|error| error.to_string().contains("no pin path")));
    }

    #[test]
    fn retained_lsm_link_guard_uses_kernel_program_names() {
        assert_eq!(
            kernel_program_name("erebor_identity_file_permission"),
            b"erebor_identity".to_vec()
        );
    }

    #[test]
    fn fresh_pin_directories_prepare_before_load_and_roll_back() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            action: "create temporary pin root",
            path: "temporary pin root",
        })?;
        let root = temporary.path().join("pins");
        let owner = KernelHostOwner::new(KernelHostConfig::identity(
            "btf",
            temporary.path().join("owner.lock"),
            Some(root.clone()),
            "boot",
            1,
        ));
        let mut rollback = PinRollback {
            paths: Vec::new(),
            directories: Vec::new(),
            committed: false,
        };
        let (maps, links) = owner
            .prepare_fresh_pin_directories(&mut rollback)?
            .context(InvalidConfigurationSnafu {
                path: root.clone(),
                reason: "configured pin root did not create pin directories",
            })?;
        assert!(root.is_dir() && maps.is_dir() && links.is_dir());
        drop(rollback);
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn identity_program_selection_keeps_nonattached_commands_out_of_links() {
        let kind = KernelObjectKind::Identity;
        assert!(kind.includes("erebor_cgroup_attach_task", "tp_btf/cgroup_attach_task"));
        assert!(kind.attaches("erebor_cgroup_attach_task", "tp_btf/cgroup_attach_task"));
        assert!(kind.includes(
            "erebor_sys_enter_execve",
            "tracepoint/syscalls/sys_enter_execve"
        ));
        assert!(kind.includes(
            "erebor_sys_enter_execveat",
            "tracepoint/syscalls/sys_enter_execveat"
        ));
        assert!(kind.includes("erebor_reconcile_tasks", "iter/task"));
        assert!(!kind.attaches("erebor_reconcile_tasks", "iter/task"));
        assert!(kind.includes("erebor_policy_activation_probe", "classifier"));
        assert!(!kind.attaches("erebor_policy_activation_probe", "classifier"));
        assert!(!kind.includes("unrelated", "tracepoint/sched/sched_process_exit"));
    }

    #[test]
    fn identity_autoloads_only_its_required_programs() -> crate::Result<()> {
        let owner =
            KernelHostOwner::new(KernelHostConfig::identity("btf", "lease", None, "boot", 1));
        let mut object = libbpf_rs::ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;

        owner.configure_autoload(&mut object);

        for program in object.progs() {
            let name = program.name().to_string_lossy();
            let section = program.section().to_string_lossy();
            assert_eq!(
                program.autoload(),
                KernelObjectKind::Identity.includes(&name, &section),
                "{name}"
            );
        }
        Ok(())
    }

    #[test]
    fn partial_pin_rollback_removes_files_and_owned_directories() -> crate::Result<()> {
        let temporary = tempfile::tempdir().context(IoSnafu {
            action: "create temporary pin root",
            path: "temporary pin root",
        })?;
        let root = temporary.path().join("pins");
        let maps = root.join("maps");
        let links = root.join("links");
        fs::create_dir_all(&maps).context(IoSnafu {
            action: "create fake map pin directory",
            path: &maps,
        })?;
        fs::create_dir(&links).context(IoSnafu {
            action: "create fake link pin directory",
            path: &links,
        })?;
        let map = maps.join("first");
        fs::write(&map, b"pin").context(IoSnafu {
            action: "create fake partial pin",
            path: &map,
        })?;
        drop(PinRollback {
            paths: vec![map],
            directories: vec![root.clone(), maps, links],
            committed: false,
        });
        assert!(!root.exists());
        Ok(())
    }
}
