use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libbpf_rs::{
    Iter, Link, Map, MapCore as _, MapFlags, MapHandle, Object, ObjectBuilder, OpenObject, Program,
    ProgramHandle, ProgramType, RingBuffer, RingBufferBuilder,
};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{
    InvalidConfigurationSnafu, IoSnafu, LibbpfSnafu, ManifestMismatchSnafu, StalePinRootSnafu,
};
use crate::lease::PinRootLease;
use crate::{
    bundled_bpf_sha256, KernelLinkManifestV1, KernelMapLayoutV1, KernelMapManifestV1,
    KernelObjectLayoutV1, KernelObjectManifestV1, KernelPlatformProbe, KernelPreflightV1,
    KernelProgramLayoutV1, Result, BUNDLED_BPF_OBJECT,
};

const BUNDLED_OBJECT_NAME: &str = "embedded erebor-interceptor.bpf.o";

pub struct EffectObservationReader {
    ring: RingBuffer<'static>,
}

impl EffectObservationReader {
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        self.ring.poll(timeout).context(LibbpfSnafu {
            action: "poll effect observation ring",
            path: Path::new("effect_observations"),
        })
    }
}

pub const REQUIRED_QUALIFICATION_LSM_PROGRAMS: [&str; 21] = [
    "qualification_task_alloc",
    "qualification_file_open",
    "qualification_bprm_check_security",
    "qualification_file_permission",
    "qualification_file_ioctl",
    "qualification_mmap_file",
    "qualification_file_mprotect",
    "qualification_ipc_permission",
    "qualification_socket_connect",
    "qualification_socket_sendmsg",
    "qualification_ptrace_access_check",
    "qualification_task_kill",
    "qualification_path_unlink",
    "qualification_path_link",
    "qualification_path_rename",
    "qualification_sb_mount",
    "qualification_sb_umount",
    "qualification_sb_pivotroot",
    "qualification_move_mount",
    "qualification_capable",
    "qualification_bpf",
];

pub const REQUIRED_IDENTITY_PROGRAMS: [&str; 37] = [
    "erebor_task_alloc",
    "erebor_cgroup_attach_task",
    "erebor_cgroup_release",
    "erebor_wake_up_new_task",
    "erebor_sys_enter_execve",
    "erebor_sys_enter_execveat",
    "erebor_bprm_check_security",
    "erebor_bprm_committing_creds",
    "erebor_sys_exit_execve",
    "erebor_sys_exit_execveat",
    "erebor_mount_mutation_sys_exit",
    "erebor_sched_process_exec",
    "erebor_identity_file_open",
    "erebor_identity_file_permission",
    "erebor_identity_file_ioctl",
    "erebor_identity_mmap_file",
    "erebor_identity_file_mprotect",
    "erebor_identity_ipc_permission",
    "erebor_identity_socket_connect",
    "erebor_identity_socket_sendmsg",
    "erebor_identity_ptrace_access_check",
    "erebor_identity_task_kill",
    "erebor_identity_path_unlink",
    "erebor_identity_inode_create",
    "erebor_identity_path_chmod",
    "erebor_identity_path_truncate",
    "erebor_identity_file_truncate",
    "erebor_identity_path_link",
    "erebor_identity_path_rename",
    "erebor_identity_sb_mount",
    "erebor_identity_sb_umount",
    "erebor_identity_sb_pivotroot",
    "erebor_identity_move_mount",
    "erebor_identity_capable",
    "erebor_identity_bpf",
    "erebor_sched_process_exit",
    "erebor_reconcile_tasks",
];

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
            Self::Qualification => &REQUIRED_QUALIFICATION_LSM_PROGRAMS,
            Self::Identity => &REQUIRED_IDENTITY_PROGRAMS,
        }
    }

    fn includes(self, name: &str, section: &str) -> bool {
        self.required_programs().contains(&name)
            && (self != Self::Qualification || section.starts_with("lsm/"))
    }

    fn attaches(self, name: &str, section: &str) -> bool {
        self.includes(name, section) && self.attaches_name(name)
    }

    fn attaches_name(self, name: &str) -> bool {
        self != Self::Identity || name != "erebor_reconcile_tasks"
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
    _lease: PinRootLease,
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
        let lease = PinRootLease::acquire(&self.config.lease_path)?;
        if let Some(pin_root) = &self.config.pin_root {
            if pin_root.exists()
                && fs::read_dir(pin_root)
                    .context(IoSnafu {
                        action: "inspect pin root",
                        path: pin_root,
                    })?
                    .next()
                    .is_some()
            {
                ensure!(
                    self.config.object_kind == KernelObjectKind::Identity,
                    StalePinRootSnafu { path: pin_root }
                );
                return self.recover(pin_root, layout, lease, preflight, object_sha256, open);
            }
        }

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
            let link = program.attach().context(LibbpfSnafu {
                action: "attach BPF program",
                path: self.config.object_path(),
            })?;
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
            link_records.push(KernelLinkManifestV1 {
                program: name,
                link_id: info.id,
                program_id: info.prog_id,
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
        let mut rollback = PinRollback {
            paths: Vec::new(),
            directories: Vec::new(),
            committed: false,
        };
        if let Some(pin_root) = &self.config.pin_root {
            let maps_root = pin_root.join("maps");
            let links_root = pin_root.join("links");
            if !pin_root.exists() {
                fs::create_dir_all(pin_root).context(IoSnafu {
                    action: "create pin root",
                    path: pin_root,
                })?;
                rollback.directories.push(pin_root.clone());
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
            _lease: lease,
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
        lease: PinRootLease,
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
        ensure!(
            directory_entry_names(&maps_root)? == expected_maps
                && directory_entry_names(&links_root)? == expected_links,
            StalePinRootSnafu { path: pin_root }
        );

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
            let new_program = object
                .progs()
                .find(|program| program.name().to_string_lossy() == name)
                .ok_or_else(|| {
                    ManifestMismatchSnafu {
                        path: self.config.object_path(),
                        reason: format!("recovery object has no program `{name}`"),
                    }
                    .build()
                })?;
            let new_program_id = Program::id_from_fd(new_program.as_fd()).context(LibbpfSnafu {
                action: "read replacement BPF program ID",
                path: self.config.object_path(),
            })?;
            let new_program = ProgramHandle::from_prog_id(new_program_id).context(LibbpfSnafu {
                action: "read replacement BPF program",
                path: self.config.object_path(),
            })?;
            ensure!(
                old_program.tag() == new_program.tag(),
                ManifestMismatchSnafu {
                    path: &path,
                    reason: format!("pinned program `{name}` does not match the configured object"),
                }
            );
            link_records.push(KernelLinkManifestV1 {
                program: name.to_owned(),
                link_id: info.id,
                program_id: info.prog_id,
                pin_path: Some(path),
            });
            links.push(link);
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
            _lease: lease,
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

    pub fn preflight(&self) -> Result<KernelPreflightV1> {
        self.validate_config()?;
        let platform = KernelPlatformProbe::inspect(&self.config.runtime_btf_path)?;
        let lsm_path = Path::new("/sys/kernel/security/lsm");
        ensure!(
            platform.bpf_lsm_active,
            InvalidConfigurationSnafu {
                path: lsm_path,
                reason: "BPF LSM is not active".to_owned(),
            }
        );
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

    fn validate_program_set(&self, programs: &[KernelProgramLayoutV1]) -> Result<()> {
        let actual = programs
            .iter()
            .filter(|program| {
                self.config
                    .object_kind
                    .includes(&program.name, &program.section)
            })
            .map(|program| program.name.as_str())
            .collect::<BTreeSet<_>>();
        let expected = self
            .config
            .object_kind
            .required_programs()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
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
        let actual = links
            .iter()
            .map(|link| link.program.as_str())
            .collect::<BTreeSet<_>>();
        let expected = self
            .config
            .object_kind
            .required_programs()
            .iter()
            .copied()
            .filter(|name| self.config.object_kind.attaches_name(name))
            .collect::<BTreeSet<_>>();
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

impl KernelHost {
    #[must_use]
    pub const fn manifest(&self) -> &KernelObjectManifestV1 {
        &self.manifest
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

    pub fn delete_map_entry(&self, name: &str, key: &[u8]) -> Result<()> {
        let map = self.map(name)?;
        map.delete(key).context(LibbpfSnafu {
            action: "delete BPF map entry",
            path: Path::new(name),
        })
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

    pub fn shutdown(mut self) -> Result<()> {
        if self.remove_pins_on_shutdown {
            self.remove_pins()?;
        }
        self.links.clear();
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
    use snafu::ResultExt as _;
    use std::fs;

    use super::{
        KernelHostConfig, KernelHostOwner, KernelObjectKind, KernelProgramLayoutV1, PinRollback,
        REQUIRED_QUALIFICATION_LSM_PROGRAMS,
    };
    use crate::error::IoSnafu;
    use crate::BUNDLED_BPF_OBJECT;

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
        let programs = REQUIRED_QUALIFICATION_LSM_PROGRAMS[..20]
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
    fn identity_program_selection_includes_lifecycle_hooks_but_not_the_iterator_link() {
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
