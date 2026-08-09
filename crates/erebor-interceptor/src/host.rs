use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use libbpf_rs::{Link, MapCore as _, MapFlags, MapHandle, Object, ObjectBuilder, ProgramType};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{
    InvalidConfigurationSnafu, IoSnafu, LibbpfSnafu, ManifestMismatchSnafu, StalePinRootSnafu,
};
use crate::lease::PinRootLease;
use crate::{
    KernelLinkManifestV1, KernelMapLayoutV1, KernelMapManifestV1, KernelObjectLayoutV1,
    KernelObjectManifestV1, KernelPlatformProbe, KernelPreflightV1, KernelProgramLayoutV1, Result,
};

pub const REQUIRED_CHASSIS_LSM_PROGRAMS: [&str; 21] = [
    "phase0_task_alloc",
    "phase0_file_open",
    "phase0_bprm_check_security",
    "phase0_file_permission",
    "phase0_file_ioctl",
    "phase0_mmap_file",
    "phase0_file_mprotect",
    "phase0_ipc_permission",
    "phase0_socket_connect",
    "phase0_socket_sendmsg",
    "phase0_ptrace_access_check",
    "phase0_task_kill",
    "phase0_path_unlink",
    "phase0_path_link",
    "phase0_path_rename",
    "phase0_sb_mount",
    "phase0_sb_umount",
    "phase0_sb_pivotroot",
    "phase0_move_mount",
    "phase0_capable",
    "phase0_bpf",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelHostConfig {
    pub object_path: PathBuf,
    pub expected_object_sha256: String,
    pub runtime_btf_path: PathBuf,
    pub lease_path: PathBuf,
    pub pin_root: Option<PathBuf>,
    pub node_boot_id: String,
    pub label_epoch: u64,
}

impl KernelHostConfig {
    #[must_use]
    pub fn new(
        object_path: impl Into<PathBuf>,
        expected_object_sha256: impl Into<String>,
        runtime_btf_path: impl Into<PathBuf>,
        lease_path: impl Into<PathBuf>,
        pin_root: Option<PathBuf>,
        node_boot_id: impl Into<String>,
        label_epoch: u64,
    ) -> Self {
        Self {
            object_path: object_path.into(),
            expected_object_sha256: expected_object_sha256.into(),
            runtime_btf_path: runtime_btf_path.into(),
            lease_path: lease_path.into(),
            pin_root,
            node_boot_id: node_boot_id.into(),
            label_epoch,
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
        let open = ObjectBuilder::default()
            .open_file(&self.config.object_path)
            .context(LibbpfSnafu {
                action: "inspect BPF object",
                path: &self.config.object_path,
            })?;
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

    pub fn start(&self) -> Result<KernelHost> {
        self.validate_config()?;
        let preflight = self.preflight()?;
        let object_sha256 = self.object_sha256()?;
        ensure!(
            object_sha256 == self.config.expected_object_sha256,
            ManifestMismatchSnafu {
                path: &self.config.object_path,
                reason: format!(
                    "object digest is {object_sha256}, expected {}",
                    self.config.expected_object_sha256
                ),
            }
        );
        let _layout = self.inspect()?;
        let lease = PinRootLease::acquire(&self.config.lease_path)?;
        if let Some(pin_root) = &self.config.pin_root {
            self.prepare_empty_pin_root(pin_root)?;
        }

        let mut builder = ObjectBuilder::default();
        builder
            .btf_custom_path(&self.config.runtime_btf_path)
            .context(LibbpfSnafu {
                action: "set runtime BTF",
                path: &self.config.runtime_btf_path,
            })?;
        let mut object = builder
            .open_file(&self.config.object_path)
            .context(LibbpfSnafu {
                action: "open BPF object",
                path: &self.config.object_path,
            })?
            .load()
            .context(LibbpfSnafu {
                action: "load BPF object",
                path: &self.config.object_path,
            })?;

        let mut links = Vec::with_capacity(REQUIRED_CHASSIS_LSM_PROGRAMS.len());
        let mut link_records = Vec::with_capacity(REQUIRED_CHASSIS_LSM_PROGRAMS.len());
        for program in object.progs_mut() {
            if !program.section().to_string_lossy().starts_with("lsm/") {
                continue;
            }
            ensure!(
                program.prog_type() == ProgramType::Lsm,
                ManifestMismatchSnafu {
                    path: &self.config.object_path,
                    reason: format!(
                        "program `{}` has an LSM section but type {:?}",
                        program.name().to_string_lossy(),
                        program.prog_type()
                    ),
                }
            );
            let name = program.name().to_string_lossy().into_owned();
            let link = program.attach_lsm().context(LibbpfSnafu {
                action: "attach LSM program",
                path: &self.config.object_path,
            })?;
            let info = link.info().context(LibbpfSnafu {
                action: "read attached LSM link",
                path: &self.config.object_path,
            })?;
            ensure!(
                info.id != 0 && info.prog_id != 0,
                ManifestMismatchSnafu {
                    path: &self.config.object_path,
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
                    path: &self.config.object_path,
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
        ensure!(
            self.config.object_path.is_file(),
            InvalidConfigurationSnafu {
                path: &self.config.object_path,
                reason: "BPF object is not a regular file".to_owned(),
            }
        );
        ensure!(
            self.config.runtime_btf_path.is_file(),
            InvalidConfigurationSnafu {
                path: &self.config.runtime_btf_path,
                reason: "runtime BTF is not a regular file".to_owned(),
            }
        );
        ensure!(
            self.config.expected_object_sha256.len() == 64
                && self
                    .config
                    .expected_object_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            InvalidConfigurationSnafu {
                path: &self.config.object_path,
                reason: "expected object digest must be lowercase SHA-256 hex".to_owned(),
            }
        );
        ensure!(
            !self.config.node_boot_id.is_empty() && self.config.label_epoch > 0,
            InvalidConfigurationSnafu {
                path: &self.config.object_path,
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
        let bytes = fs::read(&self.config.object_path).context(IoSnafu {
            action: "read BPF object",
            path: &self.config.object_path,
        })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn prepare_empty_pin_root(&self, pin_root: &Path) -> Result<()> {
        if pin_root.exists() {
            let mut entries = fs::read_dir(pin_root).context(IoSnafu {
                action: "inspect pin root",
                path: pin_root,
            })?;
            ensure!(
                entries.next().is_none(),
                StalePinRootSnafu { path: pin_root }
            );
        }
        Ok(())
    }

    fn validate_program_set(&self, programs: &[KernelProgramLayoutV1]) -> Result<()> {
        let actual = programs
            .iter()
            .filter(|program| program.section.starts_with("lsm/"))
            .map(|program| program.name.as_str())
            .collect::<BTreeSet<_>>();
        let expected = REQUIRED_CHASSIS_LSM_PROGRAMS
            .into_iter()
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            ManifestMismatchSnafu {
                path: &self.config.object_path,
                reason: format!("LSM program set is {actual:?}, expected {expected:?}"),
            }
        );
        Ok(())
    }

    fn validate_attached_set(&self, links: &[KernelLinkManifestV1]) -> Result<()> {
        let actual = links
            .iter()
            .map(|link| link.program.as_str())
            .collect::<BTreeSet<_>>();
        let expected = REQUIRED_CHASSIS_LSM_PROGRAMS
            .into_iter()
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            ManifestMismatchSnafu {
                path: &self.config.object_path,
                reason: format!("attached LSM program set is {actual:?}, expected {expected:?}"),
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

    pub fn update_map(&self, name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let map = self
            .object
            .maps()
            .find(|map| map.name().to_string_lossy() == name)
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from(name),
                    reason: "loaded object has no such map".to_owned(),
                }
                .build()
            })?;
        map.update(key, value, MapFlags::ANY).context(LibbpfSnafu {
            action: "update BPF map",
            path: Path::new(name),
        })
    }

    pub fn lookup_map(&self, name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let map = self
            .object
            .maps()
            .find(|map| map.name().to_string_lossy() == name)
            .ok_or_else(|| {
                ManifestMismatchSnafu {
                    path: PathBuf::from(name),
                    reason: "loaded object has no such map".to_owned(),
                }
                .build()
            })?;
        map.lookup(key, MapFlags::ANY).context(LibbpfSnafu {
            action: "read BPF map",
            path: Path::new(name),
        })
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.remove_pins()?;
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
        while let Some(path) = self.pinned_paths.pop() {
            let _result = fs::remove_file(path);
        }
        while let Some(path) = self.pinned_directories.pop() {
            let _result = fs::remove_dir(path);
        }
        self.links.clear();
    }
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
        KernelHostConfig, KernelHostOwner, KernelProgramLayoutV1, PinRollback,
        REQUIRED_CHASSIS_LSM_PROGRAMS,
    };
    use crate::error::IoSnafu;

    #[test]
    fn missing_required_hook_cannot_validate() {
        let owner = KernelHostOwner::new(KernelHostConfig::new(
            "object",
            "0".repeat(64),
            "btf",
            "lease",
            None,
            "boot",
            1,
        ));
        let programs = REQUIRED_CHASSIS_LSM_PROGRAMS[..20]
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
