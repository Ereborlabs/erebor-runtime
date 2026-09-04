#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ExactFileMeasurementV1, MAX_CANONICAL_COMPONENT_BYTES_V1, MAX_CANONICAL_PATH_COMPONENTS_V1,
};
use rustix::fs::{openat, openat2, statx, AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};
use uuid::Uuid;

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu};
use crate::{ExactDeviceConfig, ExactDeviceType, ExactFileObjectConfig, Result};

const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
const STATX_MNT_ID: u32 = 0x0000_1000;
const MAXIMUM_OCI_CONFIG_BYTES: u64 = 1_048_576;

pub struct ExactFileObjectResolver;

pub(crate) struct ExactFileObjectView {
    root_pid: u32,
    process: File,
    mount_namespace: File,
    mountinfo: File,
    root: File,
    namespace_root_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct OciRuntimeConfigV1 {
    root: OciRuntimeRootV1,
}

#[derive(Deserialize)]
struct OciRuntimeRootV1 {
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveExactFileObjectV1 {
    pub mount_namespace_inode: u32,
    pub mount_id: u32,
    pub mount_id_unique: u64,
    pub filesystem_device: u32,
    pub inode: u64,
    pub inode_generation: u64,
    pub mode: u16,
    pub device_type: Option<ExactDeviceType>,
    pub device_major: u32,
    pub device_minor: u32,
    pub canonical_component_hex: Vec<String>,
    pub mount_relative_component_count: u16,
    pub mount_root_filesystem_device: u32,
    pub mount_root_inode: u64,
    pub selected_mount_id_unique: u64,
    pub mount_snapshot_digest_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveMountRootRouteV1 {
    pub mount_namespace_inode: u32,
    pub mountpoint_components: Vec<Vec<u8>>,
    pub filesystem_device: u32,
    pub root_inode: u64,
    pub selected_mount_id_unique: u64,
    pub mount_snapshot_digest_id: u64,
}

impl LiveMountRootRouteV1 {
    fn from_mounts(
        mounts: &[LiveMount],
        mount_namespace_inode: u32,
        mount_snapshot_digest_id: u64,
    ) -> Result<Vec<Self>> {
        let mut routes = Vec::new();
        for mount in mounts {
            let selected_mount_id_unique = mounts
                .iter()
                .filter(|candidate| {
                    candidate.filesystem_device == mount.filesystem_device
                        && candidate.inode == mount.inode
                })
                .map(|candidate| candidate.mount_id_unique)
                .min()
                .ok_or_else(|| {
                    IdentityStateSnafu {
                        reason: "mount route has no represented source root".to_owned(),
                    }
                    .build()
                })?;
            let represented_paths = mounts
                .iter()
                .filter(|source| {
                    source.filesystem_device == mount.filesystem_device
                        && mount.root.starts_with(&source.root)
                })
                .map(|source| {
                    mount
                        .root
                        .strip_prefix(&source.root)
                        .map(|relative| source.mountpoint.join(relative))
                        .map_err(|error| {
                            IdentityStateSnafu {
                                reason: format!(
                                    "mount route is outside its represented source: {error}"
                                ),
                            }
                            .build()
                        })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            for represented_path in represented_paths {
                routes.push(Self {
                    mount_namespace_inode,
                    mountpoint_components: path_components(&represented_path)?,
                    filesystem_device: mount.filesystem_device,
                    root_inode: mount.inode,
                    selected_mount_id_unique,
                    mount_snapshot_digest_id,
                });
            }
        }
        Ok(routes)
    }
}

impl ExactFileObjectResolver {
    pub fn resolve(
        root_pid: u32,
        path: &Path,
        profile_generation_ref_id: u64,
        exact_object_key_id: u64,
        object_class_id: String,
        inode_generation: u64,
        device_class_id: Option<String>,
    ) -> Result<ExactFileObjectConfig> {
        ExactFileObjectView::acquire(root_pid)?.resolve(
            path,
            profile_generation_ref_id,
            exact_object_key_id,
            object_class_id,
            inode_generation,
            device_class_id,
        )
    }
}

impl ExactFileObjectView {
    pub(crate) fn acquire(root_pid: u32) -> Result<Self> {
        ensure!(
            root_pid > 0,
            IdentityStateSnafu {
                reason: "exact file resolution needs a live root PID",
            }
        );
        let process_path = PathBuf::from(format!("/proc/{root_pid}"));
        let process = File::open(&process_path).context(IoSnafu {
            path: &process_path,
        })?;
        let mount_namespace = open_process_file(&process, root_pid, "ns/mnt")?;
        let mountinfo = open_process_file(&process, root_pid, "mountinfo")?;
        let root = open_process_file(&process, root_pid, "root")?;
        let final_mount_namespace = open_process_file(&process, root_pid, "ns/mnt")?;
        let final_root = open_process_file(&process, root_pid, "root")?;
        ensure!(
            mount_namespace
                .metadata()
                .context(IoSnafu {
                    path: Path::new("held mount namespace"),
                })?
                .ino()
                == final_mount_namespace
                    .metadata()
                    .context(IoSnafu {
                        path: Path::new("rechecked mount namespace"),
                    })?
                    .ino()
                && same_root(&root, &final_root)?,
            IdentityStateSnafu {
                reason: "task mount namespace or root changed while its view was acquired",
            }
        );
        Ok(Self {
            root_pid,
            process,
            mount_namespace,
            mountinfo,
            root,
            namespace_root_path: None,
        })
    }

    pub(crate) fn mount_namespace_inode(&self) -> Result<u32> {
        self.mount_namespace
            .metadata()
            .context(IoSnafu {
                path: Path::new("held mount namespace"),
            })?
            .ino()
            .try_into()
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("mount namespace inode exceeds its Linux u32 ABI: {error}"),
                }
                .build()
            })
    }

    pub(crate) fn has_host_root(&self) -> Result<bool> {
        let host_root = File::open("/").context(IoSnafu {
            path: Path::new("/"),
        })?;
        let held = self.root.metadata().context(IoSnafu {
            path: Path::new("held task root"),
        })?;
        let host = host_root.metadata().context(IoSnafu {
            path: Path::new("/"),
        })?;
        Ok(held.dev() == host.dev() && held.ino() == host.ino())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve(
        &self,
        path: &Path,
        profile_generation_ref_id: u64,
        exact_object_key_id: u64,
        object_class_id: String,
        inode_generation: u64,
        device_class_id: Option<String>,
    ) -> Result<ExactFileObjectConfig> {
        let live = self.inspect(path)?;
        let device = live.device_type.map(|device_type| ExactDeviceConfig {
            device_class_id: device_class_id.clone().unwrap_or_default(),
            device_type,
            major: live.device_major,
            minor: live.device_minor,
        });
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact file resolution needs an absolute in-namespace path",
            }
        );
        ensure!(
            live.mount_namespace_inode > 0
                && (inode_generation > 0 || device.is_some())
                && device.is_some() == device_class_id.is_some()
                && device_class_id.as_ref().is_none_or(|id| !id.is_empty()),
            IdentityStateSnafu {
                reason: "device objects need one nonempty device class; non-device objects need a nonzero inode generation",
            }
        );
        Ok(ExactFileObjectConfig {
            profile_generation_ref_id,
            exact_object_key_id,
            object_class_id,
            mount_namespace_inode: live.mount_namespace_inode,
            mount_id_unique: live.mount_id_unique,
            filesystem_device: live.filesystem_device,
            inode: live.inode,
            inode_generation,
            device,
            canonical_component_hex: live.canonical_component_hex,
            mount_relative_component_count: live.mount_relative_component_count,
            mount_root_filesystem_device: live.mount_root_filesystem_device,
            mount_root_inode: live.mount_root_inode,
            selected_mount_id_unique: live.selected_mount_id_unique,
            mount_snapshot_digest_id: live.mount_snapshot_digest_id,
            mount_topology_generation: 1,
            mount_view_root_pid: self.root_pid,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_resolve_signed_selector(
        &self,
        host: &KernelHost,
        path: &Path,
        profile_generation_ref_id: u64,
        path_selector_handle: u64,
        object_class_id: String,
        device_class_id: Option<String>,
        mount_topology_generation: u64,
    ) -> Result<Option<ExactFileObjectConfig>> {
        let Some(live) = self.try_inspect(host, path)? else {
            return Ok(None);
        };
        let device = live.device_type.map(|device_type| ExactDeviceConfig {
            device_class_id: device_class_id.clone().unwrap_or_default(),
            device_type,
            major: live.device_major,
            minor: live.device_minor,
        });
        ensure!(
            live.mount_namespace_inode > 0
                && mount_topology_generation > 0
                && (live.inode_generation > 0 || device.is_some())
                && device.is_some() == device_class_id.is_some()
                && device_class_id.as_ref().is_none_or(|id| !id.is_empty()),
            IdentityStateSnafu {
                reason: "signed path selector did not resolve to the required exact object kind",
            }
        );
        Ok(Some(ExactFileObjectConfig {
            profile_generation_ref_id,
            exact_object_key_id: path_selector_handle,
            object_class_id,
            mount_namespace_inode: live.mount_namespace_inode,
            mount_id_unique: live.mount_id_unique,
            filesystem_device: live.filesystem_device,
            inode: live.inode,
            inode_generation: live.inode_generation,
            device,
            canonical_component_hex: live.canonical_component_hex,
            mount_relative_component_count: live.mount_relative_component_count,
            mount_root_filesystem_device: live.mount_root_filesystem_device,
            mount_root_inode: live.mount_root_inode,
            selected_mount_id_unique: live.selected_mount_id_unique,
            mount_snapshot_digest_id: live.mount_snapshot_digest_id,
            mount_topology_generation,
            mount_view_root_pid: self.root_pid,
        }))
    }

    pub(crate) fn inspect(&self, path: &Path) -> Result<LiveExactFileObjectV1> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact file resolution needs an absolute in-namespace path",
            }
        );
        let file = self.open_path(path)?;
        self.inspect_file(path, &file, None)
    }

    pub(crate) fn mount_root_routes(&self) -> Result<Vec<LiveMountRootRouteV1>> {
        let first = self.read_mountinfo()?;
        let entries = self.mount_entries(&first)?;
        let mounts = entries
            .iter()
            .map(|entry| LiveMount::read(&self.root, entry))
            .collect::<Result<Vec<_>>>()?;
        let second = self.read_mountinfo()?;
        ensure!(
            first == second,
            IdentityStateSnafu {
                reason: "mount topology changed while its route snapshot was built",
            }
        );
        let snapshot_digest_id = MountInfoSnapshot::digest(&first)?;
        let mount_namespace_inode = self.mount_namespace_inode()?;
        LiveMountRootRouteV1::from_mounts(&mounts, mount_namespace_inode, snapshot_digest_id)
    }

    pub(crate) fn try_inspect(
        &self,
        host: &KernelHost,
        path: &Path,
    ) -> Result<Option<LiveExactFileObjectV1>> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact file resolution needs an absolute in-namespace path",
            }
        );
        let pid_tgid = current_pid_tgid()?;
        let request_nonce = measurement_nonce();
        host.stage_exact_file_measurement(pid_tgid, request_nonce)
            .context(InterceptorSnafu)?;
        let file = match self.try_open_path(path) {
            Ok(Some(file)) => file,
            Ok(None) => {
                host.discard_exact_file_measurement(pid_tgid)
                    .context(InterceptorSnafu)?;
                return Ok(None);
            }
            Err(error) => {
                host.discard_exact_file_measurement(pid_tgid)
                    .context(InterceptorSnafu)?;
                return Err(error);
            }
        };
        let measurement = host
            .take_exact_file_measurement(pid_tgid, request_nonce)
            .context(InterceptorSnafu)?;
        self.inspect_file(path, &file, Some(measurement)).map(Some)
    }

    fn inspect_file(
        &self,
        path: &Path,
        file: &File,
        measurement: Option<ExactFileMeasurementV1>,
    ) -> Result<LiveExactFileObjectV1> {
        let mount_namespace_inode = self.mount_namespace_inode()?;
        let unique_mount = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
        let status = statx(
            file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | unique_mount,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path })?;
        ensure!(
            status.stx_mask & STATX_MNT_ID_UNIQUE != 0
                && status.stx_mnt_id > 0
                && status.stx_ino > 0,
            IdentityStateSnafu {
                reason: "kernel/filesystem did not return STATX_MNT_ID_UNIQUE and an inode",
            }
        );
        let device_type = match u32::from(status.stx_mode) & 0o170_000 {
            0o020_000 => Some(ExactDeviceType::Character),
            0o060_000 => Some(ExactDeviceType::Block),
            _ => None,
        };
        let filesystem_device = encoded_device(status.stx_dev_major, status.stx_dev_minor)?;
        let inode_generation = match measurement {
            Some(measurement) => {
                ensure!(
                    measurement.mount_namespace_inode == mount_namespace_inode
                        && measurement.mount_id_unique == status.stx_mnt_id
                        && measurement.filesystem_device == filesystem_device
                        && measurement.inode == status.stx_ino
                        && (measurement.inode_generation > 0 || device_type.is_some()),
                    IdentityStateSnafu {
                        reason: format!(
                            "kernel measurement differs from the exact object opened for `{}`",
                            path.display()
                        ),
                    }
                );
                erebor_telemetry::trace!(
                    "measured an exact file object",
                    measurement_source = %"bpf_file_open",
                    mount_namespace_inode = %mount_namespace_inode,
                    mount_id_unique = %status.stx_mnt_id,
                    inode = %status.stx_ino,
                    inode_generation = %measurement.inode_generation
                );
                measurement.inode_generation
            }
            None => 0,
        };
        let mount_snapshot = MountInfoSnapshot::read(self, path)?;
        Ok(LiveExactFileObjectV1 {
            mount_namespace_inode,
            mount_id: mount_snapshot.entered_mount_id,
            mount_id_unique: status.stx_mnt_id,
            filesystem_device,
            inode: status.stx_ino,
            inode_generation,
            mode: status.stx_mode,
            device_type,
            device_major: status.stx_rdev_major,
            device_minor: status.stx_rdev_minor,
            canonical_component_hex: mount_snapshot
                .canonical_components
                .iter()
                .map(hex::encode)
                .collect(),
            mount_relative_component_count: mount_snapshot
                .relative_component_count
                .try_into()
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("mount-relative component count overflow: {error}"),
                    }
                    .build()
                })?,
            mount_root_filesystem_device: mount_snapshot.root_filesystem_device,
            mount_root_inode: mount_snapshot.root_inode,
            selected_mount_id_unique: mount_snapshot.selected_mount_id_unique,
            mount_snapshot_digest_id: mount_snapshot.snapshot_digest_id,
        })
    }

    fn open_path(&self, path: &Path) -> Result<File> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact object path is not absolute",
            }
        );
        openat2(
            &self.root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .context(IoSnafu { path })
    }

    fn try_open_path(&self, path: &Path) -> Result<Option<File>> {
        match openat2(
            &self.root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        ) {
            Ok(file) => Ok(Some(File::from(file))),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => Ok(None),
            Err(error) => Err(std::io::Error::from(error)).context(IoSnafu { path }),
        }
    }

    fn read_mountinfo(&self) -> Result<Vec<u8>> {
        let path = PathBuf::from(format!("held /proc/{}/mountinfo", self.root_pid));
        let read = |file: &File| {
            let mut file = file;
            file.seek(SeekFrom::Start(0))
                .context(IoSnafu { path: &path })?;
            let mut source = Vec::new();
            file.read_to_end(&mut source)
                .context(IoSnafu { path: &path })?;
            Ok(source)
        };
        match open_process_file(&self.process, self.root_pid, "mountinfo") {
            Ok(file) => read(&file),
            Err(crate::Error::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound
                    || source.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
                    || source.raw_os_error() == Some(rustix::io::Errno::INVAL.raw_os_error()) =>
            {
                read(&self.mountinfo)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn retained_mountinfo_is_readable_for_test(&self) -> Result<bool> {
        Ok(!parse_mountinfo(&self.read_mountinfo()?)?.is_empty())
    }

    fn mount_entries(&self, source: &[u8]) -> Result<Vec<MountInfoEntry>> {
        let entries = parse_mountinfo(source)?;
        let Some(namespace_root_path) = &self.namespace_root_path else {
            return Ok(entries);
        };
        let root_mount_id = MountInfoEntry::mount_id_for(&self.root)?;
        Self::rebase_mount_entries(&entries, namespace_root_path, root_mount_id)
    }

    fn rebase_mount_entries(
        entries: &[MountInfoEntry],
        namespace_root_path: &Path,
        root_mount_id: u32,
    ) -> Result<Vec<MountInfoEntry>> {
        let root_mount = entries
            .iter()
            .find(|entry| entry.mount_id == root_mount_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "OCI root mount is absent from the held mountinfo view".to_owned(),
                }
                .build()
            })?;
        let relative_root = namespace_root_path
            .strip_prefix(&root_mount.mountpoint)
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("OCI root is outside its mountinfo entry: {error}"),
                }
                .build()
            })?;
        let mut rebased = vec![MountInfoEntry {
            mount_id: root_mount.mount_id,
            parent_mount_id: root_mount.mount_id,
            root: root_mount.root.join(relative_root),
            mountpoint: PathBuf::from("/"),
            device: root_mount.device.clone(),
        }];
        for entry in entries {
            if entry.mount_id == root_mount_id {
                continue;
            }
            let Ok(relative) = entry.mountpoint.strip_prefix(namespace_root_path) else {
                continue;
            };
            rebased.push(MountInfoEntry {
                mount_id: entry.mount_id,
                parent_mount_id: entry.parent_mount_id,
                root: entry.root.clone(),
                mountpoint: Path::new("/").join(relative),
                device: entry.device.clone(),
            });
        }
        Ok(rebased)
    }
}

impl ExactFileObjectView {
    pub(crate) fn acquire_oci(root_pid: u32, bundle: &Path) -> Result<Self> {
        ensure!(
            root_pid > 0 && clean_absolute_path(bundle),
            IdentityStateSnafu {
                reason: "OCI entry resolution needs a live root PID and a clean absolute bundle",
            }
        );
        let process_path = PathBuf::from(format!("/proc/{root_pid}"));
        let process = File::open(&process_path).context(IoSnafu {
            path: &process_path,
        })?;
        let mount_namespace = open_process_file(&process, root_pid, "ns/mnt")?;
        let mountinfo = open_process_file(&process, root_pid, "mountinfo")?;
        let process_root = open_process_file(&process, root_pid, "root")?;
        let bundle_directory = openat2(
            &process_root,
            bundle,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: bundle })?;
        let config_path = bundle.join("config.json");
        let config_file = openat2(
            &bundle_directory,
            "config.json",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: &config_path })?;
        let mut bytes = Vec::new();
        config_file
            .take(MAXIMUM_OCI_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .context(IoSnafu { path: &config_path })?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAXIMUM_OCI_CONFIG_BYTES as usize,
            IdentityStateSnafu {
                reason: "OCI runtime config exceeds its byte limit",
            }
        );
        let config: OciRuntimeConfigV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: &config_path })?;
        ensure!(
            clean_oci_root_path(&config.root.path),
            IdentityStateSnafu {
                reason: "OCI runtime root path is not clean and bounded",
            }
        );
        let namespace_root_path = if config.root.path.is_absolute() {
            config.root.path.clone()
        } else {
            bundle.join(&config.root.path)
        };
        let open_root = || {
            let (directory, flags) = if config.root.path.is_absolute() {
                (
                    &process_root,
                    ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
                )
            } else {
                (
                    &bundle_directory,
                    ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
                )
            };
            openat2(
                directory,
                &config.root.path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
                Mode::empty(),
                flags,
            )
            .map(File::from)
            .map_err(std::io::Error::from)
            .context(IoSnafu {
                path: &config.root.path,
            })
        };
        let root = open_root()?;
        let final_mount_namespace = open_process_file(&process, root_pid, "ns/mnt")?;
        let final_process_root = open_process_file(&process, root_pid, "root")?;
        let final_root = open_root()?;
        ensure!(
            mount_namespace
                .metadata()
                .context(IoSnafu {
                    path: Path::new("held mount namespace"),
                })?
                .ino()
                == final_mount_namespace
                    .metadata()
                    .context(IoSnafu {
                        path: Path::new("rechecked mount namespace"),
                    })?
                    .ino()
                && same_root(&process_root, &final_process_root)?
                && same_root(&root, &final_root)?,
            IdentityStateSnafu {
                reason: "task mount namespace, process root, or OCI root changed while its view was acquired",
            }
        );
        let host_root = File::open("/").context(IoSnafu {
            path: Path::new("/"),
        })?;
        ensure!(
            !same_root(&root, &host_root)?,
            IdentityStateSnafu {
                reason: "OCI runtime config selected the host root",
            }
        );
        Ok(Self {
            root_pid,
            process,
            mount_namespace,
            mountinfo,
            root,
            namespace_root_path: Some(namespace_root_path),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_resolve_declared_entry(
        &self,
        host: &KernelHost,
        path: &Path,
        profile_generation_ref_id: u64,
        path_selector_handle: u64,
        object_class_id: String,
        mount_topology_generation: u64,
    ) -> Result<Option<ExactFileObjectConfig>> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "declared entry resolution needs an absolute container path",
            }
        );
        let pid_tgid = current_pid_tgid()?;
        let request_nonce = measurement_nonce();
        host.stage_exact_file_measurement(pid_tgid, request_nonce)
            .context(InterceptorSnafu)?;
        let file = match openat2(
            &self.root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                host.discard_exact_file_measurement(pid_tgid)
                    .context(InterceptorSnafu)?;
                return Ok(None);
            }
            Err(error) => {
                host.discard_exact_file_measurement(pid_tgid)
                    .context(InterceptorSnafu)?;
                return Err(error.into()).context(IoSnafu { path });
            }
        };
        let measurement = host
            .take_exact_file_measurement(pid_tgid, request_nonce)
            .context(InterceptorSnafu)?;
        let unique_mount = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
        let status = statx(
            &file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | unique_mount,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path })?;
        let filesystem_device = encoded_device(status.stx_dev_major, status.stx_dev_minor)?;
        let mount_namespace_inode = self.mount_namespace_inode()?;
        let mode = u32::from(status.stx_mode);
        ensure!(
            status.stx_mask & STATX_MNT_ID_UNIQUE != 0
                && status.stx_mnt_id > 0
                && status.stx_ino > 0
                && mode & 0o170_000 == 0o100_000
                && mode & 0o111 != 0
                && measurement.mount_namespace_inode == mount_namespace_inode
                && measurement.mount_id_unique == status.stx_mnt_id
                && measurement.filesystem_device == filesystem_device
                && measurement.inode == status.stx_ino
                && measurement.inode_generation > 0,
            IdentityStateSnafu {
                reason: format!(
                    "declared entry `{}` is not one measured executable object in the container root",
                    path.display()
                ),
            }
        );
        let root_status = statx(
            &self.root,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | unique_mount,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: Path::new("held OCI root"),
        })?;
        let components = path_components(path)?;
        ensure!(
            !components.is_empty()
                && components.len() <= MAX_CANONICAL_PATH_COMPONENTS_V1
                && path_selector_handle > 0
                && profile_generation_ref_id > 0
                && mount_topology_generation > 0,
            IdentityStateSnafu {
                reason: "declared entry proof is not canonical and bounded",
            }
        );
        Ok(Some(ExactFileObjectConfig {
            profile_generation_ref_id,
            exact_object_key_id: path_selector_handle,
            object_class_id,
            mount_namespace_inode,
            mount_id_unique: status.stx_mnt_id,
            filesystem_device,
            inode: status.stx_ino,
            inode_generation: measurement.inode_generation,
            device: None,
            canonical_component_hex: components.iter().map(hex::encode).collect(),
            mount_relative_component_count: components.len() as u16,
            mount_root_filesystem_device: encoded_device(
                root_status.stx_dev_major,
                root_status.stx_dev_minor,
            )?,
            mount_root_inode: root_status.stx_ino,
            selected_mount_id_unique: root_status.stx_mnt_id,
            mount_snapshot_digest_id: 0,
            mount_topology_generation,
            mount_view_root_pid: self.root_pid,
        }))
    }
}

fn clean_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && (1..=4_096).contains(&path.as_os_str().as_bytes().len())
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn clean_oci_root_path(path: &Path) -> bool {
    (1..=4_096).contains(&path.as_os_str().as_bytes().len())
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn current_pid_tgid() -> Result<u64> {
    let pid = u32::try_from(rustix::process::getpid().as_raw_pid()).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("process ID exceeds the Linux u32 ABI: {error}"),
        }
        .build()
    })?;
    let tid = u32::try_from(rustix::thread::gettid().as_raw_pid()).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("thread ID exceeds the Linux u32 ABI: {error}"),
        }
        .build()
    })?;
    Ok((u64::from(pid) << 32) | u64::from(tid))
}

fn measurement_nonce() -> u64 {
    let uuid = Uuid::new_v4();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&uuid.as_bytes()[..8]);
    u64::from_le_bytes(bytes).max(1)
}

struct MountInfoSnapshot {
    entered_mount_id: u32,
    canonical_components: Vec<Vec<u8>>,
    relative_component_count: usize,
    root_filesystem_device: u32,
    root_inode: u64,
    selected_mount_id_unique: u64,
    snapshot_digest_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfoEntry {
    mount_id: u32,
    parent_mount_id: u32,
    root: PathBuf,
    mountpoint: PathBuf,
    device: String,
}

impl MountInfoSnapshot {
    fn digest(source: &[u8]) -> Result<u64> {
        let digest = Sha256::digest(source);
        let snapshot_digest_id = u64::from_le_bytes(digest[..8].try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("mount snapshot digest conversion failed: {error}"),
            }
            .build()
        })?);
        ensure!(
            snapshot_digest_id > 0,
            IdentityStateSnafu {
                reason: "mount snapshot produced the reserved zero digest handle",
            }
        );
        Ok(snapshot_digest_id)
    }

    fn read(view: &ExactFileObjectView, target: &Path) -> Result<Self> {
        let first = view.read_mountinfo()?;
        let entries = view.mount_entries(&first)?;
        let entered = entries
            .iter()
            .filter(|entry| target.starts_with(&entry.mountpoint))
            .max_by_key(|entry| entry.mountpoint.components().count())
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: format!(
                        "target `{}` is outside the represented mount view",
                        target.display()
                    ),
                }
                .build()
            })?;
        let relevant_entries = relevant_mount_entries(&entries, entered.mount_id)?;
        let mounts = relevant_entries
            .iter()
            .map(|entry| LiveMount::read(&view.root, entry))
            .collect::<Result<Vec<_>>>()?;
        let entered = mounts
            .iter()
            .find(|mount| mount.mount_id == entered.mount_id)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "entered mount disappeared from the live snapshot".to_owned(),
                }
                .build()
            })?;
        let relative_path = target.strip_prefix(&entered.mountpoint).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("target is not below entered mountpoint: {error}"),
            }
            .build()
        })?;
        let relative = path_components(relative_path)?;
        let canonical = canonicalize_mount_path(entered.mount_id, relative.clone(), &mounts)?;
        let canonical_components = canonical.components;
        ensure!(
            !canonical_components.is_empty()
                && canonical_components.len() <= MAX_CANONICAL_PATH_COMPONENTS_V1,
            IdentityStateSnafu {
                reason: format!(
                    "canonical path must contain 1..{MAX_CANONICAL_PATH_COMPONENTS_V1} bounded components"
                ),
            }
        );
        let second = view.read_mountinfo()?;
        ensure!(
            first == second,
            IdentityStateSnafu {
                reason: "mount topology changed while its security snapshot was built",
            }
        );
        let snapshot_digest_id = Self::digest(&first)?;
        Ok(Self {
            entered_mount_id: entered.mount_id,
            canonical_components,
            relative_component_count: relative.len(),
            root_filesystem_device: entered.filesystem_device,
            root_inode: entered.inode,
            selected_mount_id_unique: canonical.first_selected_mount_id_unique,
            snapshot_digest_id,
        })
    }
}

fn relevant_mount_entries(
    entries: &[MountInfoEntry],
    entered_mount_id: u32,
) -> Result<Vec<&MountInfoEntry>> {
    let by_id = entries
        .iter()
        .map(|entry| (entry.mount_id, entry))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        by_id.contains_key(&entered_mount_id),
        IdentityStateSnafu {
            reason: "entered mount is outside the mountinfo snapshot",
        }
    );

    let mut pending = vec![entered_mount_id];
    let mut processed = BTreeSet::new();
    let mut relevant = BTreeSet::new();
    while let Some(mount_id) = pending.pop() {
        if !processed.insert(mount_id) {
            continue;
        }
        let Some(current) = by_id.get(&mount_id) else {
            continue;
        };
        for candidate in entries.iter().filter(|candidate| {
            candidate.device == current.device && current.root.starts_with(&candidate.root)
        }) {
            relevant.insert(candidate.mount_id);
            if candidate.parent_mount_id != candidate.mount_id
                && by_id.contains_key(&candidate.parent_mount_id)
            {
                pending.push(candidate.parent_mount_id);
            }
        }
    }

    Ok(entries
        .iter()
        .filter(|entry| relevant.contains(&entry.mount_id))
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiveMount {
    mount_id: u32,
    parent_mount_id: u32,
    root: PathBuf,
    mountpoint: PathBuf,
    filesystem_device: u32,
    inode: u64,
    mount_id_unique: u64,
}

impl MountInfoEntry {
    fn mount_id_for(file: &File) -> Result<u32> {
        let mount_id = StatxFlags::from_bits_retain(STATX_MNT_ID);
        let status = statx(
            file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | mount_id,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: Path::new("held OCI root"),
        })?;
        ensure!(
            status.stx_mask & STATX_MNT_ID != 0 && status.stx_mnt_id > 0,
            IdentityStateSnafu {
                reason: "OCI root lacks a mountinfo-compatible mount ID",
            }
        );
        status.stx_mnt_id.try_into().map_err(|error| {
            IdentityStateSnafu {
                reason: format!("OCI root mount ID exceeds the mountinfo ABI: {error}"),
            }
            .build()
        })
    }
}

impl LiveMount {
    fn read(root: &File, entry: &MountInfoEntry) -> Result<Self> {
        let file = openat2(
            root,
            &entry.mountpoint,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &entry.mountpoint,
        })?;
        let unique_mount = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
        let status = statx(
            &file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | unique_mount,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: &entry.mountpoint,
        })?;
        ensure!(
            status.stx_mask & STATX_MNT_ID_UNIQUE != 0
                && status.stx_mnt_id > 0
                && status.stx_ino > 0,
            IdentityStateSnafu {
                reason: "mount root lacks a unique mount ID or inode",
            }
        );
        Ok(Self {
            mount_id: entry.mount_id,
            parent_mount_id: entry.parent_mount_id,
            root: entry.root.clone(),
            mountpoint: entry.mountpoint.clone(),
            filesystem_device: encoded_device(status.stx_dev_major, status.stx_dev_minor)?,
            inode: status.stx_ino,
            mount_id_unique: status.stx_mnt_id,
        })
    }
}

fn open_process_file(process: &File, root_pid: u32, entry: &str) -> Result<File> {
    let path = PathBuf::from(format!("held /proc/{root_pid}/{entry}"));
    openat(
        process,
        entry,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .context(IoSnafu { path })
}

fn same_root(left: &File, right: &File) -> Result<bool> {
    let flags = StatxFlags::BASIC_STATS | StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
    let left = statx(left, "", AtFlags::EMPTY_PATH, flags)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: Path::new("held task root"),
        })?;
    let right = statx(right, "", AtFlags::EMPTY_PATH, flags)
        .map_err(std::io::Error::from)
        .context(IoSnafu {
            path: Path::new("rechecked task root"),
        })?;
    Ok(left.stx_mask & STATX_MNT_ID_UNIQUE != 0
        && right.stx_mask & STATX_MNT_ID_UNIQUE != 0
        && left.stx_mnt_id == right.stx_mnt_id
        && left.stx_dev_major == right.stx_dev_major
        && left.stx_dev_minor == right.stx_dev_minor
        && left.stx_ino == right.stx_ino)
}

struct CanonicalMountPath {
    components: Vec<Vec<u8>>,
    first_selected_mount_id_unique: u64,
}

fn canonicalize_mount_path(
    entered_mount_id: u32,
    mut components: Vec<Vec<u8>>,
    mounts: &[LiveMount],
) -> Result<CanonicalMountPath> {
    let by_id = mounts
        .iter()
        .map(|mount| (mount.mount_id, mount))
        .collect::<BTreeMap<_, _>>();
    let mut current = *by_id.get(&entered_mount_id).ok_or_else(|| {
        IdentityStateSnafu {
            reason: "entered mount is outside the complete snapshot".to_owned(),
        }
        .build()
    })?;
    let mut first_selected_mount_id_unique = 0;
    let mut visited = BTreeSet::new();
    for _ in 0..mounts.len() {
        ensure!(
            visited.insert(current.mount_id),
            IdentityStateSnafu {
                reason: "mount parent graph contains a cycle",
            }
        );
        let selected = mounts
            .iter()
            .filter(|mount| {
                mount.filesystem_device == current.filesystem_device && mount.inode == current.inode
            })
            .min_by_key(|mount| mount.mount_id_unique)
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "mount-root index has no candidate".to_owned(),
                }
                .build()
            })?;
        let Some(parent) = by_id.get(&selected.parent_mount_id).copied() else {
            ensure!(
                selected.mountpoint == Path::new("/"),
                IdentityStateSnafu {
                    reason: "non-root selected mount has no represented parent",
                }
            );
            if first_selected_mount_id_unique == 0 {
                first_selected_mount_id_unique = selected.mount_id_unique;
            }
            return Ok(CanonicalMountPath {
                components,
                first_selected_mount_id_unique,
            });
        };
        if parent.mount_id == selected.mount_id {
            ensure!(
                selected.mountpoint == Path::new("/"),
                IdentityStateSnafu {
                    reason: "self-parent mount is not the namespace root",
                }
            );
            if first_selected_mount_id_unique == 0 {
                first_selected_mount_id_unique = selected.mount_id_unique;
            }
            return Ok(CanonicalMountPath {
                components,
                first_selected_mount_id_unique,
            });
        }
        if current.root != Path::new("/") {
            let source = mounts
                .iter()
                .filter(|mount| {
                    mount.filesystem_device == current.filesystem_device
                        && mount.root != current.root
                        && current.root.starts_with(&mount.root)
                })
                .max_by(|left, right| {
                    left.root
                        .components()
                        .count()
                        .cmp(&right.root.components().count())
                        .then_with(|| right.mount_id_unique.cmp(&left.mount_id_unique))
                });
            let Some(source) = source else {
                // A hostPath bind can be the only view of its source filesystem.
                // Its source root is still exact and the entered mount ID prevents alias reuse.
                let mut source_components = path_components(&current.root)?;
                source_components.append(&mut components);
                ensure!(
                    source_components.len() <= MAX_CANONICAL_PATH_COMPONENTS_V1,
                    IdentityStateSnafu {
                        reason: format!(
                            "canonical mount path exceeds {MAX_CANONICAL_PATH_COMPONENTS_V1} components"
                        ),
                    }
                );
                if first_selected_mount_id_unique == 0 {
                    first_selected_mount_id_unique = selected.mount_id_unique;
                }
                return Ok(CanonicalMountPath {
                    components: source_components,
                    first_selected_mount_id_unique,
                });
            };
            let source_relative = current.root.strip_prefix(&source.root).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("mount root is outside its source root: {error}"),
                }
                .build()
            })?;
            let mut source_components = path_components(source_relative)?;
            source_components.append(&mut components);
            ensure!(
                source_components.len() <= MAX_CANONICAL_PATH_COMPONENTS_V1,
                IdentityStateSnafu {
                    reason: format!(
                        "canonical mount path exceeds {MAX_CANONICAL_PATH_COMPONENTS_V1} components"
                    ),
                }
            );
            components = source_components;
            current = source;
            continue;
        }
        if first_selected_mount_id_unique == 0 {
            first_selected_mount_id_unique = selected.mount_id_unique;
        }
        let attachment = selected
            .mountpoint
            .strip_prefix(&parent.mountpoint)
            .map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("mountpoint is outside its represented parent: {error}"),
                }
                .build()
            })?;
        let mut parent_relative = path_components(attachment)?;
        parent_relative.append(&mut components);
        ensure!(
            parent_relative.len() <= MAX_CANONICAL_PATH_COMPONENTS_V1,
            IdentityStateSnafu {
                reason: format!(
                    "canonical mount path exceeds {MAX_CANONICAL_PATH_COMPONENTS_V1} components"
                ),
            }
        );
        components = parent_relative;
        current = parent;
    }
    IdentityStateSnafu {
        reason: "canonical mount walk exceeds the represented mount count".to_owned(),
    }
    .fail()
}

fn parse_mountinfo(source: &[u8]) -> Result<Vec<MountInfoEntry>> {
    let mut entries = Vec::new();
    for line in source
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
        ensure!(
            fields.len() >= 10 && fields.iter().position(|field| *field == b"-").is_some(),
            IdentityStateSnafu {
                reason: "invalid /proc mountinfo record",
            }
        );
        entries.push(MountInfoEntry {
            mount_id: parse_mount_id(fields[0])?,
            parent_mount_id: parse_mount_id(fields[1])?,
            device: std::str::from_utf8(fields[2])
                .map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("mountinfo device is not ASCII: {error}"),
                    }
                    .build()
                })?
                .to_owned(),
            root: PathBuf::from(OsString::from_vec(unescape_mountinfo(fields[3])?)),
            mountpoint: PathBuf::from(OsString::from_vec(unescape_mountinfo(fields[4])?)),
        });
    }
    ensure!(
        !entries.is_empty(),
        IdentityStateSnafu {
            reason: "mountinfo snapshot is empty",
        }
    );
    Ok(entries)
}

fn parse_mount_id(value: &[u8]) -> Result<u32> {
    let value = std::str::from_utf8(value).map_err(|error| {
        IdentityStateSnafu {
            reason: format!("mountinfo ID is not ASCII: {error}"),
        }
        .build()
    })?;
    value.parse().map_err(|error| {
        IdentityStateSnafu {
            reason: format!("mountinfo ID is invalid: {error}"),
        }
        .build()
    })
}

fn encoded_device(major: u32, minor: u32) -> Result<u32> {
    rustix::fs::makedev(major, minor)
        .try_into()
        .map_err(|error| {
            IdentityStateSnafu {
                reason: format!("encoded filesystem device exceeds its Linux u32 ABI: {error}"),
            }
            .build()
        })
}

fn unescape_mountinfo(value: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' {
            ensure!(
                index + 3 < value.len()
                    && value[index + 1..index + 4]
                        .iter()
                        .all(|byte| (b'0'..=b'7').contains(byte)),
                IdentityStateSnafu {
                    reason: "invalid mountinfo octal escape",
                }
            );
            let byte =
                (value[index + 1] - b'0') * 64 + (value[index + 2] - b'0') * 8 + value[index + 3]
                    - b'0';
            output.push(byte);
            index += 4;
        } else {
            output.push(value[index]);
            index += 1;
        }
    }
    Ok(output)
}

fn path_components(path: &Path) -> Result<Vec<Vec<u8>>> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::RootDir => None,
            std::path::Component::Normal(component) => Some(Ok(component.as_bytes().to_vec())),
            _ => Some(
                IdentityStateSnafu {
                    reason: format!(
                        "path contains a non-canonical component: {}",
                        path.display()
                    ),
                }
                .fail(),
            ),
        })
        .collect::<Result<Vec<_>>>()
        .and_then(|components| {
            ensure!(
                components.iter().all(|component| {
                    !component.is_empty()
                        && component.len() <= MAX_CANONICAL_COMPONENT_BYTES_V1
                        && !component.contains(&0)
                }),
                IdentityStateSnafu {
                    reason: "path component is empty, too long, or contains NUL",
                }
            );
            Ok(components)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use snafu::ResultExt as _;

    use super::{
        canonicalize_mount_path, parse_mountinfo, relevant_mount_entries, unescape_mountinfo,
        ExactFileObjectView, LiveMount, LiveMountRootRouteV1, MountInfoEntry,
    };
    use crate::error::IoSnafu;

    #[test]
    fn oci_entry_view_uses_the_standard_relative_runtime_root() -> crate::Result<()> {
        let bundle = tempfile::tempdir().context(IoSnafu {
            path: "temporary OCI bundle",
        })?;
        let root = bundle.path().join("rootfs");
        fs::create_dir(&root).context(IoSnafu { path: &root })?;
        let config = bundle.path().join("config.json");
        fs::write(&config, br#"{"root":{"path":"rootfs"}}"#).context(IoSnafu { path: &config })?;

        let view = ExactFileObjectView::acquire_oci(std::process::id(), bundle.path())?;

        assert!(view.mount_namespace_inode()? > 0);
        assert!(view.root.metadata().is_ok_and(|metadata| metadata.is_dir()));
        Ok(())
    }

    #[test]
    fn oci_entry_view_rejects_a_root_that_escapes_the_bundle() -> crate::Result<()> {
        let bundle = tempfile::tempdir().context(IoSnafu {
            path: "temporary OCI bundle",
        })?;
        let config = bundle.path().join("config.json");
        fs::write(&config, br#"{"root":{"path":"../rootfs"}}"#)
            .context(IoSnafu { path: &config })?;

        assert!(ExactFileObjectView::acquire_oci(std::process::id(), bundle.path()).is_err());
        Ok(())
    }

    #[test]
    fn oci_entry_view_rebases_mounts_to_container_paths() -> crate::Result<()> {
        let entries = vec![
            MountInfoEntry {
                mount_id: 1,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/"),
                device: "8:1".to_owned(),
            },
            MountInfoEntry {
                mount_id: 10,
                parent_mount_id: 1,
                root: PathBuf::from("/var/lib/containers/rootfs"),
                mountpoint: PathBuf::from("/run/container/rootfs"),
                device: "8:1".to_owned(),
            },
            MountInfoEntry {
                mount_id: 11,
                parent_mount_id: 10,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/run/container/rootfs/home/secret"),
                device: "0:42".to_owned(),
            },
            MountInfoEntry {
                mount_id: 12,
                parent_mount_id: 10,
                root: PathBuf::from("/models"),
                mountpoint: PathBuf::from("/run/container/rootfs/home/attack"),
                device: "0:42".to_owned(),
            },
            MountInfoEntry {
                mount_id: 13,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/unrelated"),
                device: "0:43".to_owned(),
            },
        ];

        let rebased = ExactFileObjectView::rebase_mount_entries(
            &entries,
            Path::new("/run/container/rootfs"),
            10,
        )?;

        assert_eq!(
            rebased,
            vec![
                MountInfoEntry {
                    mount_id: 10,
                    parent_mount_id: 10,
                    root: PathBuf::from("/var/lib/containers/rootfs"),
                    mountpoint: PathBuf::from("/"),
                    device: "8:1".to_owned(),
                },
                MountInfoEntry {
                    mount_id: 11,
                    parent_mount_id: 10,
                    root: PathBuf::from("/"),
                    mountpoint: PathBuf::from("/home/secret"),
                    device: "0:42".to_owned(),
                },
                MountInfoEntry {
                    mount_id: 12,
                    parent_mount_id: 10,
                    root: PathBuf::from("/models"),
                    mountpoint: PathBuf::from("/home/attack"),
                    device: "0:42".to_owned(),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn retained_mount_view_owns_live_namespace_inputs() -> crate::Result<()> {
        let view = ExactFileObjectView::acquire(std::process::id())?;

        assert!(view.mount_namespace_inode()? > 0);
        assert!(!parse_mountinfo(&view.read_mountinfo()?)?.is_empty());
        assert!(view
            .open_path(Path::new("/"))?
            .metadata()
            .is_ok_and(|metadata| metadata.is_dir()));
        Ok(())
    }

    #[test]
    fn retained_mount_view_reads_mountinfo_after_source_exit() -> crate::Result<()> {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .context(IoSnafu {
                path: Path::new("/bin/sleep"),
            })?;
        let child_pid = child.id();
        let view = ExactFileObjectView::acquire(child_pid)?;
        let _ = child.kill();
        let zombie_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let state = fs::read_to_string(format!("/proc/{child_pid}/stat")).unwrap_or_default();
            if state
                .split_once(") ")
                .is_some_and(|(_, state)| state.starts_with('Z'))
            {
                break;
            }
            assert!(
                std::time::Instant::now() < zombie_deadline,
                "the retained mount-view source did not enter its unreaped exit state",
            );
            std::thread::yield_now();
        }
        assert!(!parse_mountinfo(&view.read_mountinfo()?)?.is_empty());
        let _ = child.wait();

        assert!(!PathBuf::from(format!("/proc/{child_pid}")).exists());
        assert!(view.mount_namespace_inode()? > 0);
        assert!(!parse_mountinfo(&view.read_mountinfo()?)?.is_empty());
        assert!(!parse_mountinfo(&view.read_mountinfo()?)?.is_empty());
        Ok(())
    }

    #[test]
    fn retained_mount_view_requires_an_absolute_in_root_path() -> crate::Result<()> {
        let view = ExactFileObjectView::acquire(std::process::id())?;

        assert!(view.open_path(Path::new("/etc")).is_ok());
        assert!(view.open_path(Path::new("/../../etc")).is_ok());
        assert!(view.open_path(Path::new("relative/path")).is_err());
        Ok(())
    }

    #[test]
    fn mountinfo_parser_preserves_linux_path_bytes() -> crate::Result<()> {
        let parsed = parse_mountinfo(
            b"41 1 0:42 / /var/run/secrets rw - tmpfs tmpfs rw\n\
              92 1 0:42 / /work/input/job\\04042 rw - tmpfs tmpfs rw\n",
        )?;
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[1].mountpoint.as_os_str().as_encoded_bytes(),
            b"/work/input/job 42"
        );
        assert!(unescape_mountinfo(b"bad\\x").is_err());
        Ok(())
    }

    #[test]
    fn canonical_mount_walk_selects_the_oldest_root_and_repeats_to_namespace_root(
    ) -> crate::Result<()> {
        let mounts = vec![
            LiveMount {
                mount_id: 1,
                parent_mount_id: 0,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/"),
                filesystem_device: 1,
                inode: 1,
                mount_id_unique: 1,
            },
            LiveMount {
                mount_id: 5,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/var/run/secrets/service"),
                filesystem_device: 42,
                inode: 2,
                mount_id_unique: 41,
            },
            LiveMount {
                mount_id: 9,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/work/input/job-42"),
                filesystem_device: 42,
                inode: 2,
                mount_id_unique: 92,
            },
        ];
        let result = canonicalize_mount_path(9, vec![b"config.json".to_vec()], &mounts)?;
        assert_eq!(
            result.components,
            ["var", "run", "secrets", "service", "config.json"]
                .map(|component| component.as_bytes().to_vec())
        );
        assert_eq!(result.first_selected_mount_id_unique, 41);
        Ok(())
    }

    #[test]
    fn canonical_mount_walk_uses_source_ancestry_for_a_child_bind() -> crate::Result<()> {
        let mounts = vec![
            LiveMount {
                mount_id: 1,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/"),
                filesystem_device: 1,
                inode: 1,
                mount_id_unique: 1,
            },
            LiveMount {
                mount_id: 5,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/mnt/data"),
                filesystem_device: 42,
                inode: 2,
                mount_id_unique: 41,
            },
            LiveMount {
                mount_id: 9,
                parent_mount_id: 1,
                root: PathBuf::from("/models"),
                mountpoint: PathBuf::from("/work/models"),
                filesystem_device: 42,
                inode: 3,
                mount_id_unique: 92,
            },
        ];

        let result = canonicalize_mount_path(9, vec![b"model.bin".to_vec()], &mounts)?;

        assert_eq!(
            result.components,
            ["mnt", "data", "models", "model.bin"].map(|component| component.as_bytes().to_vec())
        );
        assert_eq!(result.first_selected_mount_id_unique, 41);
        Ok(())
    }

    #[test]
    fn mount_routes_include_inherited_source_paths_for_kubernetes_submounts() -> crate::Result<()> {
        let mounts = vec![
            LiveMount {
                mount_id: 1,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/"),
                filesystem_device: 1,
                inode: 1,
                mount_id_unique: 1,
            },
            LiveMount {
                mount_id: 5,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/home/secret"),
                filesystem_device: 42,
                inode: 2,
                mount_id_unique: 41,
            },
            LiveMount {
                mount_id: 9,
                parent_mount_id: 1,
                root: PathBuf::from("/models"),
                mountpoint: PathBuf::from("/home/kubelet-attack"),
                filesystem_device: 42,
                inode: 3,
                mount_id_unique: 92,
            },
            LiveMount {
                mount_id: 10,
                parent_mount_id: 1,
                root: PathBuf::from("/models"),
                mountpoint: PathBuf::from("/home/kubelet-attack-newer"),
                filesystem_device: 42,
                inode: 3,
                mount_id_unique: 93,
            },
        ];

        let routes = LiveMountRootRouteV1::from_mounts(&mounts, 7, 11)?;
        let model_paths = routes
            .iter()
            .filter(|route| route.filesystem_device == 42 && route.root_inode == 3)
            .map(|route| route.mountpoint_components.clone())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            model_paths,
            vec![
                vec!["home", "secret", "models"],
                vec!["home", "kubelet-attack"],
                vec!["home", "kubelet-attack-newer"],
            ]
            .into_iter()
            .map(|path| {
                path.into_iter()
                    .map(|component| component.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .collect()
        );
        assert!(routes
            .iter()
            .filter(|route| route.filesystem_device == 42 && route.root_inode == 3)
            .all(|route| route.selected_mount_id_unique == 92));
        Ok(())
    }

    #[test]
    fn canonical_mount_walk_accepts_an_unrepresented_hostpath_source() -> crate::Result<()> {
        let mounts = vec![
            LiveMount {
                mount_id: 1,
                parent_mount_id: 1,
                root: PathBuf::from("/"),
                mountpoint: PathBuf::from("/"),
                filesystem_device: 1,
                inode: 1,
                mount_id_unique: 1,
            },
            LiveMount {
                mount_id: 9,
                parent_mount_id: 1,
                root: PathBuf::from("/var/lib/mithril/markers"),
                mountpoint: PathBuf::from("/var/lib/mithril/markers"),
                filesystem_device: 42,
                inode: 3,
                mount_id_unique: 92,
            },
        ];

        let result = canonicalize_mount_path(9, vec![b"result".to_vec()], &mounts)?;

        assert_eq!(
            result.components,
            ["var", "lib", "mithril", "markers", "result"]
                .map(|component| component.as_bytes().to_vec())
        );
        assert_eq!(result.first_selected_mount_id_unique, 92);
        Ok(())
    }

    #[test]
    fn mount_walk_does_not_open_unrelated_mounts() -> crate::Result<()> {
        let entries = parse_mountinfo(
            b"1 1 0:1 / / rw - rootfs rootfs rw\n\
              5 1 0:42 /secret /var/run/secrets/service rw - tmpfs tmpfs rw\n\
              9 1 0:42 /secret /work/input/job-42 rw - tmpfs tmpfs rw\n\
              335 1 0:65 / /run/user/1000/doc ro - fuse.portal portal rw\n",
        )?;

        let relevant = relevant_mount_entries(&entries, 9)?;
        assert_eq!(
            relevant
                .iter()
                .map(|entry| entry.mount_id)
                .collect::<Vec<_>>(),
            vec![1, 5, 9]
        );
        Ok(())
    }

    #[test]
    fn mount_walk_includes_source_ancestor_roots() -> crate::Result<()> {
        let entries = parse_mountinfo(
            b"1 1 0:1 / / rw - rootfs rootfs rw\n\
              5 1 0:42 / /mnt/data rw - tmpfs tmpfs rw\n\
              9 1 0:42 /models /work/models rw - tmpfs tmpfs rw\n\
              335 1 0:65 / /run/user/1000/doc ro - fuse.portal portal rw\n",
        )?;

        let relevant = relevant_mount_entries(&entries, 9)?;

        assert_eq!(
            relevant
                .iter()
                .map(|entry| entry.mount_id)
                .collect::<Vec<_>>(),
            vec![1, 5, 9]
        );
        Ok(())
    }
}
