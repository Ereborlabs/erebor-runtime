use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use erebor_interceptor_abi::{MAX_CANONICAL_COMPONENT_BYTES_V1, MAX_CANONICAL_PATH_COMPONENTS_V1};
use rustix::fs::{openat, openat2, statx, AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{IdentityStateSnafu, IoSnafu};
use crate::{ExactDeviceConfig, ExactDeviceType, ExactFileObjectConfig, Result};

const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;

pub struct ExactFileObjectResolver;

pub(crate) struct ExactFileObjectView {
    root_pid: u32,
    _process: File,
    mount_namespace: File,
    root: File,
    mountinfo: Mutex<File>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveExactFileObjectV1 {
    pub mount_namespace_inode: u32,
    pub mount_id: u32,
    pub mount_id_unique: u64,
    pub filesystem_device: u32,
    pub inode: u64,
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

impl LiveExactFileObjectV1 {
    pub(crate) fn matches(&self, configured: &ExactFileObjectConfig) -> bool {
        self.mount_namespace_inode == configured.mount_namespace_inode
            && self.mount_id_unique == configured.mount_id_unique
            && self.filesystem_device == configured.filesystem_device
            && self.inode == configured.inode
            && self.canonical_component_hex == configured.canonical_component_hex
            && self.mount_relative_component_count == configured.mount_relative_component_count
            && self.mount_root_filesystem_device == configured.mount_root_filesystem_device
            && self.mount_root_inode == configured.mount_root_inode
            && self.selected_mount_id_unique == configured.selected_mount_id_unique
            && match (&configured.device, self.device_type) {
                (None, None) => true,
                (Some(device), Some(device_type)) => {
                    device.device_type == device_type
                        && device.major == self.device_major
                        && device.minor == self.device_minor
                }
                _ => false,
            }
    }
}

impl ExactFileObjectResolver {
    pub fn resolve(
        root_pid: u32,
        path: &Path,
        profile_generation_ref_id: u64,
        exact_object_key_id: u64,
        object_class_id: String,
        inode_generation: u32,
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
        let root = open_process_file(&process, root_pid, "root")?;
        let mountinfo = open_process_file(&process, root_pid, "mountinfo")?;
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
            _process: process,
            mount_namespace,
            root,
            mountinfo: Mutex::new(mountinfo),
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve(
        &self,
        path: &Path,
        profile_generation_ref_id: u64,
        exact_object_key_id: u64,
        object_class_id: String,
        inode_generation: u32,
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

    pub(crate) fn inspect(&self, path: &Path) -> Result<LiveExactFileObjectV1> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact file resolution needs an absolute in-namespace path",
            }
        );
        let file = self.open_path(path)?;
        self.inspect_file(path, &file)
    }

    pub(crate) fn try_inspect(&self, path: &Path) -> Result<Option<LiveExactFileObjectV1>> {
        ensure!(
            path.is_absolute(),
            IdentityStateSnafu {
                reason: "exact file resolution needs an absolute in-namespace path",
            }
        );
        let Some(file) = self.try_open_path(path)? else {
            return Ok(None);
        };
        self.inspect_file(path, &file).map(Some)
    }

    fn inspect_file(&self, path: &Path, file: &File) -> Result<LiveExactFileObjectV1> {
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
        let mount_snapshot = MountInfoSnapshot::read(self, path)?;
        Ok(LiveExactFileObjectV1 {
            mount_namespace_inode,
            mount_id: mount_snapshot.entered_mount_id,
            mount_id_unique: status.stx_mnt_id,
            filesystem_device: encoded_device(status.stx_dev_major, status.stx_dev_minor)?,
            inode: status.stx_ino,
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
        let mut file = self.mountinfo.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "held mountinfo lock is poisoned".to_owned(),
            }
            .build()
        })?;
        read_mountinfo_file(&mut file, self.root_pid)
    }
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
    fn read(view: &ExactFileObjectView, target: &Path) -> Result<Self> {
        let first = view.read_mountinfo()?;
        let entries = parse_mountinfo(&first)?;
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
            .map(|entry| live_mount(view, entry))
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
        let digest = Sha256::digest(&first);
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
            candidate.device == current.device && candidate.root == current.root
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
    mountpoint: PathBuf,
    filesystem_device: u32,
    inode: u64,
    mount_id_unique: u64,
}

fn live_mount(view: &ExactFileObjectView, entry: &MountInfoEntry) -> Result<LiveMount> {
    let file = view.open_path(&entry.mountpoint)?;
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
        status.stx_mask & STATX_MNT_ID_UNIQUE != 0 && status.stx_mnt_id > 0 && status.stx_ino > 0,
        IdentityStateSnafu {
            reason: "mount root lacks a unique mount ID or inode",
        }
    );
    Ok(LiveMount {
        mount_id: entry.mount_id,
        parent_mount_id: entry.parent_mount_id,
        mountpoint: entry.mountpoint.clone(),
        filesystem_device: encoded_device(status.stx_dev_major, status.stx_dev_minor)?,
        inode: status.stx_ino,
        mount_id_unique: status.stx_mnt_id,
    })
}

fn read_mountinfo_file(file: &mut File, root_pid: u32) -> Result<Vec<u8>> {
    let path = PathBuf::from(format!("held /proc/{root_pid}/mountinfo"));
    file.seek(SeekFrom::Start(0))
        .context(IoSnafu { path: &path })?;
    let mut source = Vec::new();
    file.read_to_end(&mut source)
        .context(IoSnafu { path: &path })?;
    Ok(source)
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
        if first_selected_mount_id_unique == 0 {
            first_selected_mount_id_unique = selected.mount_id_unique;
        }
        let Some(parent) = by_id.get(&selected.parent_mount_id).copied() else {
            ensure!(
                selected.mountpoint == Path::new("/"),
                IdentityStateSnafu {
                    reason: "non-root selected mount has no represented parent",
                }
            );
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
            return Ok(CanonicalMountPath {
                components,
                first_selected_mount_id_unique,
            });
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
    use std::path::{Path, PathBuf};

    use super::{
        canonicalize_mount_path, parse_mountinfo, relevant_mount_entries, unescape_mountinfo,
        ExactFileObjectView, LiveMount,
    };

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
                mountpoint: PathBuf::from("/"),
                filesystem_device: 1,
                inode: 1,
                mount_id_unique: 1,
            },
            LiveMount {
                mount_id: 5,
                parent_mount_id: 1,
                mountpoint: PathBuf::from("/var/run/secrets/service"),
                filesystem_device: 42,
                inode: 2,
                mount_id_unique: 41,
            },
            LiveMount {
                mount_id: 9,
                parent_mount_id: 1,
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
}
