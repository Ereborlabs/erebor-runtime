use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{statx, AtFlags, StatxFlags};
use sha2::{Digest as _, Sha256};
use snafu::{ensure, ResultExt as _};

use crate::error::{IdentityStateSnafu, IoSnafu};
use crate::{ExactFileObjectConfig, Result};

const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;

pub struct ExactFileObjectResolver;

impl ExactFileObjectResolver {
    pub fn resolve(
        root_pid: u32,
        path: &Path,
        profile_generation_ref_id: u64,
        exact_object_key_id: u64,
        object_class_id: String,
        inode_generation: u32,
    ) -> Result<ExactFileObjectConfig> {
        ensure!(
            root_pid > 0 && path.is_absolute(),
            IdentityStateSnafu {
                reason:
                    "exact file resolution needs a live root PID and absolute in-namespace path",
            }
        );
        let namespace_path = PathBuf::from(format!("/proc/{root_pid}/ns/mnt"));
        let mount_namespace_inode = fs::metadata(&namespace_path)
            .context(IoSnafu {
                path: &namespace_path,
            })?
            .ino();
        let host_path = PathBuf::from(format!("/proc/{root_pid}/root")).join(
            path.strip_prefix("/").map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("exact object path is not absolute: {error}"),
                }
                .build()
            })?,
        );
        let file = File::open(&host_path).context(IoSnafu { path: &host_path })?;
        let unique_mount = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
        let status = statx(
            &file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | unique_mount,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: &host_path })?;
        ensure!(
            status.stx_mask & STATX_MNT_ID_UNIQUE != 0
                && status.stx_mnt_id > 0
                && status.stx_ino > 0,
            IdentityStateSnafu {
                reason: "kernel/filesystem did not return STATX_MNT_ID_UNIQUE and an inode",
            }
        );
        ensure!(
            mount_namespace_inode > 0 && inode_generation > 0,
            IdentityStateSnafu {
                reason: "mount namespace and inode generation must be nonzero",
            }
        );
        let mount_snapshot = MountInfoSnapshot::read(root_pid, path)?;
        Ok(ExactFileObjectConfig {
            profile_generation_ref_id,
            exact_object_key_id,
            object_class_id,
            mount_namespace_inode,
            mount_id_unique: status.stx_mnt_id,
            filesystem_device: rustix::fs::makedev(status.stx_dev_major, status.stx_dev_minor),
            inode: status.stx_ino,
            inode_generation,
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
            mount_topology_generation: 1,
            mount_view_root_pid: root_pid,
        })
    }
}

struct MountInfoSnapshot {
    canonical_components: Vec<Vec<u8>>,
    relative_component_count: usize,
    root_filesystem_device: u64,
    root_inode: u64,
    selected_mount_id_unique: u64,
    snapshot_digest_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfoEntry {
    mount_id: u64,
    parent_mount_id: u64,
    root: PathBuf,
    mountpoint: PathBuf,
    device: String,
}

impl MountInfoSnapshot {
    fn read(root_pid: u32, target: &Path) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{root_pid}/mountinfo"));
        let first = fs::read(&path).context(IoSnafu { path: &path })?;
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
        let mounts = entries
            .iter()
            .map(|entry| live_mount(root_pid, entry))
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
            !canonical_components.is_empty() && canonical_components.len() <= 64,
            IdentityStateSnafu {
                reason: "canonical path must contain 1..64 bounded components",
            }
        );
        let second = fs::read(&path).context(IoSnafu { path: &path })?;
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
            canonical_components,
            relative_component_count: relative.len(),
            root_filesystem_device: entered.filesystem_device,
            root_inode: entered.inode,
            selected_mount_id_unique: canonical.first_selected_mount_id_unique,
            snapshot_digest_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiveMount {
    mount_id: u64,
    parent_mount_id: u64,
    mountpoint: PathBuf,
    filesystem_device: u64,
    inode: u64,
    mount_id_unique: u64,
}

fn live_mount(root_pid: u32, entry: &MountInfoEntry) -> Result<LiveMount> {
    let host_path = PathBuf::from(format!("/proc/{root_pid}/root")).join(
        entry.mountpoint.strip_prefix("/").map_err(|error| {
            IdentityStateSnafu {
                reason: format!("mountpoint is not absolute: {error}"),
            }
            .build()
        })?,
    );
    let file = File::open(&host_path).context(IoSnafu { path: &host_path })?;
    let unique_mount = StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE);
    let status = statx(
        &file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | unique_mount,
    )
    .map_err(std::io::Error::from)
    .context(IoSnafu { path: &host_path })?;
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
        filesystem_device: rustix::fs::makedev(status.stx_dev_major, status.stx_dev_minor),
        inode: status.stx_ino,
        mount_id_unique: status.stx_mnt_id,
    })
}

struct CanonicalMountPath {
    components: Vec<Vec<u8>>,
    first_selected_mount_id_unique: u64,
}

fn canonicalize_mount_path(
    entered_mount_id: u64,
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
    for _ in 0..=64 {
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
            parent_relative.len() <= 64,
            IdentityStateSnafu {
                reason: "canonical mount path exceeds 64 components",
            }
        );
        components = parent_relative;
        current = parent;
    }
    IdentityStateSnafu {
        reason: "canonical mount walk exceeds 64 crossings".to_owned(),
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

fn parse_mount_id(value: &[u8]) -> Result<u64> {
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
                    !component.is_empty() && component.len() <= 255 && !component.contains(&0)
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
    use std::path::PathBuf;

    use super::{canonicalize_mount_path, parse_mountinfo, unescape_mountinfo, LiveMount};

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
}
