use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{statx, AtFlags, StatxFlags};
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
        Ok(ExactFileObjectConfig {
            profile_generation_ref_id,
            exact_object_key_id,
            object_class_id,
            mount_namespace_inode,
            mount_id_unique: status.stx_mnt_id,
            filesystem_device: rustix::fs::makedev(status.stx_dev_major, status.stx_dev_minor),
            inode: status.stx_ino,
            inode_generation,
        })
    }
}
