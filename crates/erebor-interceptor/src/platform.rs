use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::IoSnafu;
use crate::{KernelPlatformProbeV1, Result};

pub struct KernelPlatformProbe;

impl KernelPlatformProbe {
    pub fn inspect(runtime_btf_path: &Path) -> Result<KernelPlatformProbeV1> {
        let kernel_release_path = Path::new("/proc/sys/kernel/osrelease");
        let kernel_release = fs::read_to_string(kernel_release_path).context(IoSnafu {
            action: "read kernel release",
            path: kernel_release_path,
        })?;
        let lsm_path = Path::new("/sys/kernel/security/lsm");
        let active_lsm_order = read_active_lsm_order(lsm_path)?;
        let mounts_path = Path::new("/proc/mounts");
        let mounts = fs::read_to_string(mounts_path).context(IoSnafu {
            action: "read mounted filesystems",
            path: mounts_path,
        })?;
        let runtime_btf_sha256 = runtime_btf_path
            .is_file()
            .then(|| {
                fs::read(runtime_btf_path)
                    .context(IoSnafu {
                        action: "read runtime BTF",
                        path: runtime_btf_path,
                    })
                    .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            })
            .transpose()?;

        Ok(KernelPlatformProbeV1 {
            kernel_release: kernel_release.trim().to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            bpf_lsm_active: active_lsm_order.split(',').any(|lsm| lsm == "bpf"),
            active_lsm_order,
            runtime_btf_sha256,
            cgroup_v2: mounts
                .lines()
                .any(|line| line.split_whitespace().nth(2) == Some("cgroup2")),
        })
    }
}

fn read_active_lsm_order(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(order) => Ok(order.trim().to_owned()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(source) => Err(source).context(IoSnafu {
            action: "read active Linux security modules",
            path,
        }),
    }
}

#[cfg(test)]
mod tests {
    use snafu::ResultExt as _;

    use super::read_active_lsm_order;
    use crate::error::IoSnafu;

    #[test]
    fn missing_securityfs_defers_lsm_proof_to_program_load() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            action: "create temporary platform-probe directory",
            path: "temporary platform-probe directory",
        })?;
        assert!(read_active_lsm_order(&directory.path().join("lsm"))?.is_empty());
        Ok(())
    }
}
