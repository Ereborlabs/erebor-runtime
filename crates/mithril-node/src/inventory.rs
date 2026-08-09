use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::error::IoSnafu;
use crate::Result;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkloadInventoryRecordV1 {
    pub process_count: u64,
    pub cgroup_binding_digest: String,
}

pub struct WorkloadInventory {
    proc_root: PathBuf,
}

impl WorkloadInventory {
    #[must_use]
    pub fn system() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
        }
    }

    #[cfg(test)]
    fn at(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }

    pub fn scan(&self) -> Result<WorkloadInventoryRecordV1> {
        let mut bindings = Vec::new();
        for entry in fs::read_dir(&self.proc_root).context(IoSnafu {
            path: &self.proc_root,
        })? {
            let entry = entry.context(IoSnafu {
                path: &self.proc_root,
            })?;
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            else {
                continue;
            };
            let cgroup_path = entry.path().join("cgroup");
            if let Ok(cgroup) = fs::read(&cgroup_path) {
                bindings.push((pid.to_owned(), cgroup));
            }
        }
        bindings.sort_by(|left, right| left.0.cmp(&right.0));
        let mut digest = Sha256::new();
        for (pid, cgroup) in &bindings {
            digest.update((pid.len() as u64).to_le_bytes());
            digest.update(pid.as_bytes());
            digest.update((cgroup.len() as u64).to_le_bytes());
            digest.update(cgroup);
        }
        Ok(WorkloadInventoryRecordV1 {
            process_count: bindings.len() as u64,
            cgroup_binding_digest: format!("{:x}", digest.finalize()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use snafu::ResultExt as _;

    use super::WorkloadInventory;
    use crate::error::IoSnafu;

    #[test]
    fn inventory_is_sorted_and_ignores_non_process_entries() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary proc directory",
        })?;
        for (pid, cgroup) in [("20", "0::/work/b\n"), ("3", "0::/work/a\n")] {
            let process = directory.path().join(pid);
            fs::create_dir(&process).context(IoSnafu { path: &process })?;
            fs::write(process.join("cgroup"), cgroup).context(IoSnafu { path: &process })?;
        }
        fs::create_dir(directory.path().join("self")).context(IoSnafu {
            path: directory.path(),
        })?;
        let inventory = WorkloadInventory::at(directory.path().to_path_buf()).scan()?;
        assert_eq!(inventory.process_count, 2);
        assert_eq!(inventory.cgroup_binding_digest.len(), 64);
        Ok(())
    }
}
