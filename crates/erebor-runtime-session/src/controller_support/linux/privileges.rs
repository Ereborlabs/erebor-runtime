use std::{fs::File, io};

use erebor_runtime_core::WorkloadPrivilegePlan;
use rustix::{
    fs::{fchown, Mode},
    process::{setrlimit, umask, Resource, Rlimit},
    thread::{set_no_new_privs, set_thread_gid, set_thread_groups, set_thread_uid, Gid, Uid},
};

pub(super) struct WorkloadPrivileges {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) supplementary_groups: Vec<u32>,
    pub(super) mask: u32,
    pub(super) maximum_open_files: u64,
    pub(super) maximum_processes: u64,
    pub(super) maximum_core_bytes: u64,
}

impl WorkloadPrivileges {
    pub(super) fn from_plan(uid: u32, gid: u32, plan: &WorkloadPrivilegePlan) -> Self {
        Self {
            uid,
            gid,
            supplementary_groups: plan.supplementary_groups().to_vec(),
            mask: plan.umask(),
            maximum_open_files: plan.maximum_open_files(),
            maximum_processes: plan.maximum_processes(),
            maximum_core_bytes: plan.maximum_core_bytes(),
        }
    }

    pub(super) fn apply(&self) -> io::Result<()> {
        let mask = Mode::from_bits(self.mask).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "workload umask is invalid")
        })?;
        set_no_new_privs(true).map_err(io::Error::from)?;
        Self::limit(Resource::Nofile, self.maximum_open_files)?;
        Self::limit(Resource::Nproc, self.maximum_processes)?;
        Self::limit(Resource::Core, self.maximum_core_bytes)?;
        umask(mask);
        let groups = self
            .supplementary_groups
            .iter()
            .copied()
            .map(Gid::from_raw)
            .collect::<Vec<_>>();
        set_thread_groups(&groups).map_err(io::Error::from)?;
        set_thread_gid(Gid::from_raw(self.gid)).map_err(io::Error::from)?;
        set_thread_uid(Uid::from_raw(self.uid)).map_err(io::Error::from)
    }

    pub(super) fn assign_terminal_owner(&self, terminal: &File) -> io::Result<()> {
        fchown(terminal, Some(Uid::from_raw(self.uid)), None).map_err(io::Error::from)
    }

    fn limit(resource: Resource, value: u64) -> io::Result<()> {
        setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::WorkloadPrivileges;
    use erebor_runtime_core::WorkloadPrivilegePlan;

    #[test]
    fn held_launch_keeps_the_admitted_privilege_plan() -> Result<(), Box<dyn std::error::Error>> {
        let plan = WorkloadPrivilegePlan::new(vec![10, 20], 0o077, 128, 256, 0)?;
        let privileges = WorkloadPrivileges::from_plan(1000, 1001, &plan);

        assert_eq!(privileges.uid, 1000);
        assert_eq!(privileges.gid, 1001);
        assert_eq!(privileges.supplementary_groups, vec![10, 20]);
        assert_eq!(privileges.mask, 0o077);
        assert_eq!(privileges.maximum_open_files, 128);
        assert_eq!(privileges.maximum_processes, 256);
        assert_eq!(privileges.maximum_core_bytes, 0);
        Ok(())
    }
}
