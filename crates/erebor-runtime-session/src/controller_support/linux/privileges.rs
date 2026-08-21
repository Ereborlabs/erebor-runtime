use std::io;

use rustix::{
    fs::Mode,
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
