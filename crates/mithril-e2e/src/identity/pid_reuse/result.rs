use std::fs;
use std::path::Path;

use mithril_node::NativeTaskSnapshotV1;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Deserialize, Serialize)]
pub(in crate::identity) struct TaskStamp {
    pub(in crate::identity) pidns_inode: u32,
    pub(in crate::identity) start_ns: u64,
}

#[derive(Deserialize, Serialize)]
pub(in crate::identity) struct PidResult {
    pub(in crate::identity) nspid: u32,
    pub(in crate::identity) second_ns: u32,
    pub(in crate::identity) first_pid: u32,
    pub(in crate::identity) second_pid: u32,
    pub(in crate::identity) first_live: u32,
    pub(in crate::identity) second_live: u32,
    pub(in crate::identity) root: NativeTaskSnapshotV1,
    pub(in crate::identity) first: NativeTaskSnapshotV1,
    pub(in crate::identity) second: NativeTaskSnapshotV1,
    pub(in crate::identity) first_stamp: TaskStamp,
    pub(in crate::identity) second_stamp: TaskStamp,
    pub(in crate::identity) fresh: bool,
}

#[cfg(test)]
pub(crate) type ReuseResult = PidResult;

#[cfg(test)]
impl PidResult {
    pub(crate) fn new(
        nspid: u32,
        second_ns: u32,
        root: crate::platform::Task,
        first: crate::platform::Task,
        second: crate::platform::Task,
    ) -> Self {
        Self {
            nspid,
            second_ns,
            first_pid: first.pid,
            second_pid: second.pid,
            first_live: first.ns_pid,
            second_live: second.ns_pid,
            root: root.snapshot,
            first: first.snapshot,
            second: second.snapshot,
            first_stamp: TaskStamp {
                pidns_inode: first.coordinate.pid_namespace_inode,
                start_ns: first.coordinate.task_start_boottime_ns,
            },
            second_stamp: TaskStamp {
                pidns_inode: second.coordinate.pid_namespace_inode,
                start_ns: second.coordinate.task_start_boottime_ns,
            },
            fresh: true,
        }
    }

    pub(crate) fn assert_fresh(&self) {
        assert_eq!(
            self.root.root_class.as_deref(),
            Some("initial_container_root")
        );
        assert_eq!(
            self.root.installed_role_class.as_deref(),
            Some("initial_role")
        );
        assert_eq!(self.root.creator_task_cookie, None);
        assert!(self.nspid > 1);
        assert_eq!(self.second_ns, self.nspid);
        assert_eq!(self.first_live, self.nspid);
        assert_eq!(self.second_live, self.nspid);
        assert_ne!(self.first_pid, self.second_pid);
        assert_ne!(self.first.task_cookie, self.second.task_cookie);
        assert_ne!(self.first.process_state_id, self.second.process_state_id);
        assert_ne!(
            self.first.active_execution_id,
            self.second.active_execution_id
        );
        assert_eq!(self.first.creator_task_cookie, Some(self.root.task_cookie));
        assert_eq!(self.second.creator_task_cookie, Some(self.root.task_cookie));
        assert_eq!(self.first_stamp.pidns_inode, self.second_stamp.pidns_inode);
        assert_ne!(self.first_stamp.start_ns, self.second_stamp.start_ns);
        assert!(self.fresh);
    }

    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context(JsonSnafu { path })?;
        fs::write(path, bytes).context(IoSnafu { path })
    }
}
