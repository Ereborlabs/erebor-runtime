use std::fs;
use std::path::Path;

use mithril_node::NativeTaskSnapshotV1;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::error::{IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Deserialize, Serialize)]
pub(in crate::identity) struct TidResult {
    pub(in crate::identity) ns_tid: u32,
    pub(in crate::identity) second_ns: u32,
    pub(in crate::identity) root: NativeTaskSnapshotV1,
    pub(in crate::identity) first: ThreadStamp,
    pub(in crate::identity) second: ThreadStamp,
    pub(in crate::identity) fresh: bool,
}

#[derive(Deserialize, Serialize)]
pub(in crate::identity) struct ThreadStamp {
    pub(in crate::identity) task_cookie: u64,
    pub(in crate::identity) host_tid: u32,
    ns_tid: u32,
    host_tgid: u32,
    pidns_inode: u32,
    start_ns: u64,
    process_state: String,
    creator_task: u64,
}

pub(in crate::identity) fn read(path: &Path) -> Result<TidResult> {
    let bytes = fs::read(path).context(IoSnafu { path })?;
    serde_json::from_slice(&bytes).context(JsonSnafu { path })
}

#[cfg(test)]
pub(crate) type ReuseResult = TidResult;

#[cfg(test)]
impl TidResult {
    pub(crate) fn new(
        ns_tid: u32,
        second_ns: u32,
        root: crate::platform::Task,
        first: crate::platform::Thread,
        second: crate::platform::Thread,
    ) -> Self {
        let fresh = ns_tid == second_ns
            && first.pid != second.pid
            && first.coordinate.task_cookie != second.coordinate.task_cookie
            && first.coordinate.task_start_boottime_ns != second.coordinate.task_start_boottime_ns
            && first.coordinate.pid_namespace_inode == second.coordinate.pid_namespace_inode;
        Self {
            ns_tid,
            second_ns,
            root: root.snapshot,
            first: ThreadStamp::new(first),
            second: ThreadStamp::new(second),
            fresh,
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
        assert!(self.ns_tid > 1);
        assert_eq!(self.second_ns, self.ns_tid);
        assert_eq!(self.first.ns_tid, self.ns_tid);
        assert_eq!(self.second.ns_tid, self.ns_tid);
        assert_ne!(self.first.host_tid, self.second.host_tid);
        assert_ne!(self.first.task_cookie, self.second.task_cookie);
        assert_eq!(self.first.process_state, self.root.process_state_id);
        assert_eq!(self.second.process_state, self.root.process_state_id);
        assert_eq!(self.first.creator_task, self.root.task_cookie);
        assert_eq!(self.second.creator_task, self.root.task_cookie);
        assert_eq!(self.first.host_tgid, self.root.host_tgid);
        assert_eq!(self.second.host_tgid, self.root.host_tgid);
        assert_eq!(self.first.pidns_inode, self.second.pidns_inode);
        assert_ne!(self.first.start_ns, self.second.start_ns);
        assert!(self.fresh);
    }

    pub(crate) fn write(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context(JsonSnafu { path })?;
        fs::write(path, bytes).context(IoSnafu { path })
    }
}

#[cfg(test)]
impl ThreadStamp {
    fn new(thread: crate::platform::Thread) -> Self {
        Self {
            task_cookie: thread.coordinate.task_cookie,
            host_tid: thread.pid,
            ns_tid: thread.ns_tid,
            host_tgid: thread.coordinate.host_tgid,
            pidns_inode: thread.coordinate.pid_namespace_inode,
            start_ns: thread.coordinate.task_start_boottime_ns,
            process_state: format!(
                "{:016x}{:016x}",
                thread.coordinate.process_state_id.high, thread.coordinate.process_state_id.low
            ),
            creator_task: thread.edge.creator_task_cookie,
        }
    }
}
