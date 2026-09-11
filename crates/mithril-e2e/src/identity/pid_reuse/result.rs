use mithril_node::NativeTaskSnapshotV1;

struct TaskStamp {
    pidns_inode: u32,
    start_ns: u64,
}

pub(crate) struct ReuseResult {
    nspid: u32,
    second_ns: u32,
    first_pid: u32,
    second_pid: u32,
    first_live: u32,
    second_live: u32,
    root: NativeTaskSnapshotV1,
    first: NativeTaskSnapshotV1,
    second: NativeTaskSnapshotV1,
    first_stamp: TaskStamp,
    second_stamp: TaskStamp,
}

impl ReuseResult {
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
    }
}
