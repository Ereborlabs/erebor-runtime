use std::fs;
use std::path::Path;

use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use mithril_node::{NativeIdentityInspector, NativeTaskSnapshotV1};
use rustix::process::Signal;
use snafu::{ensure, ResultExt as _};

use super::super::IdentityTestRunner;
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::process::ProcessFixture;
use crate::Result;

pub(in crate::identity) struct ReparentCase<'a> {
    runner: &'a IdentityTestRunner,
    inspector: &'a NativeIdentityInspector,
    procs: &'a Path,
}

impl<'a> ReparentCase<'a> {
    pub(in crate::identity) fn new(
        runner: &'a IdentityTestRunner,
        inspector: &'a NativeIdentityInspector,
        procs: &'a Path,
    ) -> Self {
        Self {
            runner,
            inspector,
            procs,
        }
    }

    pub(in crate::identity) fn double_fork(
        &self,
        ready: &Path,
    ) -> Result<(
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
    )> {
        let mut actor =
            ProcessFixture::python(&self.runner.repo_root, "native_double_fork.py", [ready])?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.root(root_pid)?;

        actor.send(b"root\n")?;
        let [mid, pid] = actor.wait_pair(ready, "double-fork children")?;
        ensure!(
            mid != root_pid && pid != root_pid,
            InvalidInputSnafu {
                path: ready,
                reason: "the double-fork actor reported its own PID as a child",
            }
        );
        actor.track(mid)?;
        actor.track(pid)?;
        actor.wait_stop(pid, "double-fork child stop")?;
        let middle = self
            .runner
            .wait_for("double-fork middle identity", self.procs, || {
                self.inspector.snapshot(mid).context(NodeSnafu)
            })?;
        let before = self
            .runner
            .wait_for("double-fork child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            middle.creator_task_cookie == Some(root.task_cookie)
                && middle.real_parent_task_cookie == root.task_cookie
                && middle.root_class.is_none()
                && middle.installed_role_class.is_none()
                && before.creator_task_cookie == Some(middle.task_cookie)
                && before.real_parent_task_cookie == middle.task_cookie
                && before.root_class.is_none()
                && before.installed_role_class.is_none()
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "the double-fork child has the wrong pre-exit identity",
            }
        );

        actor.signal(mid, Signal::TERM)?;
        actor.wait_gone(mid, "double-fork middle exit")?;
        actor.signal(pid, Signal::CONT)?;
        let after = self
            .runner
            .wait_for("double-fork child exec", self.procs, || {
                let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
                Ok(got.filter(|got| {
                    got.task_cookie == before.task_cookie
                        && got.creator_task_cookie == Some(middle.task_cookie)
                        && got.real_parent_task_cookie != middle.task_cookie
                        && got.real_parent_interval_sequence > before.real_parent_interval_sequence
                        && got.active_execution_id != before.active_execution_id
                        && got.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && got.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                        && got.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            })?;
        ensure!(
            after.root_class.is_none()
                && after.installed_role_class.is_none()
                && after.active_role_id == root.active_role_id,
            InvalidInputSnafu {
                path: self.procs,
                reason: "the double-fork child lost its inherited restriction",
            }
        );
        actor.stop()?;
        Ok((root, middle, before, after))
    }

    fn root(&self, pid: u32) -> Result<NativeTaskSnapshotV1> {
        self.runner.wait_for("external root", self.procs, || {
            let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
            Ok(got.filter(|got| {
                got.creator_task_cookie.is_none()
                    && got.root_class.as_deref() == Some("external_runtime_root")
                    && got.installed_role_class.as_deref() == Some("runtime_external_restricted")
                    && got.coordinate_state == TaskCoordinateStateV1::Runnable as u8
            }))
        })
    }
}
