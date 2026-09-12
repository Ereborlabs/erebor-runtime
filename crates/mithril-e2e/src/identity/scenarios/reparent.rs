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

pub(in crate::identity) struct NamespaceState {
    pub(in crate::identity) root: NativeTaskSnapshotV1,
    pub(in crate::identity) nspid: u32,
    pub(in crate::identity) middle: NativeTaskSnapshotV1,
    pub(in crate::identity) before: NativeTaskSnapshotV1,
    pub(in crate::identity) after: NativeTaskSnapshotV1,
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

    pub(in crate::identity) fn subreaper(
        &self,
        ready: &Path,
    ) -> Result<(
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
    )> {
        let mut actor =
            ProcessFixture::python(&self.runner.repo_root, "native_subreaper.py", [ready])?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.root(root_pid)?;

        actor.send(b"root\n")?;
        let [mid, pid] = actor.wait_pair(ready, "subreaper children")?;
        ensure!(
            mid != root_pid && pid != root_pid,
            InvalidInputSnafu {
                path: ready,
                reason: "the subreaper reported its own PID as a child",
            }
        );
        actor.track(mid)?;
        actor.track(pid)?;
        actor.wait_stop(pid, "subreaper child stop")?;
        let middle = self
            .runner
            .wait_for("subreaper middle identity", self.procs, || {
                self.inspector.snapshot(mid).context(NodeSnafu)
            })?;
        let before = self
            .runner
            .wait_for("subreaper child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            middle.creator_task_cookie == Some(root.task_cookie)
                && middle.real_parent_task_cookie == root.task_cookie
                && middle.real_parent_host_tid == root.host_tid
                && middle.real_parent_host_tgid == root.host_tgid
                && middle.root_class.is_none()
                && middle.installed_role_class.is_none()
                && before.creator_task_cookie == Some(middle.task_cookie)
                && before.real_parent_task_cookie == middle.task_cookie
                && before.real_parent_host_tid == middle.host_tid
                && before.real_parent_host_tgid == middle.host_tgid
                && before.root_class.is_none()
                && before.installed_role_class.is_none()
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "the subreaper child has the wrong pre-exit identity",
            }
        );

        actor.signal(mid, Signal::TERM)?;
        actor.wait_gone(mid, "subreaper middle exit")?;
        actor.signal(pid, Signal::CONT)?;
        let after = self
            .runner
            .wait_for("subreaper child exec", self.procs, || {
                let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
                Ok(got.filter(|got| {
                    got.task_cookie == before.task_cookie
                        && got.creator_task_cookie == Some(middle.task_cookie)
                        && got.real_parent_task_cookie == 0
                        && got.real_parent_host_tid == root.host_tid
                        && got.real_parent_host_tgid == root.host_tgid
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
                reason: "the subreaper child lost its inherited restriction",
            }
        );
        actor.stop()?;
        Ok((root, middle, before, after))
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

    pub(in crate::identity) fn namespace(&self, ready: [&Path; 3]) -> Result<NamespaceState> {
        let [init_path, mid_path, child_path] = ready;
        let work = init_path.parent().ok_or_else(|| {
            InvalidInputSnafu {
                path: init_path,
                reason: "the namespace init path has no parent directory".to_owned(),
            }
            .build()
        })?;
        let mut actor =
            ProcessFixture::unshare(&self.runner.repo_root, "native_namespace_init.py", [work])?;
        let init_ns = actor.wait_pid(init_path, "namespace init PID")?;
        let init = actor.wait_child(actor.id(), "namespace init host PID")?;
        actor.track(init)?;
        let nspid = ProcessFixture::namespace_pid(init)?;
        ensure!(
            nspid == init_ns && nspid == 1,
            InvalidInputSnafu {
                path: init_path,
                reason: "the namespace init process does not have namespace PID 1",
            }
        );
        fs::write(self.procs, init.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.root(init)?;

        actor.send(b"root\n")?;
        let mid_ns = actor.wait_pid(mid_path, "namespace middle PID")?;
        let mid = actor.wait_child(init, "namespace middle host PID")?;
        ensure!(
            ProcessFixture::namespace_pid(mid)? == mid_ns,
            InvalidInputSnafu {
                path: mid_path,
                reason: "the namespace middle PID did not map to its host PID",
            }
        );
        actor.track(mid)?;
        actor.wait_stop(mid, "namespace middle stop")?;
        let middle = self
            .runner
            .wait_for("namespace middle identity", self.procs, || {
                self.inspector.snapshot(mid).context(NodeSnafu)
            })?;
        actor.send(b"continue\n")?;
        let child_ns = actor.wait_pid(child_path, "namespace child PID")?;
        let pid = actor.wait_child(mid, "namespace child host PID")?;
        ensure!(
            ProcessFixture::namespace_pid(pid)? == child_ns,
            InvalidInputSnafu {
                path: child_path,
                reason: "the namespace child PID did not map to its host PID",
            }
        );
        actor.track(pid)?;
        actor.wait_stop(pid, "namespace child stop")?;
        let before = self
            .runner
            .wait_for("namespace child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            middle.creator_task_cookie == Some(root.task_cookie)
                && middle.real_parent_task_cookie == root.task_cookie
                && middle.real_parent_host_tid == root.host_tid
                && middle.real_parent_host_tgid == root.host_tgid
                && middle.root_class.is_none()
                && middle.installed_role_class.is_none()
                && before.creator_task_cookie == Some(middle.task_cookie)
                && before.real_parent_task_cookie == middle.task_cookie
                && before.real_parent_host_tid == middle.host_tid
                && before.real_parent_host_tgid == middle.host_tgid
                && before.root_class.is_none()
                && before.installed_role_class.is_none()
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "the namespace child has the wrong pre-exit identity",
            }
        );

        actor.send(b"reparent\n")?;
        actor.wait_gone(mid, "namespace middle exit")?;
        let after = self
            .runner
            .wait_for("namespace child exec", self.procs, || {
                let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
                Ok(got.filter(|got| {
                    got.task_cookie == before.task_cookie
                        && got.creator_task_cookie == Some(middle.task_cookie)
                        && got.real_parent_task_cookie == 0
                        && got.real_parent_host_tid == root.host_tid
                        && got.real_parent_host_tgid == root.host_tgid
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
                reason: "the namespace child lost its inherited restriction",
            }
        );
        actor.stop()?;
        Ok(NamespaceState {
            root,
            nspid,
            middle,
            before,
            after,
        })
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
