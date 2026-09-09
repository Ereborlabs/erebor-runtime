#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use mithril_node::{
    NativeIdentityInspector, NativeSecurityStateOwner, NativeTaskSnapshotV1, WorkloadBindingConfig,
};
use rustix::process::Signal;
use snafu::{ensure, ResultExt as _};

use super::super::{identity_next_id, invalid_state, IdentityTestRunner, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::physical::wait_for;
use crate::process::ProcessFixture;
use crate::Result;

pub(in crate::identity) struct ExecCase<'a> {
    runner: &'a IdentityTestRunner,
    host: &'a KernelHost,
    native: &'a NativeSecurityStateOwner,
    inspector: &'a NativeIdentityInspector,
    binding: &'a WorkloadBindingConfig,
    procs: &'a Path,
}

impl<'a> ExecCase<'a> {
    pub(in crate::identity) fn new(
        runner: &'a IdentityTestRunner,
        host: &'a KernelHost,
        native: &'a NativeSecurityStateOwner,
        inspector: &'a NativeIdentityInspector,
        binding: &'a WorkloadBindingConfig,
        procs: &'a Path,
    ) -> Self {
        Self {
            runner,
            host,
            native,
            inspector,
            binding,
            procs,
        }
    }

    pub(in crate::identity) fn child(
        &self,
        ready: &Path,
    ) -> Result<(
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
    )> {
        let mut actor =
            ProcessFixture::python(&self.runner.repo_root, "native_child_exec.py", [ready])?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.wait_root(root_pid)?;

        let next = identity_next_id(self.host)?;
        actor.send(b"root\n")?;
        let pid = match actor.wait_pid(ready, "native child creation") {
            Ok(pid) => pid,
            Err(source) => {
                let health = self.native.health(self.host).context(NodeSnafu)?;
                let after = identity_next_id(self.host)?;
                return Err(invalid_state(format!(
                    "{source}; identity health {health:?}; child allocation advanced next_id by {}",
                    after.saturating_sub(next)
                )));
            }
        };
        actor.track(pid)?;
        actor.wait_stop(pid, "native child stop")?;
        let before = self
            .runner
            .wait_for("native child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            root.creator_task_cookie.is_none()
                && root.root_class.as_deref() == Some("external_runtime_root")
                && root.installed_role_class.as_deref() == Some("runtime_external_restricted")
                && root.active_role_id == self.binding.external_role_id
                && root.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                && before.creator_task_cookie == Some(root.task_cookie)
                && before.real_parent_task_cookie == root.task_cookie
                && before.task_cookie != root.task_cookie
                && before.active_role_id == root.active_role_id
                && before.image_provenance_id == root.image_provenance_id
                && before.image_candidate_count > 0
                && before.process_execution_state == ProcessExecutionStateV1::Active as u8
                && before.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "external root or native child identity is incorrect",
            }
        );

        actor.signal(pid, Signal::CONT)?;
        let after = self.wait_child_exec(pid, &before)?;
        actor.stop()?;
        Ok((root, before, after))
    }

    pub(in crate::identity) fn non_leader(
        &self,
        ready: &Path,
    ) -> Result<(NativeTaskSnapshotV1, NativeTaskSnapshotV1)> {
        let mut actor =
            ProcessFixture::python(&self.runner.repo_root, "native_non_leader_exec.py", [ready])?;
        let pid = actor.id();
        fs::write(self.procs, pid.to_string()).context(IoSnafu { path: self.procs })?;

        let root = self.wait_root(pid)?;

        let next_id = identity_next_id(self.host)?;
        let expected_id = next_id.checked_add(2).ok_or_else(|| {
            invalid_state("identity ID sequence overflowed for non-leader thread")
        })?;
        actor.send(b"root\n")?;
        let tid = actor.wait_pid(ready, "non-leader thread creation")?;
        let thread_path = PathBuf::from(format!("/proc/{pid}/task/{tid}"));
        let actual_id = identity_next_id(self.host)?;
        ensure!(
            tid != pid && thread_path.is_dir() && actual_id == expected_id,
            InvalidInputSnafu {
                path: &thread_path,
                reason: format!(
                    "the non-leader thread needs one task identity; expected {expected_id}, got {actual_id}"
                ),
            }
        );

        actor.send(b"exec\n")?;
        let after = self.wait_exec(pid, next_id, &root)?;
        actor.stop()?;
        Ok((root, after))
    }

    fn wait_root(&self, pid: u32) -> Result<NativeTaskSnapshotV1> {
        let last = RefCell::new(None);
        wait_for(
            self.procs,
            "external root identity",
            WAIT_LIMIT,
            || {
                let Some(got) = self.inspector.snapshot(pid).context(NodeSnafu)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = Some(got.clone());
                Ok((got.creator_task_cookie.is_none()
                    && got.root_class.as_deref() == Some("external_runtime_root")
                    && got.installed_role_class.as_deref() == Some("runtime_external_restricted")
                    && got.active_role_id == self.binding.external_role_id
                    && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && got.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                    && got.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                    && got.exec_guard_state == ExecGuardStateV1::None as u8)
                    .then_some(got))
            },
            || format!("last identity snapshot: {:?}", last.borrow()),
        )
    }

    fn wait_exec(
        &self,
        pid: u32,
        id: u64,
        root: &NativeTaskSnapshotV1,
    ) -> Result<NativeTaskSnapshotV1> {
        self.runner
            .wait_for("non-leader thread exec", self.procs, || {
                let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
                Ok(got.filter(|got| {
                    got.task_cookie == id
                        && got.creator_task_cookie == Some(root.task_cookie)
                        && got.process_state_id == root.process_state_id
                        && got.active_execution_id != root.active_execution_id
                        && got.image_provenance_id != root.image_provenance_id
                        && got.active_role_id == root.active_role_id
                        && got.root_class.is_none()
                        && got.installed_role_class.is_none()
                        && got.host_tid == pid
                        && got.host_tgid == pid
                        && got.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                        && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                        && got.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                        && got.exec_guard_state == ExecGuardStateV1::None as u8
                }))
            })
    }

    fn wait_child_exec(
        &self,
        pid: u32,
        before: &NativeTaskSnapshotV1,
    ) -> Result<NativeTaskSnapshotV1> {
        let found = self.runner.wait_for("native exec commit", self.procs, || {
            let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
            Ok(got.filter(|got| {
                got.active_execution_id != before.active_execution_id
                    && got.image_provenance_id != before.image_provenance_id
                    && got.image_candidate_count > 0
                    && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && got.exec_guard_state == ExecGuardStateV1::None as u8
            }))
        });
        match found {
            Ok(got) => Ok(got),
            Err(source) => {
                let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
                let health = self.native.health(self.host).context(NodeSnafu)?;
                let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_else(|error| format!("<unavailable: {error}>"));
                let status = fs::read_to_string(format!("/proc/{pid}/status"))
                    .unwrap_or_else(|error| format!("<unavailable: {error}>"));
                Err(invalid_state(format!(
                    "{source}; live snapshot {got:?}; identity health {health:?}; comm {}; status {}",
                    comm.trim(),
                    status.lines().next().unwrap_or("<empty>")
                )))
            }
        }
    }
}
