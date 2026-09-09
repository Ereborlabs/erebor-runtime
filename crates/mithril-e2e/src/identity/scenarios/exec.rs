#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use mithril_node::{NativeIdentityInspector, NativeTaskSnapshotV1, WorkloadBindingConfig};
use snafu::{ensure, ResultExt as _};

use super::super::{identity_next_id, invalid_state, IdentityTestRunner, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::physical::wait_for;
use crate::process::ProcessFixture;
use crate::Result;

pub(in crate::identity) struct ExecCase<'a> {
    runner: &'a IdentityTestRunner,
    host: &'a KernelHost,
    inspector: &'a NativeIdentityInspector,
    binding: &'a WorkloadBindingConfig,
    procs: &'a Path,
}

impl<'a> ExecCase<'a> {
    pub(in crate::identity) fn new(
        runner: &'a IdentityTestRunner,
        host: &'a KernelHost,
        inspector: &'a NativeIdentityInspector,
        binding: &'a WorkloadBindingConfig,
        procs: &'a Path,
    ) -> Self {
        Self {
            runner,
            host,
            inspector,
            binding,
            procs,
        }
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
            "non-leader exec root identity",
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
}
