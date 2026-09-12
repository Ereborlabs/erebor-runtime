use std::cell::RefCell;
use std::fs;
use std::path::Path;

use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use mithril_node::{NativeIdentityInspector, NativeTaskSnapshotV1, WorkloadBindingConfig};
use rustix::process::Signal;
use snafu::{ensure, ResultExt as _};

use super::super::{IdentityTestRunner, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::physical::wait_for;
use crate::process::ProcessFixture;
use crate::Result;

pub(in crate::identity) struct ExecCase<'a> {
    runner: &'a IdentityTestRunner,
    inspector: &'a NativeIdentityInspector,
    binding: &'a WorkloadBindingConfig,
    procs: &'a Path,
}

impl<'a> ExecCase<'a> {
    pub(in crate::identity) fn new(
        runner: &'a IdentityTestRunner,
        inspector: &'a NativeIdentityInspector,
        binding: &'a WorkloadBindingConfig,
        procs: &'a Path,
    ) -> Self {
        Self {
            runner,
            inspector,
            binding,
            procs,
        }
    }

    pub(in crate::identity) fn orphan(
        &self,
        ready: &Path,
    ) -> Result<(
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
    )> {
        let mut actor =
            ProcessFixture::python(&self.runner.repo_root, "native_orphan.py", [ready])?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.wait_root(root_pid)?;

        actor.send(b"root\n")?;
        let pid = actor.wait_pid(ready, "orphan child")?;
        actor.track(pid)?;
        actor.wait_stop(pid, "orphan child stop")?;
        let before = self
            .runner
            .wait_for("orphan child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            before.creator_task_cookie == Some(root.task_cookie)
                && before.real_parent_task_cookie == root.task_cookie
                && before.root_class.is_none()
                && before.installed_role_class.is_none()
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "orphan child has the wrong pre-exit identity",
            }
        );

        actor.send(b"parent-exit\n")?;
        let status = actor.wait_exit("orphan parent exit", WAIT_LIMIT)?;
        ensure!(
            status.success(),
            InvalidInputSnafu {
                path: self.procs,
                reason: format!("orphan parent exited with {status}"),
            }
        );
        actor.signal(pid, Signal::CONT)?;
        let after = self.runner.wait_for("orphan child exec", self.procs, || {
            let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
            Ok(got.filter(|got| {
                got.task_cookie == before.task_cookie
                    && got.creator_task_cookie == Some(root.task_cookie)
                    && got.real_parent_task_cookie != root.task_cookie
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
                reason: "orphan child lost its inherited restriction",
            }
        );
        actor.stop()?;
        Ok((root, before, after))
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
}
