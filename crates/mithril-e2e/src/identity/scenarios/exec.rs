use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ExecGuardStateV1, PendingExecStateV1, PendingExecV1, ProcessExecutionInstanceV1,
    ProcessExecutionStateV1, ProcessSecurityStateKindV1, ProcessSecurityStateV1,
    ProcessStateVectorStateV1, ReferenceTombstoneStateV1, TaskCoordinateStateV1, TaskCoordinateV1,
    TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use mithril_node::{NativeIdentityInspector, NativeTaskSnapshotV1, WorkloadBindingConfig};
use rustix::process::Signal;
use snafu::{ensure, ResultExt as _};

use super::super::{
    id_bytes, id_key, optional_abi_map, required_abi_map, IdentityTestRunner, WAIT_LIMIT,
};
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, NodeSnafu};
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

pub(in crate::identity) struct FatalState {
    pub(in crate::identity) pending: u8,
    pub(in crate::identity) guard: u8,
    pub(in crate::identity) coord: u8,
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

    pub(in crate::identity) fn retry(
        &self,
        ready: &Path,
        failed: &Path,
        target: &Path,
    ) -> Result<(
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
        NativeTaskSnapshotV1,
    )> {
        let mut actor = ProcessFixture::python(
            &self.runner.repo_root,
            "native_exec_retry.py",
            [ready, failed, target],
        )?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.wait_root(root_pid)?;

        actor.send(b"root\n")?;
        let pid = actor.wait_pid(ready, "failed exec child")?;
        actor.track(pid)?;
        actor.wait_stop(pid, "pre-exec stop")?;
        let before = self
            .runner
            .wait_for("failed exec child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        let pending = self
            .host
            .lookup_map("pending_execs", &before.task_cookie.to_ne_bytes())
            .context(InterceptorSnafu)?;
        ensure!(
            root.root_class.as_deref() == Some("external_runtime_root")
                && root.installed_role_class.as_deref() == Some("runtime_external_restricted")
                && pending.is_none()
                && before.creator_task_cookie == Some(root.task_cookie)
                && before.real_parent_task_cookie == root.task_cookie
                && before.root_class.is_none()
                && before.installed_role_class.is_none()
                && before.process_execution_state == ProcessExecutionStateV1::Active as u8
                && before.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                && before.exec_guard_state == ExecGuardStateV1::None as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: format!(
                    "failed-exec child has the wrong identity; parent {root:?}; child {before:?}; pending {}",
                    pending.is_some()
                ),
            }
        );

        actor.signal(pid, Signal::CONT)?;
        let restored = self
            .runner
            .wait_for("failed exec restoration", failed, || {
                if !failed.exists() {
                    return Ok(None);
                }
                let Some(got) = self.inspector.snapshot(pid).context(NodeSnafu)? else {
                    return Ok(None);
                };
                let pending = self
                    .host
                    .lookup_map("pending_execs", &got.task_cookie.to_ne_bytes())
                    .context(InterceptorSnafu)?;
                Ok((pending.is_none()
                    && got.task_cookie == before.task_cookie
                    && got.creator_task_cookie == before.creator_task_cookie
                    && got.real_parent_task_cookie == before.real_parent_task_cookie
                    && got.active_execution_id == before.active_execution_id
                    && got.image_provenance_id == before.image_provenance_id
                    && got.active_role_id == before.active_role_id
                    && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && got.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                    && got.exec_guard_state == ExecGuardStateV1::None as u8)
                    .then_some(got))
            })?;

        actor.wait_stop(pid, "failed exec stop")?;
        actor.signal(pid, Signal::CONT)?;
        let after = self
            .runner
            .wait_for("normal exec after failure", self.procs, || {
                let Some(got) = self.inspector.snapshot(pid).context(NodeSnafu)? else {
                    return Ok(None);
                };
                let pending = self
                    .host
                    .lookup_map("pending_execs", &got.task_cookie.to_ne_bytes())
                    .context(InterceptorSnafu)?;
                Ok((pending.is_none()
                    && got.task_cookie == restored.task_cookie
                    && got.creator_task_cookie == restored.creator_task_cookie
                    && got.real_parent_task_cookie == restored.real_parent_task_cookie
                    && got.active_execution_id != restored.active_execution_id
                    && got.image_provenance_id != restored.image_provenance_id
                    && got.active_role_id == restored.active_role_id
                    && got.process_execution_state == ProcessExecutionStateV1::Active as u8
                    && got.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                    && got.exec_guard_state == ExecGuardStateV1::None as u8)
                    .then_some(got))
            })?;
        ensure!(
            after.root_class.is_none()
                && after.installed_role_class.is_none()
                && after.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "normal exec after failure did not restore a runnable task",
            }
        );
        actor.stop()?;
        Ok((before, restored, after))
    }

    pub(in crate::identity) fn fatal(&self, ready: &Path, target: &Path) -> Result<FatalState> {
        let mut actor = ProcessFixture::python(
            &self.runner.repo_root,
            "native_fatal_exec.py",
            [ready, target],
        )?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.wait_root(root_pid)?;

        actor.send(b"root\n")?;
        let pid = actor.wait_pid(ready, "fatal exec child")?;
        actor.track(pid)?;
        actor.wait_stop(pid, "fatal exec stop")?;
        let before = self
            .runner
            .wait_for("fatal exec child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            before.creator_task_cookie == Some(root.task_cookie)
                && before.active_role_id == root.active_role_id
                && before.exec_guard_state == ExecGuardStateV1::None as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "fatal exec child did not inherit the restricted identity",
            }
        );
        let task_key = before.task_cookie.to_ne_bytes();
        let proc_key = id_key(&before.process_state_id)?;

        actor.signal(pid, Signal::CONT)?;
        let status = actor.wait_exit("fatal exec", WAIT_LIMIT)?;
        ensure!(
            !status.success() && !PathBuf::from(format!("/proc/{pid}")).exists(),
            InvalidInputSnafu {
                path: target,
                reason: format!("fatal exec did not terminate its task; actor status {status}"),
            }
        );
        let (pending, process, coord, tombstone, source, target_exec) =
            self.runner
                .wait_for("fatal exec identity", self.procs, || {
                    let Some(pending) = optional_abi_map::<PendingExecV1>(
                        self.host,
                        "pending_execs",
                        &task_key,
                        "fatal pending exec",
                    )?
                    else {
                        return Ok(None);
                    };
                    let process = required_abi_map::<ProcessSecurityStateV1>(
                        self.host,
                        "process_states",
                        &proc_key,
                        "fatal process state",
                    )?;
                    let coord = required_abi_map::<TaskCoordinateV1>(
                        self.host,
                        "task_coordinates",
                        &task_key,
                        "fatal task coordinate",
                    )?;
                    let tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                        self.host,
                        "task_reference_tombstones",
                        &task_key,
                        "fatal task tombstone",
                    )?;
                    let source = required_abi_map::<ProcessExecutionInstanceV1>(
                        self.host,
                        "process_execution_instances",
                        &id_bytes(pending.source_execution_id),
                        "fatal source execution",
                    )?;
                    let target_exec = required_abi_map::<ProcessExecutionInstanceV1>(
                        self.host,
                        "process_execution_instances",
                        &id_bytes(pending.target_execution_id),
                        "fatal target execution",
                    )?;
                    Ok((pending.state == PendingExecStateV1::PostPonrFatal
                        && process.exec_guard_state == ExecGuardStateV1::OutcomeUnknown
                        && process.state == ProcessSecurityStateKindV1::Reclaimable
                        && process.live_thread_refs == 0
                        && coord.state == TaskCoordinateStateV1::Exited
                        && tombstone.task_free_observed == 1
                        && tombstone.released_bits == TASK_REFERENCE_ALL_V1
                        && tombstone.state == ReferenceTombstoneStateV1::Released
                        && source.state == ProcessExecutionStateV1::Complete
                        && target_exec.state == ProcessExecutionStateV1::OutcomeUnknown)
                        .then_some((pending, process, coord, tombstone, source, target_exec)))
                })?;
        ensure!(
            process.active_role_id == before.active_role_id
                && process.active_execution_id == pending.source_execution_id
                && pending.source_role_id == before.active_role_id
                && coord.task_cookie == before.task_cookie
                && tombstone.task_cookie == before.task_cookie
                && source.process_execution_instance_id == pending.source_execution_id
                && target_exec.process_execution_instance_id == pending.target_execution_id,
            InvalidInputSnafu {
                path: target,
                reason: "fatal exec restored or replaced the source restriction",
            }
        );
        actor.stop()?;
        Ok(FatalState {
            pending: pending.state as u8,
            guard: process.exec_guard_state as u8,
            coord: coord.state as u8,
        })
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
