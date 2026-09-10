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
use mithril_node::{
    NativeIdentityInspector, NativeSecurityStateOwner, NativeTaskSnapshotV1, WorkloadBindingConfig,
};
use rustix::process::Signal;
use snafu::{ensure, ResultExt as _};

use super::super::{
    id_bytes, id_key, identity_next_id, invalid_state, optional_abi_map, required_abi_map,
    IdentityTestRunner, WAIT_LIMIT,
};
use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu, NodeSnafu};
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

pub(in crate::identity) struct FatalState {
    pub(in crate::identity) pending: u8,
    pub(in crate::identity) guard: u8,
    pub(in crate::identity) coord: u8,
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

    pub(in crate::identity) fn moved(
        &self,
        ready: &Path,
        failed: &Path,
        parent: &Path,
    ) -> Result<()> {
        let target = Path::new("/bin/sleep");
        let mut actor = ProcessFixture::python(
            &self.runner.repo_root,
            "native_exec_retry.py",
            [ready, failed, target],
        )?;
        let root_pid = actor.id();
        fs::write(self.procs, root_pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.wait_root(root_pid)?;
        let old_health = self.native.health(self.host).context(NodeSnafu)?;
        let next = identity_next_id(self.host)?;

        actor.send(b"root\n")?;
        let pid = match actor.wait_pid(ready, "moved exec child") {
            Ok(pid) => pid,
            Err(source) => {
                let health = self.native.health(self.host).context(NodeSnafu)?;
                let after = identity_next_id(self.host)?;
                return Err(invalid_state(format!(
                    "{source}; parent {root:?}; identity health changed from {old_health:?} to {health:?}; child allocation advanced next_id by {}",
                    after.saturating_sub(next)
                )));
            }
        };
        actor.track(pid)?;
        actor.wait_stop(pid, "moved exec stop")?;
        let before = self
            .runner
            .wait_for("moved exec child identity", self.procs, || {
                self.inspector.snapshot(pid).context(NodeSnafu)
            })?;
        ensure!(
            before.creator_task_cookie == Some(root.task_cookie)
                && before.real_parent_task_cookie == root.task_cookie
                && before.task_cookie != root.task_cookie
                && before.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
            InvalidInputSnafu {
                path: self.procs,
                reason: "moved exec child has the wrong pre-move identity",
            }
        );

        let old_health = self.native.health(self.host).context(NodeSnafu)?;
        fs::write(parent, pid.to_string()).context(IoSnafu { path: parent })?;
        let after = self.runner.wait_for("moved exec fail closed", parent, || {
            let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
            Ok(got.filter(|got| {
                got.task_cookie == before.task_cookie
                    && got.creator_task_cookie == before.creator_task_cookie
                    && got.real_parent_task_cookie == before.real_parent_task_cookie
                    && got.coordinate_state == TaskCoordinateStateV1::FailClosedUnknown as u8
            }))
        })?;
        let move_health = self.native.health(self.host).context(NodeSnafu)?;
        ensure!(
            after.root_class.is_none()
                && after.installed_role_class.is_none()
                && move_health.placement_mismatches > old_health.placement_mismatches,
            InvalidInputSnafu {
                path: parent,
                reason: "moving a labeled child did not fail closed",
            }
        );

        actor.signal(pid, Signal::CONT)?;
        actor.wait_path(
            failed,
            "moved exec denial",
            WAIT_LIMIT,
            || Ok(failed.exists().then_some(())),
            || "the exec failure marker is absent".to_owned(),
        )?;
        actor.wait_stop(pid, "moved exec denial stop")?;
        let exec_health = self.native.health(self.host).context(NodeSnafu)?;
        ensure!(
            exec_health.placement_mismatches > move_health.placement_mismatches,
            InvalidInputSnafu {
                path: parent,
                reason: "a moved labeled child did not record its denied exec",
            }
        );
        actor.stop()
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
