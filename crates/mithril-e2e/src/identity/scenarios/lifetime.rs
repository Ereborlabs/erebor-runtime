use std::fs;
use std::mem::offset_of;
use std::path::Path;
use std::time::Duration;

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    CreatedByEdgeV1, EntryLifetimeStateV1, EntrySecurityStateV1, ProcessExecutionInstanceV1,
    ProcessExecutionStateV1, ProcessSecurityStateKindV1, ProcessSecurityStateV1,
    ProcessStateVectorStateV1, ProcessStateVectorV1, ReferenceTombstoneStateV1,
    TaskCoordinateStateV1, TaskCoordinateV1, TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use mithril_node::NativeIdentityInspector;
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use snafu::{ensure, ResultExt as _};

use super::super::{
    id_bytes, id_key, identity_next_id, invalid_state, profile_task_refs, read_u64, read_u8,
    required_abi_map, required_map_bytes, IdentityTestRunner,
};
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::process::ProcessFixture;
use crate::Result;

pub(in crate::identity) struct LifetimeCase<'a> {
    runner: &'a IdentityTestRunner,
    host: &'a KernelHost,
    inspector: &'a NativeIdentityInspector,
    procs: &'a Path,
}

pub(in crate::identity) struct LeaderState {
    pub(in crate::identity) task: u64,
    pub(in crate::identity) no_pidfd: bool,
    pub(in crate::identity) leader: LeaderRefs,
    pub(in crate::identity) worker: WorkerRefs,
}

pub(in crate::identity) struct LeaderRefs {
    pub(in crate::identity) process: u64,
    pub(in crate::identity) entry: u64,
    pub(in crate::identity) profile: u64,
    pub(in crate::identity) root_done: bool,
    pub(in crate::identity) worker_owned: bool,
}

pub(in crate::identity) struct WorkerRefs {
    pub(in crate::identity) process: u64,
    pub(in crate::identity) entry: u64,
    pub(in crate::identity) profile: u64,
    pub(in crate::identity) process_done: bool,
    pub(in crate::identity) entry_done: bool,
    pub(in crate::identity) worker_done: bool,
}

impl<'a> LifetimeCase<'a> {
    pub(in crate::identity) fn new(
        runner: &'a IdentityTestRunner,
        host: &'a KernelHost,
        inspector: &'a NativeIdentityInspector,
        procs: &'a Path,
    ) -> Self {
        Self {
            runner,
            host,
            inspector,
            procs,
        }
    }

    pub(in crate::identity) fn leader(&self, ready: &Path, release: &Path) -> Result<LeaderState> {
        self.runner
            .wait_for("native reference baseline", self.procs, || {
                Ok((profile_task_refs(self.host)? == 0).then_some(()))
            })
            .map_err(|source| {
                invalid_state(format!(
                    "{source}; live cgroup tasks `{}`; profile refs {}",
                    fs::read_to_string(self.procs).unwrap_or_default().trim(),
                    profile_task_refs(self.host).unwrap_or(u64::MAX)
                ))
            })?;

        let mut actor = ProcessFixture::python(
            &self.runner.repo_root,
            "native_leader_first.py",
            [ready, release],
        )?;
        let pid = actor.id();
        fs::write(self.procs, pid.to_string()).context(IoSnafu { path: self.procs })?;
        let root = self.runner.wait_for("leader-first root", self.procs, || {
            let got = self.inspector.snapshot(pid).context(NodeSnafu)?;
            Ok(got.filter(|got| {
                got.creator_task_cookie.is_none()
                    && got.root_class.as_deref() == Some("external_runtime_root")
                    && got.installed_role_class.as_deref() == Some("runtime_external_restricted")
                    && got.coordinate_state == TaskCoordinateStateV1::Runnable as u8
            }))
        })?;
        let pkey = id_key(&root.process_state_id)?;
        let process = required_abi_map::<ProcessSecurityStateV1>(
            self.host,
            "process_states",
            &pkey,
            "leader-first process state",
        )?;
        let ekey = id_bytes(process.entry_instance_id);
        let next = identity_next_id(self.host)?;

        actor.send(b"root\n")?;
        let tid = actor.wait_pid(ready, "leader-first worker")?;
        let raw = i32::try_from(tid)
            .map_err(|source| invalid_state(format!("worker TID {tid} is invalid: {source}")))?;
        let thread = Pid::from_raw(raw)
            .ok_or_else(|| invalid_state("worker TID zero cannot have a pidfd"))?;
        let no_pidfd = pidfd_open(thread, PidfdFlags::empty()).is_err();
        let coord = required_abi_map::<TaskCoordinateV1>(
            self.host,
            "task_coordinates",
            &next.to_ne_bytes(),
            "leader-first worker coordinate",
        )?;
        let created = required_abi_map::<CreatedByEdgeV1>(
            self.host,
            "created_by_edges",
            &next.to_ne_bytes(),
            "leader-first worker creator edge",
        )?;
        ensure!(
            no_pidfd
                && identity_next_id(self.host)? == next + 2
                && coord.task_cookie == next
                && coord.host_tid == tid
                && coord.host_tgid == root.host_tgid
                && coord.process_state_id == process.process_state_id
                && coord.state == TaskCoordinateStateV1::Runnable
                && created.child_task_cookie == next
                && created.creator_task_cookie == root.task_cookie,
            InvalidInputSnafu {
                path: ready,
                reason: "the worker did not receive one exact native identity",
            }
        );

        let leader = self
            .runner
            .wait_for("leader reference release", self.procs, || {
                let root_coord = required_abi_map::<TaskCoordinateV1>(
                    self.host,
                    "task_coordinates",
                    &root.task_cookie.to_ne_bytes(),
                    "leader-first root coordinate",
                )?;
                let process = required_abi_map::<ProcessSecurityStateV1>(
                    self.host,
                    "process_states",
                    &pkey,
                    "leader-first live process",
                )?;
                let entry = required_map_bytes(
                    self.host,
                    "entry_states",
                    &ekey,
                    "leader-first live entry",
                )?;
                let entry_refs = read_u64(
                    &entry,
                    offset_of!(EntrySecurityStateV1, live_task_refs),
                    "leader-first live entry references",
                )?;
                let root_dead = required_abi_map::<TaskReferenceTombstoneV1>(
                    self.host,
                    "task_reference_tombstones",
                    &root.task_cookie.to_ne_bytes(),
                    "leader-first root tombstone",
                )?;
                let worker_dead = required_abi_map::<TaskReferenceTombstoneV1>(
                    self.host,
                    "task_reference_tombstones",
                    &next.to_ne_bytes(),
                    "leader-first worker tombstone",
                )?;
                let profile = profile_task_refs(self.host)?;
                let root_done = root_dead.task_free_observed == 1
                    && root_dead.released_bits == TASK_REFERENCE_ALL_V1
                    && root_dead.state == ReferenceTombstoneStateV1::Released;
                let worker_owned = worker_dead.task_free_observed == 0
                    && worker_dead.released_bits == 0
                    && worker_dead.state == ReferenceTombstoneStateV1::Owned;
                Ok((root_coord.state == TaskCoordinateStateV1::Exited
                    && process.state == ProcessSecurityStateKindV1::Active
                    && process.live_thread_refs == 1
                    && process.active_role_id == root.active_role_id
                    && entry_refs == 1
                    && profile == 1
                    && root_done
                    && worker_owned)
                    .then_some(LeaderRefs {
                        process: process.live_thread_refs,
                        entry: entry_refs,
                        profile,
                        root_done,
                        worker_owned,
                    }))
            })?;

        fs::write(release, b"release\n").context(IoSnafu { path: release })?;
        let status = actor.wait_exit("leader-first worker exit", Duration::from_secs(5))?;
        ensure!(
            status.success(),
            InvalidInputSnafu {
                path: release,
                reason: format!("the leader-first actor exited with {status}"),
            }
        );
        let worker = self
            .runner
            .wait_for("worker reference release", self.procs, || {
                let coord = required_abi_map::<TaskCoordinateV1>(
                    self.host,
                    "task_coordinates",
                    &next.to_ne_bytes(),
                    "leader-first exited worker coordinate",
                )?;
                let process = required_abi_map::<ProcessSecurityStateV1>(
                    self.host,
                    "process_states",
                    &pkey,
                    "leader-first retired process",
                )?;
                let vector = required_abi_map::<ProcessStateVectorV1>(
                    self.host,
                    "process_state_vectors",
                    &pkey,
                    "leader-first retired process vector",
                )?;
                let execution = required_abi_map::<ProcessExecutionInstanceV1>(
                    self.host,
                    "process_execution_instances",
                    &id_bytes(process.active_execution_id),
                    "leader-first completed execution",
                )?;
                let entry = required_map_bytes(
                    self.host,
                    "entry_states",
                    &ekey,
                    "leader-first draining entry",
                )?;
                let entry_refs = read_u64(
                    &entry,
                    offset_of!(EntrySecurityStateV1, live_task_refs),
                    "leader-first final entry references",
                )?;
                let lifetime = read_u8(
                    &entry,
                    offset_of!(EntrySecurityStateV1, lifetime_state),
                    "leader-first entry lifetime",
                )?;
                let tombstone = required_abi_map::<TaskReferenceTombstoneV1>(
                    self.host,
                    "task_reference_tombstones",
                    &next.to_ne_bytes(),
                    "leader-first released worker tombstone",
                )?;
                let profile = profile_task_refs(self.host)?;
                let process_done = process.state == ProcessSecurityStateKindV1::Reclaimable
                    && process.live_thread_refs == 0
                    && vector.state == ProcessStateVectorStateV1::Retiring
                    && execution.state == ProcessExecutionStateV1::Complete;
                let entry_done =
                    entry_refs == 0 && lifetime == EntryLifetimeStateV1::Draining as u8;
                let worker_done = tombstone.task_free_observed == 1
                    && tombstone.released_bits == TASK_REFERENCE_ALL_V1
                    && tombstone.state == ReferenceTombstoneStateV1::Released;
                Ok((coord.state == TaskCoordinateStateV1::Exited
                    && process_done
                    && entry_done
                    && profile == 0
                    && worker_done)
                    .then_some(WorkerRefs {
                        process: process.live_thread_refs,
                        entry: entry_refs,
                        profile,
                        process_done,
                        entry_done,
                        worker_done,
                    }))
            })?;
        actor.stop()?;
        Ok(LeaderState {
            task: next,
            no_pidfd,
            leader,
            worker,
        })
    }
}
