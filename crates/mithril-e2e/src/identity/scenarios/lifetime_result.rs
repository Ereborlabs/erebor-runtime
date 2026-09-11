use std::cell::RefCell;
use std::time::Duration;

use erebor_interceptor_abi::{
    EntryLifetimeStateV1, EntrySecurityStateV1, Id128V1, ProcessExecutionInstanceV1,
    ProcessExecutionStateV1, ProcessSecurityStateKindV1, ProcessSecurityStateV1,
    ProcessStateVectorStateV1, ProcessStateVectorV1, ReferenceTombstoneStateV1,
    TaskCoordinateStateV1, TaskCoordinateV1, TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use snafu::ResultExt as _;
use zerocopy::{KnownLayout, TryFromBytes};

use crate::error::{InterceptorSnafu, InvalidInputSnafu};
use crate::physical::wait_for;
use crate::platform::{Platform, Task, Thread};
use crate::Result;

#[derive(Debug)]
pub(crate) struct LifetimeState {
    root: TaskCoordinateV1,
    worker: TaskCoordinateV1,
    process: ProcessSecurityStateV1,
    vector: ProcessStateVectorV1,
    entry: EntrySecurityStateV1,
    execution: ProcessExecutionInstanceV1,
    root_ref: TaskReferenceTombstoneV1,
    worker_ref: TaskReferenceTombstoneV1,
    profile: u64,
}

impl LifetimeState {
    pub(crate) fn wait_live<P: Platform>(env: &P, root: &Task, worker: &Thread) -> Result<Self> {
        Self::wait(env, root, worker, "leader exit", |state| {
            state.root.state == TaskCoordinateStateV1::Exited
                && state.process.state == ProcessSecurityStateKindV1::Active
                && state.process.live_thread_refs == 1
                && state.entry.live_task_refs == 1
                && state.profile == 1
                && state.root_ref.state == ReferenceTombstoneStateV1::Released
                && state.worker_ref.state == ReferenceTombstoneStateV1::Owned
        })
    }

    pub(crate) fn wait_dead<P: Platform>(env: &P, root: &Task, worker: &Thread) -> Result<Self> {
        Self::wait(env, root, worker, "worker exit", |state| {
            state.worker.state == TaskCoordinateStateV1::Exited
                && state.process.state == ProcessSecurityStateKindV1::Reclaimable
                && state.process.live_thread_refs == 0
                && state.vector.state == ProcessStateVectorStateV1::Retiring
                && state.execution.state == ProcessExecutionStateV1::Complete
                && state.entry.live_task_refs == 0
                && state.entry.lifetime_state == EntryLifetimeStateV1::Draining
                && state.profile == 0
                && state.worker_ref.state == ReferenceTombstoneStateV1::Released
        })
    }

    pub(crate) fn assert_live(&self, role: u32) {
        assert_eq!(self.process.active_role_id, role);
        assert_eq!(self.root_ref.task_free_observed, 1);
        assert_eq!(self.root_ref.released_bits, TASK_REFERENCE_ALL_V1);
        assert_eq!(self.worker_ref.task_free_observed, 0);
        assert_eq!(self.worker_ref.released_bits, 0);
    }

    pub(crate) fn assert_dead(&self) {
        assert_eq!(self.worker_ref.task_free_observed, 1);
        assert_eq!(self.worker_ref.released_bits, TASK_REFERENCE_ALL_V1);
    }

    fn wait<P: Platform>(
        env: &P,
        root: &Task,
        worker: &Thread,
        operation: &str,
        ready: impl Fn(&Self) -> bool,
    ) -> Result<Self> {
        let path = env.maps().0.to_owned();
        let last = RefCell::new(String::from("<absent>"));
        wait_for(
            &path,
            operation,
            Duration::from_secs(30),
            || {
                let Some(state) = Self::read(env, root, worker)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = format!("{state:?}");
                Ok(ready(&state).then_some(state))
            },
            || format!("last lifetime state: {}", last.borrow()),
        )
    }

    fn read<P: Platform>(env: &P, root: &Task, worker: &Thread) -> Result<Option<Self>> {
        let pkey = Self::key(root.coordinate.process_state_id);
        let Some(process) = Self::map::<P, ProcessSecurityStateV1>(env, "process_states", &pkey)?
        else {
            return Ok(None);
        };
        let Some(vector) =
            Self::map::<P, ProcessStateVectorV1>(env, "process_state_vectors", &pkey)?
        else {
            return Ok(None);
        };
        let Some(entry) = Self::map::<P, EntrySecurityStateV1>(
            env,
            "entry_states",
            &Self::key(process.entry_instance_id),
        )?
        else {
            return Ok(None);
        };
        let Some(execution) = Self::map::<P, ProcessExecutionInstanceV1>(
            env,
            "process_execution_instances",
            &Self::key(process.active_execution_id),
        )?
        else {
            return Ok(None);
        };
        let Some(root_coord) = env.coordinate(root.coordinate.task_cookie)? else {
            return Ok(None);
        };
        let Some(worker_coord) = env.coordinate(worker.coordinate.task_cookie)? else {
            return Ok(None);
        };
        let Some(root_ref) = env.tombstone(root.coordinate.task_cookie)? else {
            return Ok(None);
        };
        let Some(worker_ref) = env.tombstone(worker.coordinate.task_cookie)? else {
            return Ok(None);
        };
        let (_, reader) = env.maps();
        let Some(bytes) = reader
            .lookup(
                "profile_generation_task_refs",
                &root.snapshot.profile_generation_ref_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        let profile = u64::from_ne_bytes(bytes.as_slice().try_into().map_err(|_| {
            InvalidInputSnafu {
                path: env.maps().0,
                reason: "profile reference count is invalid",
            }
            .build()
        })?);
        Ok(Some(Self {
            root: root_coord,
            worker: worker_coord,
            process,
            vector,
            entry,
            execution,
            root_ref,
            worker_ref,
            profile,
        }))
    }

    fn map<P, T>(env: &P, name: &str, key: &[u8]) -> Result<Option<T>>
    where
        P: Platform,
        T: KnownLayout + TryFromBytes,
    {
        let (_, reader) = env.maps();
        reader
            .lookup(name, key)
            .context(InterceptorSnafu)?
            .map(|bytes| {
                T::try_read_from_bytes(&bytes).map_err(|source| {
                    InvalidInputSnafu {
                        path: env.maps().0,
                        reason: format!("{name} value is invalid: {source}"),
                    }
                    .build()
                })
            })
            .transpose()
    }

    fn key(id: Id128V1) -> [u8; 16] {
        let mut key = [0; 16];
        key[..8].copy_from_slice(&id.high.to_ne_bytes());
        key[8..].copy_from_slice(&id.low.to_ne_bytes());
        key
    }
}
