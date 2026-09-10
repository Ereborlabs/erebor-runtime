use mithril_node::NativeTaskSnapshotV1;
use std::cell::RefCell;
use std::path::Path;
use std::time::Duration;

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{
    CreatedByEdgeV1, IdentityRuntimeConfigV1, ReferenceTombstoneStateV1, TaskCoordinateStateV1,
    TaskCoordinateV1, TaskReferenceTombstoneV1, TASK_REFERENCE_ALL_V1,
};
use snafu::ResultExt as _;
use zerocopy::TryFromBytes as _;

use crate::error::{InterceptorSnafu, InvalidInputSnafu};
use crate::physical::wait_for;

mod cri;
mod host;
mod kubernetes;
mod runc;

pub(crate) use self::cri::CriFixture;
pub(crate) use self::host::Host;
pub(crate) use self::kubernetes::Kubernetes;
pub(crate) use self::runc::Runc;
pub(crate) use mithril_e2e_macros::platform_test;
pub(crate) type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const TASK_LIMIT: Duration = Duration::from_secs(30);

pub(crate) struct Task {
    pub(crate) pid: u32,
    pub(crate) ns_pid: u32,
    pub(crate) snapshot: NativeTaskSnapshotV1,
    pub(crate) coordinate: TaskCoordinateV1,
}

pub(crate) struct Thread {
    pub(crate) pid: u32,
    pub(crate) ns_tid: u32,
    pub(crate) coordinate: TaskCoordinateV1,
    pub(crate) edge: CreatedByEdgeV1,
}

pub(crate) trait Platform: Sized {
    fn setup(_name: &str) -> TestResult<Self> {
        pending("setup")
    }
    fn start_control(&mut self) -> TestResult<()> {
        pending("start Control")
    }
    fn start_node(&mut self) -> TestResult<()> {
        pending("start Node")
    }
    fn install_policy(&mut self) -> TestResult<()> {
        pending("install policy")
    }
    fn node_ready(&mut self) -> TestResult<()> {
        pending("wait for Node")
    }
    fn start_actor(
        &mut self,
        _name: &str,
        _args: &[&str],
    ) -> TestResult<crate::process::ProcessFixture> {
        pending("start actor")
    }
    fn place(&mut self, _pid: u32) -> TestResult<()> {
        pending("place actor")
    }
    fn stage(&mut self) -> TestResult<()> {
        pending("stage actor")
    }
    fn admit(&mut self, _pid: u32) -> TestResult<()> {
        pending("admit actor")
    }
    fn task(&mut self, _pid: u32, _name: &str) -> TestResult<Task> {
        pending("read task")
    }
    fn maps(&self) -> (&Path, &KernelStateReader);
    fn coordinate(&self, task: u64) -> crate::Result<Option<TaskCoordinateV1>> {
        let (pin, reader) = self.maps();
        let Some(bytes) = reader
            .lookup("task_coordinates", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        TaskCoordinateV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: pin,
                    reason: format!("task coordinate is invalid: {source}"),
                }
                .build()
            })
    }
    fn edge(&self, task: u64) -> crate::Result<Option<CreatedByEdgeV1>> {
        let (pin, reader) = self.maps();
        let Some(bytes) = reader
            .lookup("created_by_edges", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        CreatedByEdgeV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: pin,
                    reason: format!("creator edge is invalid: {source}"),
                }
                .build()
            })
    }
    fn tombstone(&self, task: u64) -> crate::Result<Option<TaskReferenceTombstoneV1>> {
        let (pin, reader) = self.maps();
        let Some(bytes) = reader
            .lookup("task_reference_tombstones", &task.to_ne_bytes())
            .context(InterceptorSnafu)?
        else {
            return Ok(None);
        };
        TaskReferenceTombstoneV1::try_read_from_bytes(&bytes)
            .map(Some)
            .map_err(|source| {
                InvalidInputSnafu {
                    path: pin,
                    reason: format!("task tombstone is invalid: {source}"),
                }
                .build()
            })
    }
    fn next_id(&self) -> TestResult<u64> {
        let (_, reader) = self.maps();
        let bytes = reader
            .lookup("identity_config", &0_u32.to_ne_bytes())
            .context(InterceptorSnafu)?
            .ok_or("identity runtime configuration is missing")?;
        Ok(IdentityRuntimeConfigV1::try_read_from_bytes(&bytes)
            .map_err(|source| format!("identity runtime configuration is invalid: {source}"))?
            .next_id)
    }
    fn thread(&mut self, pid: u32, ns_tid: u32, task: u64, name: &str) -> TestResult<Thread> {
        let pin = self.maps().0;
        let last = RefCell::new(String::from("coordinate=<absent>; edge=<absent>"));
        Ok(wait_for(
            pin,
            name,
            TASK_LIMIT,
            || {
                let coordinate = self.coordinate(task)?;
                let edge = self.edge(task)?;
                *last.borrow_mut() = format!("coordinate={coordinate:?}; edge={edge:?}");
                Ok(coordinate.zip(edge).map(|(coordinate, edge)| Thread {
                    pid,
                    ns_tid,
                    coordinate,
                    edge,
                }))
            },
            || format!("task cookie {task}; last state: {}", last.borrow()),
        )?)
    }
    fn task_exit(&mut self, task: u64, name: &str) -> TestResult<TaskCoordinateV1> {
        let pin = self.maps().0;
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            pin,
            name,
            TASK_LIMIT,
            || {
                let Some(value) = self.coordinate(task)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = format!("{value:?}");
                Ok((value.state == TaskCoordinateStateV1::Exited).then_some(value))
            },
            || format!("task cookie {task}; last coordinate: {}", last.borrow()),
        )?)
    }
    fn task_release(&mut self, task: u64, name: &str) -> TestResult<TaskReferenceTombstoneV1> {
        let pin = self.maps().0;
        let last = RefCell::new(String::from("<absent>"));
        Ok(wait_for(
            pin,
            name,
            TASK_LIMIT,
            || {
                let Some(value) = self.tombstone(task)? else {
                    return Ok(None);
                };
                *last.borrow_mut() = format!("{value:?}");
                Ok((value.task_free_observed == 1
                    && value.released_bits == TASK_REFERENCE_ALL_V1
                    && value.state == ReferenceTombstoneStateV1::Released)
                    .then_some(value))
            },
            || format!("task cookie {task}; last tombstone: {}", last.borrow()),
        )?)
    }
    fn work(&self) -> &Path {
        Path::new(".")
    }
    fn output(&self) -> &Path {
        Path::new(".")
    }
    fn stop(&mut self) -> TestResult<()> {
        pending("stop fixture")
    }
}

fn pending<T>(name: &str) -> TestResult<T> {
    Err(format!("{name} is not implemented for this platform").into())
}
