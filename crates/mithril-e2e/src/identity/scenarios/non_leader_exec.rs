use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};
use mithril_node::{NativeIdentityInspector, NativeTaskSnapshotV1, WorkloadBindingConfig};
use snafu::{ensure, ResultExt as _};

use super::super::{identity_next_id, IdentityTestRunner, NativeProcessFixture, WAIT_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu, NodeSnafu};
use crate::physical::wait_for;
use crate::Result;

pub(in crate::identity) fn run(
    runner: &IdentityTestRunner,
    host: &KernelHost,
    inspector: &NativeIdentityInspector,
    binding: &WorkloadBindingConfig,
    procs_path: &Path,
    ready_path: &Path,
) -> Result<(NativeTaskSnapshotV1, NativeTaskSnapshotV1)> {
    let mut fixture =
        NativeProcessFixture::start_with_non_leader_exec(&runner.repo_root, ready_path)?;
    let root_pid = fixture.outer_pid();
    fs::write(procs_path, root_pid.to_string()).context(IoSnafu { path: procs_path })?;

    let last_root = RefCell::new(None);
    let root = wait_for(
        procs_path,
        "non-leader thread exec root identity",
        WAIT_LIMIT,
        || {
            let Some(snapshot) = inspector.snapshot(root_pid).context(NodeSnafu)? else {
                return Ok(None);
            };
            *last_root.borrow_mut() = Some(snapshot.clone());
            Ok((snapshot.creator_task_cookie.is_none()
                && snapshot.root_class.as_deref() == Some("external_runtime_root")
                && snapshot.installed_role_class.as_deref() == Some("runtime_external_restricted")
                && snapshot.active_role_id == binding.external_role_id
                && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                && snapshot.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                && snapshot.exec_guard_state == ExecGuardStateV1::None as u8)
                .then_some(snapshot))
        },
        || format!("last identity snapshot: {:?}", last_root.borrow()),
    )?;
    ensure!(
        root.creator_task_cookie.is_none()
            && root.root_class.as_deref() == Some("external_runtime_root")
            && root.installed_role_class.as_deref() == Some("runtime_external_restricted")
            && root.active_role_id == binding.external_role_id
            && root.coordinate_state == TaskCoordinateStateV1::Runnable as u8,
        InvalidInputSnafu {
            path: procs_path,
            reason: "non-leader thread exec root has the wrong identity",
        }
    );

    let next_id_before_thread = identity_next_id(host)?;
    let expected_next_id = next_id_before_thread.checked_add(2).ok_or_else(|| {
        super::super::invalid_state("identity ID sequence overflowed for non-leader thread")
    })?;
    fixture.release_root()?;
    let thread_tid =
        fixture.wait_for_reported_tid(ready_path, "non-leader Python thread creation")?;
    let thread_path = PathBuf::from(format!("/proc/{root_pid}/task/{thread_tid}"));
    let next_id_after_thread = identity_next_id(host)?;
    ensure!(
        thread_tid != root_pid && thread_path.is_dir() && next_id_after_thread == expected_next_id,
        InvalidInputSnafu {
            path: &thread_path,
            reason: format!(
                "non-leader Python thread did not receive one exact task identity; expected next ID {expected_next_id}, got {next_id_after_thread}"
            ),
        }
    );

    fixture.release_non_leader_exec()?;
    let after_exec = runner.wait_for("non-leader thread exec commit", procs_path, || {
        let snapshot = inspector.snapshot(root_pid).context(NodeSnafu)?;
        Ok(snapshot.filter(|snapshot| {
            snapshot.task_cookie == next_id_before_thread
                && snapshot.creator_task_cookie == Some(root.task_cookie)
                && snapshot.process_state_id == root.process_state_id
                && snapshot.active_execution_id != root.active_execution_id
                && snapshot.image_provenance_id != root.image_provenance_id
                && snapshot.active_role_id == root.active_role_id
                && snapshot.root_class.is_none()
                && snapshot.installed_role_class.is_none()
                && snapshot.host_tid == root_pid
                && snapshot.host_tgid == root_pid
                && snapshot.coordinate_state == TaskCoordinateStateV1::Runnable as u8
                && snapshot.process_execution_state == ProcessExecutionStateV1::Active as u8
                && snapshot.process_state_vector_state == ProcessStateVectorStateV1::Active as u8
                && snapshot.exec_guard_state == ExecGuardStateV1::None as u8
        }))
    })?;
    fixture.stop()?;
    Ok((root, after_exec))
}
