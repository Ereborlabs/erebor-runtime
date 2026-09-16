use std::time::Duration;

use erebor_interceptor_abi::{
    ExecGuardStateV1, ProcessExecutionStateV1, ProcessStateVectorStateV1, TaskCoordinateStateV1,
};

use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::identity::fixture::IdentityFixture;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity_physical]
fn child_enters_mount_ns<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clone-mount-exec")?;
    let group = env.actor_group()?.to_owned();
    let pin = env.maps().0.to_owned();
    let owner = IdentityFixture::start(&group, &pin)?;
    let mut clone = CloneIntoCgroupFixture::start_with_mount_namespace_target(&group)?;
    let root_pid = clone.root_pid();

    let root = env.task(root_pid, "clone root")?;
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    clone.release_root()?;
    let pid = wait_for(
        &group,
        "clone child creation",
        Duration::from_secs(5),
        || clone.child_pid(),
        || format!("clone root PID {root_pid} has no child"),
    )
    .map_err(|source| {
        format!(
            "{source}; root identity: {:?}; health: {:?}",
            root.snapshot,
            env.health()
        )
    })?;
    let before = env.task(pid, "clone child")?;
    assert_eq!(
        before.snapshot.creator_task_cookie,
        Some(root.snapshot.task_cookie)
    );
    assert_eq!(
        before.snapshot.real_parent_task_cookie,
        root.snapshot.task_cookie
    );
    assert_eq!(before.snapshot.root_class, None);
    assert_eq!(before.coordinate.state, TaskCoordinateStateV1::Runnable);

    let old_mount = clone.child_mount(pid)?;
    let target = clone.target_mount_namespace()?;
    assert_ne!(old_mount, target);
    clone.release_child_into_mount_namespace()?;
    assert_eq!(clone.wait_child_exec(pid, &target, "sleep")?, target);
    let after = env.wait_pid_exec(
        pid,
        before.snapshot.task_cookie,
        &before,
        "clone child exec",
    )?;
    let a = &after.snapshot;
    let b = &before.snapshot;
    assert_eq!(a.task_cookie, b.task_cookie);
    assert_eq!(a.creator_task_cookie, b.creator_task_cookie);
    assert_eq!(a.real_parent_task_cookie, b.real_parent_task_cookie);
    assert_eq!(a.process_state_id, b.process_state_id);
    assert_ne!(a.active_execution_id, b.active_execution_id);
    assert_ne!(a.image_provenance_id, b.image_provenance_id);
    assert_eq!(a.active_role_id, b.active_role_id);
    assert_eq!(a.root_class, None);
    assert_eq!(a.installed_role_class, None);
    assert_eq!(after.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(
        a.process_execution_state,
        ProcessExecutionStateV1::Active as u8
    );
    assert_eq!(
        a.process_state_vector_state,
        ProcessStateVectorStateV1::Active as u8
    );
    assert_eq!(a.exec_guard_state, ExecGuardStateV1::None as u8);

    clone.stop()?;
    owner.stop()?;
    env.stop()
}
