use std::{fs, os::unix::fs::MetadataExt as _};

use erebor_interceptor_abi::ExecutionSetBindingStateV1;
use mithril_node::{NativeSecurityStateOwner, WorkloadBindingOwner};
use snafu::ResultExt as _;

use crate::error::NodeSnafu;
use crate::identity::{retained::RetainedHost, test_binding};
use crate::physical::boot_identity;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

fn root_binding<P: Platform>(env: &P, id: u64) -> TestResult<ExecutionSetBindingStateV1> {
    let value = env.state(
        "execution_set_bindings",
        &id.to_ne_bytes(),
        "cgroup binding",
    )?;
    value.ok_or_else(|| format!("cgroup {id} has no binding").into())
}

#[platform_test(host)]
fn cgroup_path_gets_fresh_identity<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-reuse")?;
    let pin = env.maps().0.to_owned();
    let group = env.actor_group()?.to_owned();
    let (_, node) = boot_identity()?;
    let mut host = RetainedHost::start(&pin)?;
    let binding = test_binding(&group);
    let identity = NativeSecurityStateOwner::new(node, 1);
    let mut first = ProcessFixture::python(env.source(), "ready.py", std::iter::empty::<&str>())?;
    env.place(first.id())?;
    let mut bindings = WorkloadBindingOwner::system(node, 1).context(NodeSnafu)?;
    bindings
        .publish_all(host.host()?, std::slice::from_ref(&binding))
        .context(NodeSnafu)?;
    identity.activate(host.host_mut()?).context(NodeSnafu)?;
    let first_task = env.task(first.id(), "first cgroup lifetime")?;
    let first_id = fs::metadata(&group)?.ino();
    let first_bind = root_binding(&env, first_id)?;
    first.stop()?;
    let first_cookie = first_task.snapshot.task_cookie;
    env.task_release(first_cookie, "first cgroup lifetime release")?;

    host.shutdown()?;
    host.restart()?;
    let mut bindings = WorkloadBindingOwner::system(node, 1).context(NodeSnafu)?;
    bindings
        .publish_all(host.host()?, std::slice::from_ref(&binding))
        .context(NodeSnafu)?;
    identity.activate(host.host_mut()?).context(NodeSnafu)?;
    fs::remove_dir(&group)?;
    fs::create_dir(&group)?;

    let mut second = ProcessFixture::python(env.source(), "ready.py", std::iter::empty::<&str>())?;
    env.place(second.id())?;
    let mut binding = test_binding(&group);
    binding.container_id = "c".repeat(64);
    binding.pod_uid = "identity-pod-uid-reused".to_owned();
    binding.sandbox_id = "identity-sandbox-reused".to_owned();
    binding.container_generation = 2;
    let mut bindings = WorkloadBindingOwner::system(node, 1).context(NodeSnafu)?;
    bindings
        .publish_all(host.host()?, std::slice::from_ref(&binding))
        .context(NodeSnafu)?;
    identity.activate(host.host_mut()?).context(NodeSnafu)?;
    let second_task = env.task(second.id(), "second cgroup lifetime")?;
    let second_id = fs::metadata(&group)?.ino();
    let second_bind = root_binding(&env, second_id)?;
    let first_state = &first_task.snapshot;
    let second_state = &second_task.snapshot;

    assert_ne!(second_id, first_id);
    assert_ne!(second_bind.binding_nonce, first_bind.binding_nonce);
    assert_ne!(
        second_bind.root_cgroup_live_interval_id,
        first_bind.root_cgroup_live_interval_id
    );
    assert_ne!(second_state.task_cookie, first_state.task_cookie);
    assert_ne!(second_state.process_state_id, first_state.process_state_id);
    assert_ne!(
        second_state.active_execution_id,
        first_state.active_execution_id
    );
    assert_eq!(second_state.creator_task_cookie, None);
    assert_eq!(
        second_state.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    assert_eq!(
        second_state.installed_role_class.as_deref(),
        Some("fail_closed_unknown")
    );
    assert_eq!(second_state.active_role_id, binding.external_role_id);

    second.stop()?;
    host.stop()?;
    env.stop()
}
