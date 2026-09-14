use std::os::unix::fs::MetadataExt as _;

use erebor_interceptor_abi::{
    BindingLifecycleStateV1, ExecutionSetBindingStateV1, TaskCoordinateStateV1,
};
use mithril_node::{NativeSecurityStateOwner, WorkloadBindingOwner};
use snafu::ResultExt as _;
use zerocopy::IntoBytes as _;

use crate::error::{InterceptorSnafu, NodeSnafu};
use crate::identity::{profile_task_refs, retained::RetainedHost, test_binding, WAIT_LIMIT};
use crate::physical::{boot_identity, wait_for};
use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
#[scope = "binding-gap"]
fn binding_gap_stays_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("binding-gap")?;
    let pin = env.maps().0.to_owned();
    let group = env.actor_group()?.to_owned();
    let (_, node) = boot_identity()?;
    let mut host = RetainedHost::start(&pin)?;
    let script = actor_script(env.source(), "ready.py")?;
    let mut actor = ProcessFixture::python(&script, std::iter::empty::<&str>())?;
    env.place(actor.id())?;

    let binding = test_binding(&group);
    let mut bindings = WorkloadBindingOwner::system(node, 1).context(NodeSnafu)?;
    bindings
        .publish_all(host.host()?, std::slice::from_ref(&binding))
        .context(NodeSnafu)?;
    let identity = NativeSecurityStateOwner::new(node, 1);
    let report = identity.activate(host.host_mut()?).context(NodeSnafu)?;
    let root = env.task(actor.id(), "binding-gap root")?;
    let root_state = &root.snapshot;
    let root_class = root_state.root_class.as_deref();
    let role_class = root_state.installed_role_class.as_deref();

    assert_eq!(root_state.creator_task_cookie, None);
    assert_eq!(root_class, Some("restored_or_unknown_root"));
    assert_eq!(role_class, Some("fail_closed_unknown"));
    assert_eq!(root_state.active_role_id, binding.external_role_id);
    assert_eq!(
        root_state.coordinate_state,
        TaskCoordinateStateV1::Runnable as u8
    );
    assert_eq!(report.allocation_failures, 0);
    assert_eq!(report.coordinate_failures, 0);
    assert_eq!(report.reconciliation_required, 0);

    let root_id = std::fs::metadata(&group)?.ino();
    let mut state = env
        .state::<ExecutionSetBindingStateV1>(
            "execution_set_bindings",
            &root_id.to_ne_bytes(),
            "binding-gap state",
        )?
        .ok_or("the binding-gap state is missing")?;
    state.lifecycle_state = BindingLifecycleStateV1::Terminating;
    state.transition_version += 1;
    host.host()?
        .update_map(
            "execution_set_bindings",
            &root_id.to_ne_bytes(),
            state.as_bytes(),
        )
        .context(InterceptorSnafu)?;
    identity
        .recover_tasks(host.host_mut()?, false)
        .context(NodeSnafu)?;

    state.lifecycle_state = BindingLifecycleStateV1::Active;
    state.transition_version += 1;
    host.host()?
        .update_map(
            "execution_set_bindings",
            &root_id.to_ne_bytes(),
            state.as_bytes(),
        )
        .context(InterceptorSnafu)?;
    identity
        .recover_tasks(host.host_mut()?, false)
        .context(NodeSnafu)?;

    actor.stop()?;
    let refs = wait_for(
        &group,
        "profile reference release",
        WAIT_LIMIT,
        || {
            let value = profile_task_refs(host.host()?)?;
            Ok((value == 0).then_some(value))
        },
        || "the profile still has task references".to_owned(),
    )?;
    assert_eq!(refs, 0);
    host.stop()?;
    env.stop()
}
