use std::fs;
use std::os::unix::fs::MetadataExt as _;

use mithril_control::ContainerKindV1;

use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(kubernetes)]
#[lifecycle = identity]
fn ephemeral_actor_is_isolated<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("ephemeral-container")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("container_kinds_policy.json")?;
    env.node_ready()?;

    let actors = [
        GroupActor {
            name: "application",
            script: Some("ready.py"),
            args: &[],
            kind: ContainerKindV1::Application,
        },
        GroupActor {
            name: "debugger",
            script: Some("ready.py"),
            args: &[],
            kind: ContainerKindV1::Ephemeral,
        },
    ];
    let mut group = env.start_actor_group(&actors, &labels, |_, group| {
        assert!(
            group.is_empty(),
            "the Application actor started out of order"
        );
        Ok(())
    })?;
    assert_eq!(group.len(), 2);

    let app = env.task(group[0].0.id(), "Application actor")?;
    let debug = env.task(group[1].0.id(), "Ephemeral actor")?;
    let app_ns = fs::metadata(format!("/proc/{}/ns/pid", app.pid))?.ino();
    let debug_ns = fs::metadata(format!("/proc/{}/ns/pid", debug.pid))?.ino();
    assert_ne!(app_ns, 0);
    assert_eq!(app_ns, debug_ns, "the Ephemeral actor missed its target");

    for task in [&app, &debug] {
        assert_eq!(
            task.snapshot.root_class.as_deref(),
            Some("initial_container_root")
        );
        assert_eq!(task.snapshot.creator_task_cookie, None);
        assert_eq!(
            task.snapshot.installed_role_class.as_deref(),
            Some("initial_role")
        );
        assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    }
    assert_ne!(app.snapshot.task_cookie, debug.snapshot.task_cookie);
    assert_ne!(
        app.snapshot.process_state_id,
        debug.snapshot.process_state_id
    );
    assert_ne!(
        app.snapshot.active_execution_id,
        debug.snapshot.active_execution_id
    );
    assert_ne!(
        app.snapshot.execution_set_id,
        debug.snapshot.execution_set_id
    );
    assert_ne!(
        app.snapshot.profile_generation_ref_id,
        debug.snapshot.profile_generation_ref_id
    );
    assert_ne!(app.snapshot.active_role_id, debug.snapshot.active_role_id);
    let app_bind = app
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("missing Application binding")?;
    let debug_bind = debug
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("missing Ephemeral binding")?;
    assert_ne!(app_bind.root_cgroup_id, debug_bind.root_cgroup_id);

    for (actor, _) in group.iter_mut().rev() {
        actor.stop()?;
    }
    env.stop()
}
