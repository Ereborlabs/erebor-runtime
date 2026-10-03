use std::fs;

use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = recovery_exit]
fn external_exit_preserves_recovery<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("post-cutover-exit")?;
    env.start_control()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../../fixtures/process/actor_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut app = env.start_actor("recovery_tree.py", &[], &labels)?;
    env.place(app.id())?;
    fs::create_dir(env.work().join("external"))?;
    let mut ext = env.add_actor("python", &["/fixtures/recovery_tree.py", "/work/external"])?;
    env.place(ext.id())?;
    app.send(b"fork\n")?;
    let app_child = app.wait_child(app.id(), "application child")?;
    app.track(app_child)?;
    ext.send(b"fork\n")?;
    let ext_child = ext.wait_child(ext.id(), "external child")?;
    ext.track(ext_child)?;
    env.install_policy("actor_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(app.id())?;

    let before = env.recovered(app.id(), "four-task recovery")?.snapshot;
    let recovery = before
        .recovered_container_activation
        .as_ref()
        .ok_or("application recovery is missing")?;
    assert_eq!(recovery.phase, "complete");
    assert_eq!(
        (
            recovery.expected_task_count,
            recovery.application_task_count,
            recovery.external_task_count,
            recovery.invalid_task_count
        ),
        (4, 2, 2, 0)
    );
    let initial = before
        .runtime_binding
        .as_ref()
        .ok_or("application binding is missing")?;
    assert_eq!(initial.lifecycle_state, "active_recovered");
    assert_eq!(
        initial.prepared_container_entry_instance_id,
        recovery.application_entry_instance_id
    );
    assert_eq!(
        before.entry_instance_id,
        recovery.application_entry_instance_id
    );
    assert!(before.admitted_entry_rule_id > 0);
    let outside = env.task(ext.id(), "recovered external root")?.snapshot;
    assert_eq!(outside.admitted_entry_rule_id, 0);
    assert_ne!(outside.entry_instance_id, before.entry_instance_id);
    assert_ne!(outside.active_role_id, before.active_role_id);

    fs::write(env.work().join("external/recovery-stop"), b"stop\n")?;
    ext.stop()?;
    let after = env
        .task(app.id(), "application after external exit")?
        .snapshot;
    let current = after
        .runtime_binding
        .as_ref()
        .ok_or("external exit removed the application binding")?;
    assert_eq!(current.lifecycle_state, "active_recovered");
    assert_eq!(current.binding_id, initial.binding_id);
    assert_eq!(
        current.prepared_container_entry_instance_id,
        recovery.application_entry_instance_id
    );
    assert_eq!(after.entry_instance_id, before.entry_instance_id);
    assert_eq!(after.admitted_entry_rule_id, before.admitted_entry_rule_id);
    assert_eq!(after.task_cookie, before.task_cookie);
    assert_eq!(after.active_role_id, before.active_role_id);

    fs::write(env.work().join("recovery-stop"), b"stop\n")?;
    app.stop()?;
    env.stop()
}
