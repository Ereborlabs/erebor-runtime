use crate::platform::{platform_test, Platform, TestResult};
use std::fs;

#[platform_test(host, runc, kubernetes)]
#[scope = "recovery-tasks"]
fn four_tasks_recover<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("four-task-recovery")?;
    env.start_control()?;
    let mut app = env.start_actor("recovery_tree.py", &[])?;
    env.place(app.id())?;
    let mut ext = env.add_actor("python", &["/fixtures/recovery_tree.py", "/work"])?;
    env.place(ext.id())?;
    app.send(b"fork\n")?;
    let app_child = app.wait_child(app.id(), "application child")?;
    app.track(app_child)?;
    ext.send(b"fork\n")?;
    let ext_child = ext.wait_child(ext.id(), "external child")?;
    ext.track(ext_child)?;
    env.install_policy()?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(app.id())?;
    let root = env.recovered(app.id(), "four-task recovery")?;
    let binding = root
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("the recovered actor has no runtime binding")?;
    let recovery = root
        .snapshot
        .recovered_container_activation
        .as_ref()
        .ok_or("the recovered actor has no recovery result")?;
    assert_eq!(binding.lifecycle_state, "active_recovered");
    assert_eq!(
        binding.prepared_container_entry_instance_id,
        root.snapshot.entry_instance_id
    );
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert!(root.snapshot.active_role_id > 0);
    assert!(root.snapshot.admitted_entry_rule_id > 0);
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(recovery.phase, "complete");
    assert_ne!(
        recovery.recovery_attempt_id,
        "00000000000000000000000000000000"
    );
    assert_eq!(
        recovery.application_entry_instance_id,
        root.snapshot.entry_instance_id
    );
    assert_eq!(
        (
            recovery.expected_task_count,
            recovery.application_task_count
        ),
        (4, 2)
    );
    assert_eq!(
        (recovery.external_task_count, recovery.invalid_task_count),
        (2, 0)
    );
    let outside = env.task(ext.id(), "recovered external root")?;
    assert_eq!(
        outside
            .snapshot
            .runtime_binding
            .as_ref()
            .map(|value| value.lifecycle_state.as_str()),
        Some("active_recovered")
    );
    assert_eq!(outside.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(
        outside.snapshot.active_role_id,
        root.snapshot.active_role_id
    );
    assert_ne!(
        outside.snapshot.entry_instance_id,
        root.snapshot.entry_instance_id
    );
    assert_eq!(
        outside.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );
    fs::write(env.work().join("recovery-stop"), b"stop\n")?;
    app.wait_gone(app.id(), "application actor exit")?;
    ext.wait_gone(ext.id(), "external actor exit")?;
    app.stop()?;
    ext.stop()?;
    env.stop()
}
