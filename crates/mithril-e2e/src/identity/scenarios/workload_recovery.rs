use std::time::Duration;

use rustix::io::Errno;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
fn workload_recovers<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("workload-recovery")?;
    env.start_control()?;

    let mut actor = env.start_actor("native_recovery.py", &[])?;
    let pid = actor.id();
    env.place(pid)?;

    env.install_policy()?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let root = env.recovered(pid, "recovered actor identity")?;
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
    assert_eq!(recovery.expected_task_count, 1);
    assert_eq!(recovery.application_task_count, 1);
    assert_eq!(recovery.external_task_count, 0);
    assert_eq!(recovery.invalid_task_count, 0);

    actor.send(b"effect\n")?;
    let code = env.actor_code(&mut actor, "denied executable", Duration::from_secs(5))?;
    assert_eq!(code, Errno::ACCESS.raw_os_error());
    env.stop()
}
