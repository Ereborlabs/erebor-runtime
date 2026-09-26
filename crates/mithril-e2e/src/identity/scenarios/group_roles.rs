use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn container_roles_are_distinct<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("group-roles")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("group_roles_policy.json")?;
    env.node_ready()?;

    let actors = [
        GroupActor {
            name: "worker",
            script: Some("read_path.py"),
            args: &["worker"],
        },
        GroupActor {
            name: "helper",
            script: Some("read_path.py"),
            args: &["helper"],
        },
    ];
    let mut group = env.start_actor_group("pid-reuse-pod-v1.yaml", &actors, &labels)?;
    let first = env.task(group[0].0.id(), "worker identity")?;
    let second = env.task(group[1].0.id(), "helper identity")?;
    assert_ne!(first.snapshot.task_cookie, second.snapshot.task_cookie);
    assert_ne!(
        first.snapshot.active_role_id,
        second.snapshot.active_role_id
    );
    assert_eq!(
        first.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    assert_eq!(
        second.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    let first_binding = first
        .snapshot
        .runtime_binding
        .ok_or("worker binding missing")?;
    let second_binding = second
        .snapshot
        .runtime_binding
        .ok_or("helper binding missing")?;
    assert_ne!(first_binding.binding_id, second_binding.binding_id);
    assert_ne!(first_binding.root_cgroup_id, second_binding.root_cgroup_id);

    for (actor, _) in &mut group {
        actor.send(b"/fixtures/policy_replace.py\n")?;
    }
    let first_path = group[0].1.join("0.json");
    let second_path = group[1].1.join("0.json");
    let allowed = group[0].0.wait_text(&first_path, "worker read")?;
    let denied = group[1].0.wait_text(&second_path, "helper read")?;
    let (allowed_errno, allowed_size): (i32, usize) = serde_json::from_str(&allowed)?;
    let (denied_errno, denied_size): (i32, usize) = serde_json::from_str(&denied)?;
    assert_eq!(allowed_errno, 0, "worker read: {allowed}");
    assert!(allowed_size > 0);
    assert_eq!(denied_errno, libc::EACCES, "helper read: {denied}");
    assert_eq!(denied_size, 0);

    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
