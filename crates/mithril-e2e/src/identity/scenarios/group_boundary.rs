use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn each_group_is_one_workload<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("group-boundary")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("group_roles_policy.json")?;
    env.node_ready()?;

    let actors = [GroupActor {
        name: "worker",
        script: Some("read_path.py"),
        args: &["worker"],
    }];
    let mut first = env
        .start_actor_group("pid-reuse-pod-v1.yaml", &actors, &labels, |_, _| Ok(()))
        .map_err(|error| format!("first group: {error}"))?;
    let before = env.task(first[0].0.id(), "first group identity")?;
    let mut second = env
        .start_actor_group("pid-reuse-pod-v1.yaml", &actors, &labels, |_, _| Ok(()))
        .map_err(|error| format!("second group: {error}"))?;
    let after = env.task(second[0].0.id(), "second group identity")?;

    assert_ne!(before.snapshot.task_cookie, after.snapshot.task_cookie);
    assert_ne!(
        before.snapshot.process_state_id,
        after.snapshot.process_state_id
    );
    assert_ne!(
        before.snapshot.execution_set_id,
        after.snapshot.execution_set_id
    );
    assert_eq!(
        before.snapshot.active_role_id,
        after.snapshot.active_role_id
    );
    let a = before
        .snapshot
        .runtime_binding
        .ok_or("first binding missing")?;
    let b = after
        .snapshot
        .runtime_binding
        .ok_or("second binding missing")?;
    assert_ne!(a.binding_id, b.binding_id);
    assert_ne!(a.root_cgroup_id, b.root_cgroup_id);

    for group in [&mut first, &mut second] {
        group[0].0.send(b"/fixtures/policy_replace.py\n")?;
        let path = group[0].1.join("0.json");
        let result = group[0].0.wait_text(&path, "worker read")?;
        let (errno, size): (i32, usize) = serde_json::from_str(&result)?;
        assert_eq!(errno, 0, "worker read: {result}");
        assert!(size > 0, "worker read: {result}");
        group[0].0.stop()?;
    }
    env.stop()
}
