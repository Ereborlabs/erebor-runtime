use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn repeated_entry_is_fresh<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-reentry")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("runtime_exec.py", &[])?;

    let args = ["/fixtures/ready.py"];
    let mut first = env.add_actor("python", &args)?;
    let one = env.task(first.id(), "first Python entry")?;
    let mut second = env.add_actor("python", &args)?;
    let two = env.task(second.id(), "second Python entry")?;

    for task in [&one, &two] {
        assert_eq!(task.snapshot.creator_task_cookie, None);
        assert_eq!(
            task.snapshot.root_class.as_deref(),
            Some("external_runtime_root")
        );
        assert_eq!(
            task.snapshot.installed_role_class.as_deref(),
            Some("qualified_registered_role")
        );
        assert_eq!(task.snapshot.active_role_id, 4);
        assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
        assert_ne!(task.snapshot.profile_generation_ref_id, 0);
    }
    assert_eq!(one.snapshot.active_role_id, two.snapshot.active_role_id);
    assert_eq!(
        one.snapshot.admitted_entry_rule_id,
        two.snapshot.admitted_entry_rule_id
    );
    assert_eq!(
        one.snapshot.profile_generation_ref_id,
        two.snapshot.profile_generation_ref_id
    );
    assert_ne!(one.pid, two.pid);
    assert_ne!(one.snapshot.task_cookie, two.snapshot.task_cookie);
    assert_ne!(one.snapshot.process_state_id, two.snapshot.process_state_id);
    assert_ne!(
        one.snapshot.active_execution_id,
        two.snapshot.active_execution_id
    );

    second.stop()?;
    first.stop()?;
    main.stop()?;
    env.stop()
}
