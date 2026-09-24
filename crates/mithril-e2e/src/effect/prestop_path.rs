use erebor_interceptor_abi::ExactFileObjectKeyV1;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = node_restart]
fn prestop_uses_literal_path<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("prestop-path")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("ready.py", &[])?;
    let root = env.task(main.id(), "application before Node restart")?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    let after = env.task(main.id(), "application after Node restart")?;
    assert_eq!(after.snapshot, root.snapshot);

    let mut prestop = env.add_actor("python", &["/fixtures/ready.py"])?;
    prestop.ready()?;
    let entry = env.task(prestop.id(), "PreStop literal admission")?;
    assert_eq!(entry.snapshot.active_role_id, 4);
    assert_ne!(entry.snapshot.active_role_id, after.snapshot.active_role_id);
    assert_ne!(
        entry.snapshot.admitted_entry_rule_id,
        after.snapshot.admitted_entry_rule_id
    );
    for task in [&after, &entry] {
        let rule = task.entry_rule(&env)?;
        assert_eq!(rule.target_role_id, task.snapshot.active_role_id);
        assert_ne!(rule.admitted_entry_rule_id, 0);
        assert_eq!(rule.exact_object_key_id, 0);
        assert_eq!(rule.executable_object, ExactFileObjectKeyV1::default());
    }

    prestop.stop()?;
    main.stop()?;
    env.stop()
}
