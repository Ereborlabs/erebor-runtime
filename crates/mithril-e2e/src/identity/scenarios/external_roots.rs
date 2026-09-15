use erebor_interceptor_abi::TaskCoordinateStateV1;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[scope = "external-roots"]
fn concurrent_roots_stay_distinct<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("concurrent-roots")?;
    env.start_control()?;
    let mut init = env.start_actor("external_roots.py", &[])?;
    env.install_policy("external_roots_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    let app = env.recovered(init.id(), "recovered actor identity")?;

    let args = ["/fixtures/external_roots.py", "/work", "external"];
    let mut first = env.add_actor("python-external", &args)?;
    let mut second = env.add_actor("python-external", &args)?;
    let one = env.task(first.id(), "first external root")?;
    let two = env.task(second.id(), "second external root")?;

    assert_eq!(one.snapshot.creator_task_cookie, None);
    assert_eq!(two.snapshot.creator_task_cookie, None);
    assert!(one.snapshot.admitted_entry_rule_id > 0);
    assert!(two.snapshot.admitted_entry_rule_id > 0);
    assert_ne!(one.pid, two.pid);
    assert_ne!(one.snapshot.task_cookie, two.snapshot.task_cookie);
    assert_ne!(one.snapshot.process_state_id, two.snapshot.process_state_id);
    assert_ne!(
        one.snapshot.active_execution_id,
        two.snapshot.active_execution_id
    );
    assert_eq!(
        one.snapshot.profile_generation_ref_id,
        two.snapshot.profile_generation_ref_id
    );
    assert_eq!(
        one.snapshot.admitted_entry_rule_id,
        two.snapshot.admitted_entry_rule_id
    );
    assert_eq!(
        one.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(two.snapshot.root_class, one.snapshot.root_class);
    assert_eq!(
        one.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(
        two.snapshot.installed_role_class,
        one.snapshot.installed_role_class
    );
    assert!(one.snapshot.active_role_id > 0);
    assert_eq!(two.snapshot.active_role_id, one.snapshot.active_role_id);
    assert_ne!(one.snapshot.active_role_id, app.snapshot.active_role_id);
    assert_eq!(one.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(two.coordinate.state, TaskCoordinateStateV1::Runnable);

    first.stop()?;
    second.stop()?;
    init.stop()?;
    env.stop()
}
