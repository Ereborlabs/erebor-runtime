use std::iter;

use erebor_interceptor_abi::TaskCoordinateStateV1;

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[scope = "identity"]
fn attached_roots_are_restricted<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("restricted-roots")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy()?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;
    let app = env.task(init.id(), "application root")?;

    let script = actor_script(env.source(), "ready.py")?;
    let mut one = ProcessFixture::python(&script, iter::empty::<&str>())?;
    let mut two = ProcessFixture::python(&script, iter::empty::<&str>())?;
    env.place(one.id())?;
    env.place(two.id())?;
    let first = env.task(one.id(), "first restricted root")?;
    let second = env.task(two.id(), "second restricted root")?;

    assert_eq!(first.snapshot.creator_task_cookie, None);
    assert_eq!(second.snapshot.creator_task_cookie, None);
    assert_eq!(first.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(second.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(first.snapshot.task_cookie, second.snapshot.task_cookie);
    assert_ne!(
        first.snapshot.process_state_id,
        second.snapshot.process_state_id
    );
    assert_eq!(
        first.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(second.snapshot.root_class, first.snapshot.root_class);
    assert_eq!(
        first.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_eq!(
        second.snapshot.installed_role_class,
        first.snapshot.installed_role_class
    );
    assert!(first.snapshot.active_role_id > 0);
    assert_eq!(
        second.snapshot.active_role_id,
        first.snapshot.active_role_id
    );
    assert_ne!(first.snapshot.active_role_id, app.snapshot.active_role_id);
    assert_eq!(first.coordinate.state, TaskCoordinateStateV1::Runnable);
    assert_eq!(second.coordinate.state, TaskCoordinateStateV1::Runnable);

    one.stop()?;
    two.stop()?;
    init.stop()?;
    env.stop()
}
