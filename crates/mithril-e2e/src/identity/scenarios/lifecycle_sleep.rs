use std::time::Duration;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(kubernetes)]
fn native_sleep_adds_no_task<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("lifecycle-sleep")?;
    env.start_control()?;
    env.install_policy()?;
    env.start_node()?;
    env.node_ready()?;
    env.post_start_sleep(Duration::from_secs(30))?;
    let mut actor = env.start_actor("ready.py", &[])?;

    let tasks = env.actor_tasks()?;
    assert_eq!(tasks, vec![actor.id()], "native sleep created a task");
    assert!(
        !env.workload_ready()?,
        "native sleep did not delay readiness"
    );
    env.wait_workload_ready()?;
    env.stage()?;
    env.admit(actor.id())?;
    env.running(actor.id())?;

    actor.stop()?;
    env.stop()
}
