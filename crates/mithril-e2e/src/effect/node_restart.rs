use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = node_restart]
fn node_restart_keeps_actor<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("node-restart")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_sleep_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("ready.py", &[])?;
    let before = env.task(actor.id(), "actor before Node restart")?;

    env.restart_node()?;
    env.node_ready()?;
    let after = env.task(actor.id(), "actor after Node restart")?;

    assert_eq!(after.snapshot, before.snapshot);
    assert_eq!(after.coordinate, before.coordinate);
    actor.stop()?;
    env.stop()
}
