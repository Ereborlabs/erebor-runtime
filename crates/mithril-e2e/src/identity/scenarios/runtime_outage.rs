use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(runc)]
#[lifecycle = node_outage]
fn runtime_gate_fails_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-outage")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("python_policy.json")?;
    env.node_ready()?;
    env.stop_node()?;

    let denied = match env.start_actor("ready.py", &[]) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            env.stop()?;
            return Err("the protected actor started without Node admission".into());
        }
    };
    let message = denied.to_string();
    assert!(message.contains("DENY_NODE_UNAVAILABLE"), "{message}");
    assert!(message.contains("runtime.sock"), "{message}");
    assert!(!env.work().join("ready").exists(), "the actor ran");
    env.stop()
}
