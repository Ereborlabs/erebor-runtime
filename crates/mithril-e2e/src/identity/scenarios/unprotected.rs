use mithril_control::WorkloadProtectionPolicy as Policy;

use std::time::Duration;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn unprotected_actor_runs<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("unprotected")?;
    env.start_control()?;
    env.start_node()?;

    let policy: Policy =
        serde_json::from_str(include_str!("../../../fixtures/process/actor_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("ready.py", &[], &labels)?;
    actor.send(b"stop\n")?;
    actor.close();
    let status = actor.wait_exit("unprotected actor exit", Duration::from_secs(5))?;
    assert!(status.success(), "unprotected actor exited with {status}");

    actor.stop()?;
    env.stop()
}
