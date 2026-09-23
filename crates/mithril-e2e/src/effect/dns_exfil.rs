use std::time::Duration;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn tcp_dns_exfil_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("dns-exfil")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("dns_exfil_policy.json")?;
    env.node_ready()?;

    let mut actor = env.start_actor("dns_exfil.py", &[])?;
    let task = env.task(actor.id(), "DNS actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    actor.send(b"run\n")?;
    let status = actor.wait_exit("TCP DNS exfil denial", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "DNS actor exited with {status}: {stderr}");

    actor.stop()?;
    env.stop()
}
