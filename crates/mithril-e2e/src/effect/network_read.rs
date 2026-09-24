use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use serde_json::Value;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn read_results_stay_separate<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("network-read")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("network_read.py", &[])?;
    let pid = actor.id();
    let task = env.task(pid, "network read actor")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let text = actor.wait_text(&env.work().join("read-result.json"), "read return classes")?;
    let reads: Value = serde_json::from_str(&text)?;
    assert_eq!(reads["zero_byte"].as_bool(), Some(true));
    assert_eq!(reads["end_of_file"].as_bool(), Some(true));
    assert_eq!(reads["partial_positive"].as_bool(), Some(true));
    assert_eq!(reads["mapped"].as_bool(), Some(true));
    assert_eq!(reads["inherited_descriptor"].as_bool(), Some(true));
    assert_eq!(reads["io_error"].as_bool(), Some(true));

    env.install_policy("network_read_policy.json")?;
    env.node_ready()?;
    let effects = EffectCheck::new(&env, task)?;
    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        "token-read-ok",
        "retained token read",
        Duration::from_secs(5),
    )?;

    let read = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::Read,
        0,
        "token read",
    )?;
    let map = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::MmapRead,
        0,
        "token mapping",
    )?;
    assert_ne!(read.exact_object_key_id, 0);
    assert_eq!(read.exact_object_key_id, map.exact_object_key_id);

    actor.send(b"release\n")?;
    actor.wait_gone(pid, "network read actor exit")?;
    actor.stop()?;
    env.stop()
}
