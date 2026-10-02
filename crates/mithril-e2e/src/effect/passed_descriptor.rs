use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = descriptor_recovery]
fn passed_files_keep_authority<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("passed-descriptor")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/retained_descriptor_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("retained_descriptor.py", &["passed"], &labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("actor_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let task = env.recovered(pid, "passed descriptor actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    env.install_policy("retained_descriptor_policy.json")?;
    env.node_ready()?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        &format!("fd-0-{0}-{0}-0-0", libc::EACCES),
        "passed descriptor results",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::Read,
        -libc::EACCES,
        "passed secret read denial",
    )?;
    let allowed = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::Read,
        0,
        "passed control read allowance",
    )?;
    assert_ne!(denied.exact_object_key_id, 0);
    assert_ne!(allowed.exact_object_key_id, 0);
    assert_ne!(denied.exact_object_key_id, allowed.exact_object_key_id);
    assert_ne!(denied.composite_atom_id, 0);
    assert_ne!(allowed.composite_atom_id, 0);
    assert_ne!(denied.profile_generation_ref_id, 0);
    assert_eq!(
        denied.profile_generation_ref_id,
        allowed.profile_generation_ref_id
    );

    actor.send(b"release\n")?;
    actor.wait_gone(pid, "passed descriptor actor exit")?;
    actor.stop()?;
    env.stop()
}
