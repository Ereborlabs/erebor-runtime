use std::fs;

use erebor_interceptor_abi::{PendingExecStateV1, PolicyGenerationStateV1};

use super::generation_state::GenerationState;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
#[lifecycle = terminal_retirement]
fn terminal_evidence_survives_retirement<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("terminal-retirement")?;
    let bin = env.work().join("bin");
    fs::create_dir_all(&bin)?;
    ProcessFixture::fatal_exec(&bin.join("post-ponr-execfail"))?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("fatal_exec_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;

    assert!(env.add_actor("post-ponr-execfail", &[]).is_err());
    let pending = GenerationState::wait_fatal(&env)?;
    let old = pending.source_profile_generation_ref_id;
    let descriptor = GenerationState::descriptor(&env, old)?;
    let held = GenerationState::read(&env, descriptor.profile_id, old, pending.task_cookie)?;
    assert_eq!(pending.state, PendingExecStateV1::PostPonrFatal);
    assert_eq!(held.active, Some(old));
    assert_eq!(held.descriptor, Some(descriptor));

    env.install_policy("policy_replace_policy.json")?;
    env.node_ready()?;
    let retiring =
        GenerationState::wait_retiring(&env, descriptor.profile_id, old, pending.task_cookie)?;
    assert_ne!(retiring.active, Some(old));
    assert_eq!(
        retiring.descriptor.map(|value| value.state),
        Some(PolicyGenerationStateV1::Retiring)
    );

    init.stop()?;
    let retired =
        GenerationState::wait_absent(&env, descriptor.profile_id, old, pending.task_cookie)?;
    assert!(retired.descriptor.is_none());
    assert_eq!(retired.targets, 0);
    assert_eq!(retired.bindings, 0);
    assert_eq!(retired.pending, Some(pending));
    env.stop()
}
