use std::collections::BTreeSet;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::generation_state::GenerationState;
use crate::effect::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn signed_file_gate_changes<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-gate")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("read_path.py", &[], &labels)?;
    let work = env.work().to_owned();
    let group = actor.group_path().ok_or("no actor cgroup")?.to_owned();
    let root = env.task(actor.id(), "file gate actor")?.snapshot;
    assert_ne!(root.active_role_id, 0);
    assert_ne!(root.admitted_entry_rule_id, 0);
    let mut generations = BTreeSet::new();
    let mut version = 0;

    // Replace signed policy on the same running actor: allow, deny, clear, deny.
    for (round, (policy, errno, reason)) in [
        ("actor_policy.json", 0, "APPLICATION_DEFAULT_ALLOW"),
        (
            "policy_replace_policy.json",
            libc::EACCES,
            "EXACT_POLICY_DENY",
        ),
        ("actor_policy.json", 0, "APPLICATION_DEFAULT_ALLOW"),
        (
            "policy_replace_policy.json",
            libc::EACCES,
            "EXACT_POLICY_DENY",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(env.install_policy(policy)?, labels);
        env.node_ready()?;
        let task = env.task(actor.id(), "file gate identity")?;
        let effects = EffectCheck::new(&env, task)?;
        actor.send(b"/fixtures/policy_replace.py\n")?;
        let text = actor.wait_text(&work.join(format!("{round}.json")), "file gate read")?;
        let (actual, size): (i32, usize) = serde_json::from_str(&text)?;
        assert_eq!(actual, errno, "{policy}: {text}");
        assert_eq!(size > 0, errno == 0, "{policy}: {text}");
        let event = effects.wait(
            &env,
            reason,
            F::File,
            O::OpenRead,
            -errno,
            "file gate evidence",
        )?;
        let task = env.task(actor.id(), "file gate generation")?.snapshot;
        assert_eq!(task.task_cookie, root.task_cookie);
        assert_eq!(task.entry_instance_id, root.entry_instance_id);
        assert_eq!(task.process_state_id, root.process_state_id);
        assert_eq!(task.active_role_id, root.active_role_id);
        assert_eq!(task.admitted_entry_rule_id, root.admitted_entry_rule_id);
        assert_eq!(
            task.profile_generation_ref_id,
            root.profile_generation_ref_id
        );
        let process = env.process(&task.process_state_id)?;
        let generation = process.active_profile_generation_ref_id;
        assert!(
            generations.insert(generation),
            "reused generation: {policy}"
        );
        assert_eq!(event.profile_generation_ref_id, generation);
        assert_eq!(event.entry_instance_id, root.entry_instance_id);
        let profile = GenerationState::descriptor(&env, generation)?;
        assert!(
            profile.owner_generation > version,
            "stale signed version: {policy}"
        );
        let state = GenerationState::read(&env, profile.profile_id, generation, task.task_cookie)?;
        assert_eq!(state.active, Some(generation));
        assert_eq!(state.descriptor, Some(profile));
        assert!(state.targets > 0);
        assert!(state.bindings > 0);
        assert!(state.pending.is_none());
        actor.ensure_running("file gate policy replacement")?;
        version = profile.owner_generation;
    }

    actor.stop()?;
    env.stop()?;
    assert!(!work.exists(), "actor files remain: {}", work.display());
    assert!(!group.exists(), "actor cgroup remains: {}", group.display());
    Ok(())
}
