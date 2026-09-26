use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as Family, KernelEffectOperationV1 as Operation,
};
use snafu::ResultExt as _;

use super::generation_state::GenerationState;
use crate::error::IoSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn simultaneous_policies_are_isolated<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("multi-policy")?;
    env.start_control()?;
    env.start_node()?;

    // Keep both actors alive under different policies on the same Node.
    let deny_labels = env.install_policy("multi_policy_deny.json")?;
    let allow_labels = env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut denied = env.start_actor("read_path.py", &[], &deny_labels)?;
    let denied_work = env.work().to_owned();

    let mut allowed = env.start_actor("read_path.py", &[], &allow_labels)?;
    let allowed_work = env.work().to_owned();

    for round in 0..2 {
        denied.send(b"/fixtures/policy_replace.py\n")?;
        allowed.send(b"/fixtures/policy_replace.py\n")?;
        let mut tasks = Vec::new();
        for (actor, work, errno, reason) in [
            (&mut denied, &denied_work, libc::EACCES, "EXACT_POLICY_DENY"),
            (&mut allowed, &allowed_work, 0, "APPLICATION_DEFAULT_ALLOW"),
        ] {
            let result = actor.wait_text(&work.join(format!("{round}.json")), "read")?;
            let (actual, size): (i32, usize) = serde_json::from_str(&result)?;
            assert_eq!(actual, errno, "{}: {result}", work.display());
            assert_eq!(size > 0, errno == 0);
            actor.ensure_running("simultaneous policy enforcement")?;
            let task = env.task(actor.id(), "policy actor identity")?;
            let gen = task.snapshot.profile_generation_ref_id;
            let profile = GenerationState::descriptor(&env, gen)?;
            let cookie = task.snapshot.task_cookie;
            let state = GenerationState::read(&env, profile.profile_id, gen, cookie)?;
            assert_eq!(state.active, Some(gen));
            let path = env.maps().0;
            let last = RefCell::new(String::new());
            wait_for(
                path,
                "policy read evidence",
                Duration::from_secs(30),
                || {
                    let events = env
                        .snapshot()
                        .map_err(|error| std::io::Error::other(error.to_string()))
                        .context(IoSnafu { path })?
                        .recent_effects;
                    *last.borrow_mut() = format!("{events:?}");
                    let (file, read) = (Family::File, Operation::OpenRead);
                    let found = events.iter().any(|event| {
                        task.matches_effect(event, reason, file, read, -errno)
                            && event.profile_generation_ref_id == gen
                    });
                    Ok(found.then_some(()))
                },
                || format!("last evidence: {}", last.borrow()),
            )?;
            let snapshot = task.snapshot;
            let binding = snapshot.runtime_binding.clone().ok_or("binding missing")?;
            tasks.push((snapshot, binding, profile));
        }
        let (denied_task, denied_bind, denied_profile) = &tasks[0];
        let (allowed_task, allowed_bind, allowed_profile) = &tasks[1];
        assert_ne!(denied_task.task_cookie, allowed_task.task_cookie);
        assert_ne!(denied_task.execution_set_id, allowed_task.execution_set_id);
        assert_ne!(denied_bind.binding_id, allowed_bind.binding_id);
        assert_ne!(denied_bind.root_cgroup_id, allowed_bind.root_cgroup_id);
        assert_ne!(denied_profile.profile_id, allowed_profile.profile_id);
        assert_ne!(
            denied_profile.profile_generation_ref_id,
            allowed_profile.profile_generation_ref_id
        );
        assert_eq!(denied_profile.node_boot_id, allowed_profile.node_boot_id);
        assert_eq!(denied_profile.label_epoch, allowed_profile.label_epoch);
    }

    denied.stop()?;
    allowed.stop()?;
    env.stop()
}
