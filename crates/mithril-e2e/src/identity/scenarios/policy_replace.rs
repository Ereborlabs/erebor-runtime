use std::{cell::Cell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};

use super::lifetime_result::LifetimeState;
use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn running_task_uses_new_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("policy-replace")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("policy_replace.py", &[])?;
    let root = env.task(actor.id(), "initial policy identity")?;
    let snap = &root.snapshot;
    let old = snap.profile_generation_ref_id;
    let refs = LifetimeState::profile_refs(&env, &root)?;

    env.install_policy("policy_replace_policy.json")?;
    env.node_ready()?;
    let held = env.task(actor.id(), "retained policy identity")?.snapshot;
    assert_eq!(held.task_cookie, snap.task_cookie);
    assert_eq!(held.active_role_id, snap.active_role_id);
    assert_eq!(held.admitted_entry_rule_id, snap.admitted_entry_rule_id);
    assert_eq!(held.profile_generation_ref_id, old);
    assert_eq!(LifetimeState::profile_refs(&env, &root)?, refs);

    let mut entry = env.add_actor("python", &["/fixtures/ready.py"])?;
    let next = env.task(entry.id(), "replacement policy entry")?.snapshot;
    assert!(next.profile_generation_ref_id > old);
    assert_eq!(next.active_role_id, snap.active_role_id);
    assert_ne!(next.admitted_entry_rule_id, 0);
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"effect\n")?;

    let path = env.maps().0.to_owned();
    let state = Cell::new((false, false));
    wait_for(
        &path,
        "replacement effect evidence",
        Duration::from_secs(30),
        || {
            let events = env
                .snapshot()
                .map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?
                .recent_effects;
            let events = events
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            let denied = events.iter().any(|event| {
                event.reason == "EXACT_POLICY_DENY"
                    && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                    && event.operation == u32::from(KernelEffectOperationV1::OpenRead as u16)
                    && event.kernel_result == -libc::EACCES
                    && event.profile_generation_ref_id == next.profile_generation_ref_id
                    && event.task_cookie == snap.task_cookie
                    && event.active_role_id == snap.active_role_id
                    && event.admitted_entry_rule_id == snap.admitted_entry_rule_id
            });
            let child = events.iter().any(|event| {
                event.reason == "APPLICATION_DEFAULT_ALLOW"
                    && event.effect_family == u32::from(KernelEffectFamilyV1::Exec as u16)
                    && event.operation == u32::from(KernelEffectOperationV1::Execute as u16)
                    && event.profile_generation_ref_id == next.profile_generation_ref_id
                    && event.task_cookie != snap.task_cookie
                    && event.active_role_id == snap.active_role_id
                    && event.admitted_entry_rule_id == snap.admitted_entry_rule_id
            });
            actor.ensure_running("replacement effect")?;
            state.set((denied, child));
            Ok((denied && child).then_some(()))
        },
        || format!("denied={}, child={}", state.get().0, state.get().1),
    )?;
    actor.ensure_running("replacement denial and child exec")?;

    entry.stop()?;
    actor.stop()?;
    env.stop()
}
