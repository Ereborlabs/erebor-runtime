use std::{fs, time::Duration};

use erebor_interceptor_abi::PolicyGenerationStateV1 as State;
use mithril_control::{KubernetesPolicyModeV1 as Mode, WorkloadProtectionPolicy as Policy};

use super::{generation_state::GenerationState, lifetime_result::LifetimeState};
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn generation_retires_after_exit<P: Platform>() -> TestResult<()> {
    let mut policies: [Policy; 2] = [
        serde_json::from_str(include_str!("../../../fixtures/process/actor_policy.json"))?,
        serde_json::from_str(include_str!(
            "../../../fixtures/process/actor_sleep_policy.json"
        ))?,
    ];
    for mode in [Mode::Protect, Mode::Observe] {
        let mut env = P::setup("generation-retirement")?;
        env.start_control()?;
        env.start_node()?;
        let mut inputs = Vec::new();
        for (index, policy) in policies.iter_mut().enumerate() {
            policy.spec.mode = mode;
            let file = env.work().join(format!("generation-{index}.json"));
            fs::write(&file, serde_json::to_vec(policy)?)?;
            inputs.push(file.to_str().ok_or("invalid policy path")?.to_owned());
        }
        let labels = &policies[0].spec.pod_selector.match_labels;
        let mut init = env.start_actor("ready.py", &[], labels)?;
        let mut actor = env.add_actor("python", &["/fixtures/ready.py"])?;
        actor.ready()?;
        env.install_policy(&inputs[0])?;
        env.node_ready()?;
        let root = env.recovered(init.id(), "initial generation holder")?;
        let peer = env.recovered(actor.id(), "second generation holder")?;
        let old = root.snapshot.profile_generation_ref_id;
        assert_eq!(peer.snapshot.profile_generation_ref_id, old);
        assert_ne!(peer.snapshot.task_cookie, root.snapshot.task_cookie);
        let descriptor = GenerationState::descriptor(&env, old)?;
        let profile = descriptor.profile_id;
        let cookie = root.snapshot.task_cookie;
        let held = GenerationState::read(&env, profile, old, cookie)?;
        assert_eq!(held.active, Some(old));
        assert_eq!(descriptor.state, State::Active);
        let refs = LifetimeState::profile_refs(&env, &root)?;
        assert!(refs >= 2, "generation {old}: {refs} holders");

        env.install_policy(&inputs[1])?;
        env.node_ready()?;
        let retiring = GenerationState::wait_retiring(&env, profile, old, cookie)?;
        let current = retiring.active.ok_or("missing active generation")?;
        assert!(current > old);
        assert_eq!(
            retiring.descriptor.map(|value| value.state),
            Some(State::Retiring)
        );
        assert_eq!(LifetimeState::profile_refs(&env, &root)?, refs);
        let retained = env.task(init.id(), "retained generation holder")?.snapshot;
        assert_eq!(retained.task_cookie, cookie);
        assert_eq!(retained.process_state_id, root.snapshot.process_state_id);
        assert_eq!(
            retained.active_execution_id,
            root.snapshot.active_execution_id
        );
        assert_eq!(retained.entry_instance_id, root.snapshot.entry_instance_id);
        assert_eq!(retained.profile_generation_ref_id, old);

        actor.send(b"stop\n")?;
        let status = actor.wait_exit("first holder exit", Duration::from_secs(5))?;
        assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
        actor.stop()?;
        env.task_release(peer.snapshot.task_cookie, "first holder release")?;
        init.ensure_running("last generation holder")?;
        let remaining = LifetimeState::profile_refs(&env, &root)?;
        assert!(remaining > 0 && remaining < refs, "{refs} -> {remaining}");
        let retained = GenerationState::wait_retiring(&env, profile, old, cookie)?;
        assert_eq!(retained.active, Some(current));
        assert_eq!(
            retained.descriptor.map(|value| value.state),
            Some(State::Retiring)
        );

        init.send(b"stop\n")?;
        let status = init.wait_exit("last holder exit", Duration::from_secs(5))?;
        assert!(status.success(), "{status}; stderr: {:?}", init.stderr()?);
        init.stop()?;
        let absent = GenerationState::wait_absent(&env, profile, old, cookie)?;
        assert!(absent.descriptor.is_none());
        assert_eq!(absent.targets, 0);
        assert_eq!(absent.bindings, 0);
        assert!(absent.pending.is_none());
        assert_ne!(absent.active, Some(old));
        env.stop()?;
    }
    Ok(())
}
