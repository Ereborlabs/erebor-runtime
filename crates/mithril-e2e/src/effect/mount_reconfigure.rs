use std::time::Duration;

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O, PolicyGenerationModeV1 as Mode,
    ProfileGenerationDescriptorV1,
};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_config]
fn reconfigure_dirties_mounts<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-config")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/mount_alias_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("mount_alias.py", &["reconfigure"], &labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let root = env.recovered(pid, "mount actor")?.snapshot.root_class;
    assert_eq!(root.as_deref(), Some("recovered_application_root"));

    let wait = Duration::from_secs(5);
    for (policy, mode) in [
        ("mount_alias_policy.json", Mode::Protect),
        ("mount_observe_policy.json", Mode::Observe),
    ] {
        env.install_policy(policy)?;
        env.node_ready()?;
        actor.send(b"mount\n")?;
        actor.wait_name(pid, "mnt-mount-0", "tmpfs mount", wait)?;
        actor.send(b"read\n")?;
        actor.wait_name(pid, "mnt-read-0", "initial benign read", wait)?;
        let task = env.task(pid, "mount actor")?;
        let generation = env
            .process(&task.snapshot.process_state_id)?
            .active_profile_generation_ref_id;
        let descriptor = env
            .state::<ProfileGenerationDescriptorV1>(
                "profile_generation_descriptors",
                &generation.to_ne_bytes(),
                "mount policy mode",
            )?
            .ok_or("mount policy descriptor is missing")?;
        assert_eq!(descriptor.mode, mode);
        let effects = EffectCheck::new(&env, task)?;
        let count = |name| -> TestResult<u64> {
            env.state::<u64>(name, &0_u32.to_ne_bytes(), "mount counter")?
                .ok_or_else(|| format!("{name} is missing").into())
        };
        let epoch = count("mount_global_mutation_epoch")?;
        let activity = count("mount_global_activity_sequence")?;
        actor.send(b"config\n")?;
        actor.wait_name(pid, "mnt-config-0", "tmpfs reconfiguration", wait)?;
        let changed = count("mount_global_mutation_epoch")?;
        assert!(changed > epoch, "{mode:?}: mutation epoch did not advance");
        assert!(count("mount_global_activity_sequence")? > activity);
        assert!(
            changed != count("mount_global_clean_epoch")?
                || count("mount_global_pending_mutations")? != 0,
            "{mode:?}: reconfiguration left the global view clean"
        );
        actor.send(b"read\n")?;
        actor.wait_name(pid, "mnt-read-0", "benign control read", wait)?;
        let text = actor.wait_text(&env.work().join("mount-result.json"), "mount result")?;
        let result: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(result["errno"], 0);
        assert_eq!(result["value"], "allowed bind source\n");
        assert_eq!(result["size"], 4 * 1024 * 1024);
        effects.wait(
            &env,
            "EXACT_POLICY_ALLOW",
            F::File,
            O::OpenRead,
            0,
            "benign evidence",
        )?;
        actor.send(b"unmount\n")?;
        actor.wait_name(pid, "mnt-unmount-0", "tmpfs cleanup", wait)?;
    }

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
