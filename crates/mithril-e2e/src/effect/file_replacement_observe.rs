use std::time::Duration;

use erebor_interceptor_abi::{
    KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O, MountSecurityViewStateV1,
    MountTopologyStateV1,
};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_replace_observe]
fn observe_replacement_stays_closed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-replacement-observe")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy =
        serde_json::from_str(include_str!("../../fixtures/process/file_observe.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("exception.py", &["bind"], &labels)?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let root = env.recovered(pid, "replacement actor")?.snapshot.root_class;
    assert_eq!(root.as_deref(), Some("recovered_application_root"));
    env.install_policy("file_observe.json")?;
    env.node_ready()?;

    let wait = Duration::from_secs(5);
    actor.send(b"base\n")?;
    actor.wait_name(pid, "link-base-0", "initial observed read", wait)?;
    let task = env.task(pid, "replacement actor")?;
    let initial = EffectCheck::new(&env, task)?;
    actor.send(b"confirm\n")?;
    actor.wait_name(pid, "link-confirm-0", "exact observed read", wait)?;
    let original = initial.wait(
        &env,
        "WOULD_DENY",
        F::File,
        O::OpenRead,
        0,
        "original exact observation",
    )?;
    assert_ne!(original.exact_object_key_id, 0);
    assert_ne!(original.composite_atom_id, 0);

    for (action, reason, result) in [
        ("replace", "UNRESOLVED_OBJECT", -libc::EACCES),
        ("restore", "WOULD_DENY", 0),
    ] {
        let task = env.task(pid, "replacement actor")?;
        let effects = EffectCheck::new(&env, task)?;
        actor.send(format!("{action}\n").as_bytes())?;
        actor.wait_name(pid, &format!("link-{action}-0"), "mount completion", wait)?;
        if action == "replace" {
            let view = env
                .state::<MountSecurityViewStateV1>(
                    "mount_security_views",
                    &original.mount_namespace_inode.to_ne_bytes(),
                    "replacement mount view",
                )?
                .ok_or("the replacement mount view is missing")?;
            assert_eq!(view.state, MountTopologyStateV1::Dirty);
        }
        actor.send(b"read\n")?;
        actor.wait_name(pid, &format!("link-read-{}", -result), "source read", wait)?;
        let event = effects.wait(
            &env,
            reason,
            F::File,
            O::OpenRead,
            result,
            "replacement read evidence",
        )?;
        assert_eq!(event.task_cookie, original.task_cookie);
        if action == "restore" {
            assert_eq!(event.exact_object_key_id, original.exact_object_key_id);
            assert_eq!(event.composite_atom_id, original.composite_atom_id);
        }
    }

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
