use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = bind_observe_recovery]
fn bind_alias_keeps_exact_observe<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-bind-observe")?;
    env.start_control()?;
    env.stop_node()?;
    let mut actor = env.start_actor("exception.py", &["bind"])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let root = env.recovered(pid, "bind alias actor")?;
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    env.install_policy("file_observe.json")?;
    env.node_ready()?;

    actor.send(b"base\n")?;
    actor.wait_name(pid, "link-base-0", "base read", Duration::from_secs(5))?;
    let task = env.task(pid, "bind alias actor")?;
    assert_ne!(task.snapshot.active_role_id, 0);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    for name in ["confirm", "first", "second"] {
        actor.send(format!("{name}\n").as_bytes())?;
        actor.wait_name(
            pid,
            &format!("link-{name}-0"),
            "bind alias read",
            Duration::from_secs(5),
        )?;
    }
    let events = effects.wait_many(
        &env,
        "WOULD_DENY",
        (F::File, O::OpenRead),
        0,
        3,
        "exact bind alias evidence",
    )?;
    let base = &events[0];
    assert_ne!(base.mount_id_unique, 0);
    assert_ne!(base.exact_object_key_id, 0);
    assert_ne!(base.composite_atom_id, 0);
    for alias in &events[1..] {
        assert_ne!(alias.mount_id_unique, base.mount_id_unique);
        assert_eq!(alias.filesystem_device, base.filesystem_device);
        assert_eq!(alias.inode, base.inode);
        assert_eq!(alias.inode_generation, base.inode_generation);
        assert_eq!(alias.exact_object_key_id, base.exact_object_key_id);
        assert_eq!(alias.composite_atom_id, base.composite_atom_id);
        assert_eq!(alias.task_cookie, base.task_cookie);
    }
    assert_ne!(events[1].mount_id_unique, events[2].mount_id_unique);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
