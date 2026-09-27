use std::{path::Path, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_node::ExactFileObjectResolver;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = mount_late]
fn allowed_bind_keeps_exact_allow<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("file-bind-allowed")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_alias_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["bind-allowed"], &labels)?;
    let pid = actor.id();
    let task = env.task(pid, "allowed bind actor")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    env.install_policy("retained_descriptor_policy.json")?;
    env.node_ready()?;

    let task = env.task(pid, "allowed bind actor")?;
    assert_ne!(task.snapshot.active_role_id, 0);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;
    for name in ["base", "alias"] {
        actor.send(format!("{name}\n").as_bytes())?;
        let mark = format!("link-{name}-0");
        actor.wait_name(pid, &mark, "allowed bind read", Duration::from_secs(5))?;
    }
    let events = effects.wait_many(
        &env,
        "EXACT_POLICY_ALLOW",
        (F::File, O::OpenRead),
        0,
        2,
        "allowed bind evidence",
    )?;
    let paths = [
        Path::new("/tmp/mithril-descriptor-allowed"),
        Path::new("/work/bind-allowed/mithril-descriptor-allowed"),
    ];
    assert_eq!(events.len(), paths.len());
    let mut views = Vec::new();
    for (path, event) in paths.iter().zip(&events) {
        let view = ExactFileObjectResolver::resolve(
            pid,
            path,
            event.profile_generation_ref_id,
            event.exact_object_key_id,
            "allow-control".into(),
            event.inode_generation,
            None,
        )?;
        assert_eq!(view.mount_id_unique, event.mount_id_unique);
        assert_eq!(view.filesystem_device, event.filesystem_device);
        assert_eq!(view.inode, event.inode);
        assert_eq!(view.inode_generation, event.inode_generation);
        views.push(view);
    }
    let base = &events[0];
    let alias = &events[1];
    assert_ne!(base.mount_id_unique, alias.mount_id_unique);
    assert_ne!(base.exact_object_key_id, 0);
    assert_ne!(base.composite_atom_id, 0);
    let origin = &views[0];
    let target = &views[1];
    let selected = origin.selected_mount_id_unique;
    assert_eq!(selected, target.selected_mount_id_unique);
    assert_eq!(
        origin.canonical_component_hex,
        target.canonical_component_hex
    );
    assert_eq!(origin.mount_namespace_inode, target.mount_namespace_inode);
    assert_eq!(base.filesystem_device, alias.filesystem_device);
    assert_eq!(base.inode, alias.inode);
    assert_eq!(base.inode_generation, alias.inode_generation);
    assert_eq!(base.exact_object_key_id, alias.exact_object_key_id);
    assert_eq!(base.composite_atom_id, alias.composite_atom_id);
    assert_eq!(base.task_cookie, alias.task_cookie);

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
