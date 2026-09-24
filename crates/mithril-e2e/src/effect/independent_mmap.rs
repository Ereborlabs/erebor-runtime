use std::time::Duration;

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn independent_mapping_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("independent-mmap")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("retained_descriptor.py", &[])?;
    env.install_policy("retained_descriptor_policy.json")?;
    env.node_ready()?;

    let root = env.task(main.id(), "primary mapping root")?;
    let root_check = EffectCheck::new(&env, root)?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        &format!("fd-0-{0}-{0}-0-0", libc::EACCES),
        "primary mapping control",
        Duration::from_secs(5),
    )?;
    let first = root_check.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::Read,
        0,
        "primary root read",
    )?;

    let mut actor = env.add_actor(
        "python",
        &["/fixtures/retained_descriptor.py", "/work", "independent"],
    )?;
    actor.ready()?;
    let task = env.task(actor.id(), "independent mapper")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(task.snapshot.active_role_id, first.active_role_id);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(task.snapshot.task_cookie, first.task_cookie);
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        actor.id(),
        &format!("map-{}-0", libc::EACCES),
        "independent mapping results",
        Duration::from_secs(5),
    )?;
    let denied = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::MmapWrite,
        -libc::EACCES,
        "shared mapping denial",
    )?;
    let allowed = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::File,
        O::MmapRead,
        0,
        "benign mapping control",
    )?;
    assert_ne!(denied.exact_object_key_id, 0);
    assert_ne!(allowed.exact_object_key_id, 0);
    assert_ne!(denied.exact_object_key_id, allowed.exact_object_key_id);
    assert_ne!(first.process_lineage_id, denied.process_lineage_id);
    assert_ne!(first.process_instance_id, denied.process_instance_id);

    actor.send(b"release\n")?;
    actor.wait_gone(actor.id(), "independent mapper exit")?;
    actor.stop()?;
    main.send(b"release\n")?;
    main.wait_gone(main.id(), "primary mapping root exit")?;
    main.stop()?;
    env.stop()
}
