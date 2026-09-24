use std::{fs, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn passed_socket_keeps_worker_role<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("socket-pass-allowed")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("socket_pass_allowed_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("socket_pass.py", &["main-approved"])?;
    let root = env.task(main.id(), "socket owner")?;
    let mut receiver =
        env.add_actor("python", &["/fixtures/socket_pass.py", "/work", "approved"])?;
    receiver.ready()?;
    let task = env.task(receiver.id(), "approved receiver")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(task.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_ne!(task.snapshot.task_cookie, root.snapshot.task_cookie);
    assert_ne!(
        task.snapshot.process_state_id,
        root.snapshot.process_state_id
    );
    assert_ne!(
        task.snapshot.active_execution_id,
        root.snapshot.active_execution_id
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    assert_ne!(
        task.snapshot.admitted_entry_rule_id,
        root.snapshot.admitted_entry_rule_id
    );
    let effects = EffectCheck::new(&env, task)?;

    receiver.send(b"listen\n")?;
    receiver.wait_name(
        receiver.id(),
        "pass-listening",
        "approved Unix receiver",
        Duration::from_secs(5),
    )?;
    main.send(b"act\n")?;
    main.wait_name(
        main.id(),
        "peer-ok",
        "approved payload",
        Duration::from_secs(5),
    )?;
    receiver.wait_name(
        receiver.id(),
        "fd1-ok",
        "approved descriptor",
        Duration::from_secs(5),
    )?;
    let sent = effects.wait(
        &env,
        "EXACT_POLICY_ALLOW",
        F::Network,
        O::Send,
        0,
        "approved socket send",
    )?;
    assert_ne!(sent.network_socket_key_id, 0);
    assert_ne!(sent.network_destination_policy_handle, 0);

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(receiver.id(), "approved receiver exit")?;
    receiver.stop()?;
    main.stop()?;
    env.stop()
}
