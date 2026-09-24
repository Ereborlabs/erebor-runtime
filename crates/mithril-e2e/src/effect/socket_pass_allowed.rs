use std::{collections::BTreeSet, fs, time::Duration};

use erebor_interceptor_abi::{
    IpcOperationV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
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
    let rx = &task.snapshot;
    let tx = &root.snapshot;
    assert_eq!(rx.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        rx.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(rx.active_role_id, tx.active_role_id);
    assert_ne!(rx.task_cookie, tx.task_cookie);
    assert_ne!(rx.process_state_id, tx.process_state_id);
    assert_ne!(rx.active_execution_id, tx.active_execution_id);
    assert_ne!(rx.admitted_entry_rule_id, 0);
    assert_ne!(rx.admitted_entry_rule_id, tx.admitted_entry_rule_id);
    let effects = EffectCheck::new(&env, task)?;
    let relation = EffectCheck::new(&env, root)?;

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
    let ipc = relation.wait_many(
        &env,
        "EXACT_POLICY_ALLOW",
        (F::Ipc, O::IpcAccess),
        0,
        3,
        "Unix relationship",
    )?;
    let operations = ipc
        .iter()
        .map(|event| event.operation_argument)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        operations,
        [
            IpcOperationV1::Connect,
            IpcOperationV1::Send,
            IpcOperationV1::Receive
        ]
        .map(|operation| operation as u32)
        .into()
    );

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(receiver.id(), "approved receiver exit")?;
    receiver.stop()?;
    main.stop()?;
    env.stop()
}
