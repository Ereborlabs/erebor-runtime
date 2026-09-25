use std::{cell::RefCell, fs, path::PathBuf, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use snafu::ResultExt as _;

use super::check::EffectCheck;
use crate::{
    error::IoSnafu,
    physical::wait_for,
    platform::{platform_test, Platform, TestResult},
    process::ProcessFixture,
};

#[platform_test(host)]
#[lifecycle = socket_pass_recovery]
fn cross_namespace_receiver_is_restricted<P: Platform>() -> TestResult<()> {
    let wait = Duration::from_secs(5);
    let mut env = P::setup("socket-pass")?;
    env.start_control()?;
    env.stop_node()?;
    let mut main = env.start_actor("socket_pass.py", &["main-namespace"])?;
    env.place(main.id())?;
    let mut receiver = env.add_actor(
        "python",
        &["/fixtures/socket_pass.py", "/work", "ns-receiver"],
    )?;
    receiver.ready()?;
    env.place(receiver.id())?;
    receiver.send(b"unshare\n")?;
    receiver.wait_name(receiver.id(), "ns-ready", "netns", wait)?;
    let sender_ns = fs::read_link(format!("/proc/{}/ns/net", main.id()))?;
    let receiver_ns = fs::read_link(format!("/proc/{}/ns/net", receiver.id()))?;
    assert_ne!(sender_ns, receiver_ns);

    env.install_policy("socket_pass_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(main.id())?;
    let root = env.recovered(main.id(), "socket owner")?;
    let task = env.task(receiver.id(), "restricted receiver")?;
    assert_ne!(task.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;

    let ns_pid = ProcessFixture::namespace_pid(receiver.id())?;
    main.send(format!("act {ns_pid}\n").as_bytes())?;
    let comm = PathBuf::from(format!("/proc/{}/comm", main.id()));
    let last = RefCell::new(String::new());
    let fd = wait_for(
        &comm,
        "accepted socket descriptor",
        wait,
        || {
            let name = fs::read_to_string(&comm).context(IoSnafu { path: &comm })?;
            *last.borrow_mut() = name.clone();
            Ok(name
                .trim()
                .strip_prefix("sock-")
                .and_then(|fd| fd.parse::<i32>().ok()))
        },
        || format!("last actor name: {}", last.borrow()),
    )?;
    let ns_pid = ProcessFixture::namespace_pid(main.id())?;
    receiver.send(format!("{ns_pid} {fd}\n").as_bytes())?;
    receiver.wait_name(receiver.id(), "fd1-13-13", "denial", wait)?;
    let sent = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Network,
        O::Send,
        -libc::EACCES,
        "denied send",
    )?;
    let read = effects.wait(
        &env,
        "UNSUPPORTED_OBJECT",
        F::Network,
        O::Receive,
        -libc::EACCES,
        "denied receive",
    )?;
    assert_ne!(sent.network_socket_key_id, 0);
    assert_eq!(sent.network_socket_key_id, read.network_socket_key_id);
    assert_eq!(
        sent.network_socket_generation,
        read.network_socket_generation
    );
    main.send(b"check\n")?;
    main.wait_name(main.id(), "peer-empty", "no bytes", wait)?;

    fs::write(env.work().join("release"), b"release\n")?;
    receiver.wait_gone(receiver.id(), "restricted receiver exit")?;
    receiver.stop()?;
    main.stop()?;
    env.stop()
}
