use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use snafu::ResultExt as _;

use super::check::EffectCheck;
use crate::error::InterceptorSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn async_read_keeps_authority<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("io-read")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("io_read.py", &[], &labels)?;
    let pid = actor.id();
    let task = env.task(pid, "asynchronous reader")?;
    let cookie = task.snapshot.task_cookie;
    env.install_policy("retained_descriptor_policy.json")?;
    env.node_ready()?;
    let effects = EffectCheck::new(&env, task)?;

    actor.send(b"act\n")?;
    actor.wait_name(
        pid,
        "uring-13-0",
        "asynchronous read results",
        Duration::from_secs(5),
    )?;
    let mut objects = Vec::new();
    for (reason, result) in [
        ("EXACT_POLICY_DENY", -libc::EACCES),
        ("EXACT_POLICY_ALLOW", 0),
    ] {
        let event = effects.wait_match(&env, "asynchronous file read", |event| {
            event.task_cookie == cookie
                && event.reason == reason
                && event.effect_family == F::File as u32
                && event.operation == O::Read as u32
                && event.kernel_result == result
                && event.io_uring_submission_sequence > 0
        })?;
        assert_ne!(event.exact_object_key_id, 0);
        assert_ne!(event.active_role_id, 0);
        assert_ne!(event.profile_generation_ref_id, 0);
        assert_ne!(event.io_uring_ring_id, "00000000000000000000000000000000");
        assert_eq!(event.io_uring_ring_generation, 1);
        assert_eq!(event.io_uring_user_data, 0x4d49_5448_5249_4c01);
        assert_eq!(event.io_uring_file_offset, 0);
        assert_ne!(event.io_uring_buffer_address, 0);
        assert_ne!(event.io_uring_file_cookie, 0);
        assert_ne!(event.io_uring_executor_pid_tgid, 0);
        assert_eq!(event.io_uring_byte_length, 1);
        assert!(event.io_uring_sqe_index < 2);
        assert_ne!(event.io_uring_request_flags & 16, 0);
        assert_eq!(event.io_uring_rw_flags, 0);
        assert_eq!(event.io_uring_opcode, 22);
        objects.push((event.exact_object_key_id, event.profile_generation_ref_id));
    }
    assert_ne!(objects[0].0, objects[1].0);
    assert_eq!(objects[0].1, objects[1].1);

    let (path, reader) = env.maps();
    let last = RefCell::new(String::new());
    wait_for(
        path,
        "asynchronous authority cleanup",
        Duration::from_secs(5),
        || {
            let rings = reader
                .keys("io_uring_ring_states")
                .context(InterceptorSnafu)?;
            let requests = reader
                .keys("io_uring_request_states")
                .context(InterceptorSnafu)?;
            let refs = reader
                .lookup("profile_generation_async_refs", &objects[0].1.to_ne_bytes())
                .context(InterceptorSnafu)?;
            *last.borrow_mut() =
                format!("rings={rings:?}, requests={requests:?}, references={refs:?}");
            Ok((rings.is_empty()
                && requests.is_empty()
                && refs.as_deref() == Some(&0_u64.to_ne_bytes()))
            .then_some(()))
        },
        || last.borrow().clone(),
    )?;

    actor.send(b"stop\n")?;
    actor.wait_gone(pid, "asynchronous reader exit")?;
    actor.stop()?;
    env.stop()
}
