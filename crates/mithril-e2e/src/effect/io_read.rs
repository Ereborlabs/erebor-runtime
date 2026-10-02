use std::{cell::RefCell, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use snafu::ResultExt as _;

use super::check::EffectCheck;
use crate::error::InterceptorSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = identity]
fn async_read_keeps_authority<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("io-read")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("io_read.py", &[], &labels)?;
    let pid = actor.id();
    let limit = Duration::from_secs(5);
    for (policy, denied, reason) in [
        (
            "retained_descriptor_policy.json",
            libc::EACCES,
            "EXACT_POLICY_DENY",
        ),
        ("io_read_observe.json", 0, "WOULD_DENY"),
    ] {
        env.install_policy(policy)?;
        env.node_ready()?;
        let task = env.task(pid, "asynchronous reader")?;
        let cookie = task.snapshot.task_cookie;
        let effects = EffectCheck::new(&env, task)?;

        actor.send(b"act\n")?;
        let name = format!("uring-{denied}-0");
        actor
            .wait_name(pid, &name, "async reads", limit)
            .inspect_err(|_| eprintln!("io_uring failure: {:?}", env.snapshot()))?;
        let mut objects = Vec::new();
        for (reason, result) in [(reason, -denied), ("EXACT_POLICY_ALLOW", 0)] {
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
            limit,
            || {
                for map in ["io_uring_ring_states", "io_uring_request_states"] {
                    let keys = reader.keys(map).context(InterceptorSnafu)?;
                    *last.borrow_mut() = format!("{map}: {keys:?}");
                    if !keys.is_empty() {
                        return Ok(None);
                    }
                }
                let refs = reader
                    .lookup("profile_generation_async_refs", &objects[0].1.to_ne_bytes())
                    .context(InterceptorSnafu)?;
                *last.borrow_mut() = format!("references={refs:?}");
                Ok((refs.as_deref() == Some(&0_u64.to_ne_bytes())).then_some(()))
            },
            || last.borrow().clone(),
        )?;
    }

    actor.send(b"stop\n")?;
    actor.wait_gone(pid, "asynchronous reader exit")?;
    actor.stop()?;
    env.stop()
}
