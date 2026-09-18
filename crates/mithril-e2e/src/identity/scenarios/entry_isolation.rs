use std::cell::RefCell;
use std::fs;
use std::io::Write as _;
use std::time::Duration;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};
use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use rustix::fs::{mkfifoat, Mode, CWD};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn entry_roles_are_isolated<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("entry-isolation")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("entry_isolation_policy.json")?;
    env.node_ready()?;

    fs::create_dir(env.work().join("secret"))?;
    fs::write(env.work().join("secret/data"), b"application secret\n")?;
    for name in ["startup", "readiness", "liveness"] {
        fs::write(env.work().join(format!("{name}.denied")), b"denied\n")?;
    }
    let gate = env.work().join("entry-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;

    let secret = "/work/secret/data";
    let gate_arg = "/work/entry-gate";
    let cat = [secret, gate_arg, "/work/startup.denied"];
    let grep = ["application", secret, gate_arg, "/work/readiness.denied"];
    let wc = [secret, gate_arg, "/work/liveness.denied"];
    let entries = [
        ("startup", "cat", cat.as_slice()),
        ("readiness", "grep", grep.as_slice()),
        ("liveness", "wc", wc.as_slice()),
    ];

    let mut main = env.start_actor("runtime_exec.py", &[])?;
    let app = env.task(main.id(), "application identity")?;
    let path = env.maps().0.to_owned();
    for (name, command, args) in entries {
        let mut actor = env.add_actor(command, args)?;
        let operation = format!("{name} entry FIFO");
        let mut release = actor.fifo_writer(&gate, &operation, Duration::from_secs(5))?;
        let task = env.task(actor.id(), &format!("{name} entry identity"))?;
        let snap = &task.snapshot;
        let root = snap.root_class.as_deref();
        let class = snap.installed_role_class.as_deref();
        assert_eq!(snap.creator_task_cookie, None, "{name}");
        assert_eq!(root, Some("external_runtime_root"), "{name}");
        assert_eq!(class, Some("qualified_registered_role"), "{name}");
        assert_ne!(snap.task_cookie, 0, "{name}");
        assert!(!snap.process_state_id.is_empty(), "{name}");
        assert!(!snap.active_execution_id.is_empty(), "{name}");
        assert_ne!(snap.profile_generation_ref_id, 0, "{name}");
        assert_ne!(snap.admitted_entry_rule_id, 0, "{name}");
        assert_ne!(snap.active_role_id, app.snapshot.active_role_id, "{name}");

        release.write_all(b"release\n")?;
        drop(release);
        actor.close();
        let operation = format!("{name} policy denial");
        assert!(!actor
            .wait_exit(&operation, Duration::from_secs(5))?
            .success());

        let last = RefCell::new(String::from("<none>"));
        let operation = format!("{name} policy evidence");
        wait_for(
            &path,
            &operation,
            Duration::from_secs(30),
            || {
                let events = env.snapshot().map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                *last.borrow_mut() = format!("{:?}", events.recent_effects.iter().rev().take(8));
                Ok(events.recent_effects.into_iter().find(|event| {
                    event.reason == "EXACT_POLICY_DENY"
                        && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
                        && event.operation == u32::from(KernelEffectOperationV1::OpenRead as u16)
                        && event.kernel_result == -libc::EACCES
                        && event.task_cookie == snap.task_cookie
                        && event.active_role_id == snap.active_role_id
                        && event.admitted_entry_rule_id == snap.admitted_entry_rule_id
                }))
            },
            || format!("{name}; last effects: {}", last.borrow()),
        )?;
        actor.stop()?;
    }

    main.stop()?;
    env.stop()
}
