use std::cell::RefCell;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::Duration;

use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};
use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use rustix::fs::{mkfifoat, Mode, CWD};
use snafu::ResultExt as _;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn startup_role_is_isolated<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("entry-isolation")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("entry_isolation_policy.json")?;
    env.node_ready()?;

    fs::create_dir(env.work().join("secret"))?;
    fs::write(env.work().join("secret/data"), b"application secret\n")?;
    fs::write(env.work().join("startup.denied"), b"startup secret\n")?;
    let gate = env.work().join("entry-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;

    let mut main = env.start_actor("runtime_exec.py", &[])?;
    let app = env.task(main.id(), "application identity")?;
    let args = [
        "/work/secret/data",
        "/work/entry-gate",
        "/work/startup.denied",
    ];
    let mut actor = env.add_actor("cat", &args)?;
    let mut release = wait_for(
        &gate,
        "startup entry FIFO",
        Duration::from_secs(5),
        || match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&gate)
        {
            Ok(file) => Ok(Some(file)),
            Err(source) if source.raw_os_error() == Some(libc::ENXIO) => Ok(None),
            Err(source) => Err(source).context(IoSnafu { path: &gate }),
        },
        || "the startup entry has no FIFO reader".to_owned(),
    )?;
    let task = env.task(actor.id(), "startup entry identity")?;
    let snap = &task.snapshot;
    assert_eq!(snap.creator_task_cookie, None);
    assert_eq!(snap.root_class.as_deref(), Some("external_runtime_root"));
    let class = snap.installed_role_class.as_deref();
    assert_eq!(class, Some("qualified_registered_role"));
    assert_ne!(snap.admitted_entry_rule_id, 0);
    assert_ne!(snap.active_role_id, app.snapshot.active_role_id);

    release.write_all(b"release\n")?;
    drop(release);
    actor.close();
    assert!(!actor
        .wait_exit("startup policy denial", Duration::from_secs(5))?
        .success());

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "startup policy evidence",
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
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    main.stop()?;
    env.stop()
}
