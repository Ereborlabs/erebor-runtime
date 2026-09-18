use std::cell::RefCell;
use std::time::Duration;

use erebor_interceptor_abi::{
    KernelEffectFamilyV1, KernelEffectOperationV1, TaskCoordinateStateV1,
};
use rustix::io::Errno;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
#[lifecycle = identity]
fn cgroup_exec_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("external-cgroup")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("actor_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[])?;

    let script = actor_script(env.source(), "exec_on_release.py")?;
    let mut actor = ProcessFixture::python(&script, ["/usr/bin/true"])?;
    env.place(actor.id())?;
    let task = env.task(actor.id(), "external cgroup identity")?;
    let snap = &task.snapshot;
    assert_eq!(snap.creator_task_cookie, None);
    assert_eq!(snap.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        snap.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_eq!(snap.active_role_id, 2);
    assert_eq!(snap.admitted_entry_rule_id, 0);
    assert_eq!(task.coordinate.state, TaskCoordinateStateV1::Runnable);

    actor.send(b"exec\n")?;
    actor.close();
    let status = actor.wait_exit("external cgroup exec", Duration::from_secs(5))?;
    assert_eq!(status.code(), Some(Errno::ACCESS.raw_os_error()));

    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "external cgroup exec evidence",
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
                event.task_cookie == snap.task_cookie
                    && event.reason == "UNSUPPORTED_OBJECT"
                    && event.effect_family == u32::from(KernelEffectFamilyV1::Exec as u16)
                    && event.operation == u32::from(KernelEffectOperationV1::Execute as u16)
                    && event.active_role_id == snap.active_role_id
                    && event.admitted_entry_rule_id == 0
                    && event.kernel_result == -libc::EACCES
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;

    actor.stop()?;
    init.stop()?;
    env.stop()
}
