use std::{path::Path, time::Duration};

use erebor_interceptor_abi::{
    ExecutionSetBindingStateV1, KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O,
    TaskCoordinateStateV1,
};

use crate::effect::EffectCheck;
use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn root_first_open_allowed<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("clone-first-open")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;

    let script = actor_script(env.source(), "clone_cgroup.py")?;
    let file = Path::new("/etc/hostname");
    let path = env.work().join("clone.pid");
    let group = init.group_path().ok_or("missing actor cgroup")?;
    let mut actor = ProcessFixture::python(
        &script,
        [group.as_os_str(), file.as_os_str(), path.as_os_str()],
    )?;
    let pid = actor.wait_pid(&path, "clone root PID")?;
    actor.set_actor(pid)?;
    let task = env.task(pid, "unmoved root identity")?;
    assert_eq!(task.snapshot.creator_task_cookie, None);
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("runtime_external_restricted")
    );
    assert_ne!(task.snapshot.active_role_id, 0);
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(task.coordinate.state, TaskCoordinateStateV1::Runnable);
    let key = task
        .snapshot
        .runtime_binding
        .as_ref()
        .ok_or("missing runtime binding")?
        .root_cgroup_id
        .to_ne_bytes();
    let binding = env
        .state::<ExecutionSetBindingStateV1>("execution_set_bindings", &key, "clone binding")?
        .ok_or("missing clone binding")?;
    assert_eq!(task.snapshot.active_role_id, binding.external_role_id);
    let effects = EffectCheck::new(&env, task.clone())?;

    actor.send(b"open\n")?;
    let status = actor.wait_exit("unmoved first open", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let event = effects.wait_match(&env, "clone open result", |event| {
        event.task_cookie == task.snapshot.task_cookie
            && event.effect_family == u32::from(F::File as u16)
            && event.operation == u32::from(O::OpenRead as u16)
    })?;
    assert_eq!(event.kernel_result, 0);
    assert_eq!(event.active_role_id, binding.external_role_id);
    assert_eq!(event.admitted_entry_rule_id, 0);
    assert_eq!(
        event.profile_generation_ref_id,
        task.snapshot.profile_generation_ref_id
    );

    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    init.stop()?;
    env.stop()
}
