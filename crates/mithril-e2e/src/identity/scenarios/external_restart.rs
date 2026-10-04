use std::{fs, fs::File, os::fd::AsRawFd as _, os::unix::fs::FileExt as _, time::Duration};

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;
use erebor_interceptor_abi::{
    ExecutionSetBindingStateV1, ReferenceTombstoneStateV1, TaskCoordinateStateV1,
    TaskReferenceTombstoneV1,
};
use libbpf_rs::{MapCore as _, MapFlags, MapHandle};
use mithril_node::NativeIdentityInspector;
use rustix::process::{pidfd_open, Pid, PidfdFlags};

#[platform_test(host)]
#[lifecycle = node_restart]
fn recovered_root_survives_restart<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("external-restart")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut app = env.start_actor("ready.py", &[], &labels)?;
    let script = actor_script(env.source(), "label_loss.py")?;
    let path = env.work().join("label-control");
    fs::write(&path, [0])?;
    let control = File::options().write(true).open(&path)?;
    let mut actor = ProcessFixture::python(&script, [&path])?;
    let limit = Duration::from_secs(5);
    actor.wait_name(actor.id(), "label-held", "external actor hold", limit)?;
    env.place(actor.id())?;
    let before = env.task(actor.id(), "external before label loss")?.snapshot;
    let group = before.runtime_binding.as_ref().ok_or("missing binding")?;
    let key = group.root_cgroup_id.to_ne_bytes();
    let binding = env
        .state::<ExecutionSetBindingStateV1>("execution_set_bindings", &key, "external binding")?
        .ok_or("missing external binding")?;
    assert!(binding.external_role_id > 0);
    let pid = Pid::from_raw(i32::try_from(actor.id())?).ok_or("invalid actor PID")?;
    let fd = pidfd_open(pid, PidfdFlags::empty())?;
    let map = MapHandle::from_pinned_path(env.maps().0.join("maps/task_labels"))?;
    let key = fd.as_raw_fd().to_ne_bytes();
    assert!(map.lookup(&key, MapFlags::ANY)?.is_some());

    map.delete(&key)?;
    assert!(map.lookup(&key, MapFlags::ANY)?.is_none());
    let inspector = NativeIdentityInspector::new(env.maps().0);
    assert!(inspector.snapshot(actor.id())?.is_none());
    control.write_all_at(&[1], 0)?;
    actor.wait_name(actor.id(), "label-read-ok", "read after loss", limit)?;
    let recovered = env.task(actor.id(), "recovered external identity")?;
    let fresh = &recovered.snapshot;
    assert_ne!(fresh.task_cookie, before.task_cookie);
    assert_ne!(fresh.process_state_id, before.process_state_id);
    for state in [&before, fresh] {
        assert_eq!(state.creator_task_cookie, None);
        assert_eq!(state.admitted_entry_rule_id, 0);
        assert_eq!(state.root_class.as_deref(), Some("external_runtime_root"));
        let role = state.installed_role_class.as_deref();
        assert_eq!(role, Some("runtime_external_restricted"));
        assert_eq!(state.active_role_id, binding.external_role_id);
    }
    assert_eq!(recovered.coordinate.state, TaskCoordinateStateV1::Runnable);
    let healthy = env.snapshot()?;

    env.stop_node()?;
    assert!(env.snapshot().is_err(), "Node observation is live");
    let gap = env.task(actor.id(), "recovered external identity during Node gap")?;
    assert_eq!(gap.snapshot, recovered.snapshot);
    assert_eq!(gap.coordinate, recovered.coordinate);
    env.start_node()?;
    env.node_ready()?;
    let after = env.task(actor.id(), "recovered external identity after Node restart")?;
    assert_eq!(after.snapshot, recovered.snapshot);
    assert_eq!(after.coordinate, recovered.coordinate);
    let key = before.task_cookie.to_ne_bytes();
    let name = "task_reference_tombstones";
    let old = env
        .state::<TaskReferenceTombstoneV1>(name, &key, "live original reference")?
        .ok_or("missing original task reference")?;
    assert_eq!(old.state, ReferenceTombstoneStateV1::Owned);
    assert_eq!((old.released_bits, old.task_free_observed), (0, 0));
    for observation in [healthy, env.snapshot()?] {
        let identity = observation
            .capabilities
            .iter()
            .find(|cap| cap.capability_id == "EXACT_NATIVE_IDENTITY")
            .ok_or("the identity capability is missing")?;
        assert_eq!(identity.state, "SUPPORTED", "{identity:?}");
    }

    actor.close();
    let status = actor.wait_exit("external actor exit", limit)?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    actor.stop()?;
    app.stop()?;
    env.stop()
}
