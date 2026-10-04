use std::{fs, fs::File, os::fd::AsRawFd as _, os::unix::fs::FileExt as _, time::Duration};

use crate::platform::{actor_script, platform_test, Platform, TestResult};
use crate::process::ProcessFixture;
use erebor_interceptor_abi::{ReferenceTombstoneStateV1, TASK_REFERENCE_ALL_V1};
use libbpf_rs::{MapCore as _, MapFlags, MapHandle};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use zerocopy::IntoBytes as _;

#[platform_test(host)]
#[lifecycle = node_restart]
fn orphan_release_requires_exact_owner<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("orphan-reference")?;
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
    let before = env.task(actor.id(), "external before label loss")?;
    let cookie = before.snapshot.task_cookie;
    let profile = before.snapshot.profile_generation_ref_id;
    let task_key = cookie.to_ne_bytes();
    let profile_key = profile.to_ne_bytes();
    let refs_map = "profile_generation_task_refs";
    let pid = Pid::from_raw(i32::try_from(actor.id())?).ok_or("invalid actor PID")?;
    let fd = pidfd_open(pid, PidfdFlags::empty())?;
    let labels = MapHandle::from_pinned_path(env.maps().0.join("maps/task_labels"))?;
    let key = fd.as_raw_fd().to_ne_bytes();

    labels.delete(&key)?;
    assert!(labels.lookup(&key, MapFlags::ANY)?.is_none());
    control.write_all_at(&[1], 0)?;
    actor.wait_name(actor.id(), "label-read-ok", "read after loss", limit)?;
    let fresh = env.task(actor.id(), "recovered external actor")?;
    assert_ne!(fresh.snapshot.task_cookie, cookie);
    let coordinates = MapHandle::from_pinned_path(env.maps().0.join("maps/task_coordinates"))?;
    let mut corrupt = before.coordinate;
    corrupt.process_instance_id.low ^= 1;

    env.stop_node()?;
    actor.close();
    assert!(actor.wait_exit("external actor exit", limit)?.success());
    actor.stop()?;
    coordinates.update(&task_key, corrupt.as_bytes(), MapFlags::EXIST)?;
    env.start_node()?;
    env.node_ready()?;
    let retained = env.tombstone(cookie)?.ok_or("missing orphan tombstone")?;
    assert_eq!(retained.state, ReferenceTombstoneStateV1::Owned);
    assert_eq!(
        (retained.released_bits, retained.task_free_observed),
        (0, 0)
    );
    let refs = env
        .state::<u64>(refs_map, &profile_key, "retained refs")?
        .ok_or("missing profile references")?;
    assert_eq!(refs, 2);

    coordinates.update(&task_key, before.coordinate.as_bytes(), MapFlags::EXIST)?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    let released = env.tombstone(cookie)?.ok_or("missing released tombstone")?;
    assert_eq!(released.state, ReferenceTombstoneStateV1::Released);
    assert_eq!(released.released_bits, TASK_REFERENCE_ALL_V1);
    assert_eq!(released.task_free_observed, 1);
    let refs = env
        .state::<u64>(refs_map, &profile_key, "released refs")?
        .ok_or("missing profile references")?;
    assert_eq!(refs, 1);

    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    let duplicate = env.tombstone(cookie)?.ok_or("missing tombstone")?;
    assert_eq!(duplicate, released);
    assert_eq!(
        env.state::<u64>(refs_map, &profile_key, "duplicate refs")?,
        Some(refs)
    );
    app.stop()?;
    env.stop()
}
