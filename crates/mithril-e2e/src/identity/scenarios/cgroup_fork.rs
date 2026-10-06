use std::path::Path;

use erebor_interceptor_abi::TaskCoordinateStateV1;

use crate::identity::clone3::CloneIntoCgroupFixture;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn moved_root_stops<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("cgroup-stop")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("external_read_policy.json")?;
    env.node_ready()?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    let group = env.actor_group()?.to_owned();
    let mut actor = CloneIntoCgroupFixture::start(&group)?;
    let pid = actor.root_pid();

    let moved = env.move_task(pid, "moved root cleanup")?;
    assert_eq!(
        moved.coordinate.state,
        TaskCoordinateStateV1::FailClosedUnknown
    );
    actor.stop()?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    init.stop()?;
    env.stop()
}
