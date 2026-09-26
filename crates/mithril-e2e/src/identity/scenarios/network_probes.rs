use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use crate::platform::{platform_test, GroupActor, Labels, Platform, TestResult};

#[platform_test(kubernetes)]
#[lifecycle = identity]
fn native_probes_keep_pid1<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("network-probes")?;
    env.start_control()?;
    env.start_node()?;
    env.node_ready()?;

    let actors = ["http", "tcp", "grpc"].map(|name| GroupActor {
        name,
        script: None,
        args: &[],
    });
    let mut group =
        env.start_actor_group("network-probes-pod-v1.yaml", &actors, &Labels::default())?;
    assert!(env.workload_ready()?, "native probes did not become Ready");

    let until = Instant::now() + Duration::from_secs(4);
    loop {
        for (spec, (actor, _)) in actors.iter().zip(&group) {
            let path = actor
                .group_path()
                .ok_or("actor has no cgroup")?
                .join("cgroup.procs");
            let tasks = fs::read_to_string(&path)?
                .split_ascii_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(tasks, [actor.id()], "{}: {}", spec.name, path.display());
        }
        if Instant::now() >= until {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
