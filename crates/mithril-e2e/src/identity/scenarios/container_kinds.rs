use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn group_kinds_are_isolated<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("container-kinds")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("container_kinds_policy.json")?;
    env.node_ready()?;

    let actors = [
        GroupActor {
            name: "sidecar",
            script: Some("read_path.py"),
            args: &["sidecar"],
        },
        GroupActor {
            name: "init",
            script: Some("ready.py"),
            args: &[],
        },
        GroupActor {
            name: "application",
            script: Some("read_path.py"),
            args: &["application"],
        },
    ];
    let mut early = None;
    let mut group = env.start_actor_group(
        "container-kinds-pod-v1.yaml",
        &actors,
        &labels,
        |env, group| {
            assert_eq!(group.len(), 2, "init and sidecar must precede application");
            let side = env.task(group[0].0.id(), "sidecar before application")?;
            let init = env.task(group[1].0.id(), "init before application")?;
            assert_ne!(side.snapshot.task_cookie, init.snapshot.task_cookie);
            early = Some((side.snapshot, init.snapshot));
            group[1].0.send(b"stop\n")?;
            Ok(())
        },
    )?;
    let (side_before, init_root) = early.ok_or("the pre-application checkpoint did not run")?;
    let side_after = env.task(group[0].0.id(), "sidecar after application")?;
    let application = env.task(group[2].0.id(), "application identity")?;
    assert_eq!(side_before, side_after.snapshot);
    let roots = [&side_before, &init_root, &application.snapshot];
    for first in 0..3 {
        let root = roots[first];
        assert_eq!(root.root_class.as_deref(), Some("initial_container_root"));
        assert!(root.creator_task_cookie.is_none());
        assert!(root.execution_set_id.is_some());
        assert!(root.runtime_binding.is_some());
        for peer in roots.iter().skip(first + 1) {
            assert_ne!(root.task_cookie, peer.task_cookie);
            assert_ne!(root.process_state_id, peer.process_state_id);
            assert_ne!(root.execution_set_id, peer.execution_set_id);
            assert_ne!(root.active_role_id, peer.active_role_id);
            assert_ne!(
                root.runtime_binding
                    .as_ref()
                    .ok_or("first binding missing")?
                    .root_cgroup_id,
                peer.runtime_binding
                    .as_ref()
                    .ok_or("second binding missing")?
                    .root_cgroup_id
            );
        }
    }

    for index in [0, 2] {
        let (actor, work) = &mut group[index];
        actor.send(b"/fixtures/policy_replace.py\n")?;
        let result = actor.wait_text(&work.join("0.json"), "container-kind read")?;
        let (errno, size): (i32, usize) = serde_json::from_str(&result)?;
        if index == 0 {
            assert_eq!((errno, size > 0), (0, true), "sidecar: {result}");
        } else {
            assert_eq!((errno, size), (libc::EACCES, 0), "{index}: {result}");
        }
    }
    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
