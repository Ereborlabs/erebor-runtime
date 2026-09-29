use std::fs;

use mithril_control::ContainerKindV1;

use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(kubernetes)]
#[lifecycle = identity]
fn stock_probes_are_entries<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("probe-entries")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("container_kinds_policy.json")?;
    env.node_ready()?;

    let actors = [
        ("readiness", ContainerKindV1::Sidecar),
        ("liveness", ContainerKindV1::Sidecar),
        ("startup", ContainerKindV1::Sidecar),
        ("application", ContainerKindV1::Application),
    ]
    .map(|(name, kind)| GroupActor {
        name,
        script: Some("ready.py"),
        args: &[],
        kind,
    });
    let mut checked = false;
    let mut group = env.start_actor_group(&actors, &labels, |env, group| {
        assert_eq!(group.len(), 3, "the application started before its probes");
        let mut states = Vec::new();
        for ((actor, _), spec) in group.iter_mut().zip(&actors) {
            let root_pid = actor.id();
            let path = actor
                .group_path()
                .ok_or("probe actor has no cgroup")?
                .to_path_buf();
            let probe_pid = actor.wait_group_task(
                &path,
                &[root_pid],
                "python",
                &format!("{} probe process", spec.name),
            )?;
            let root = env.task(root_pid, &format!("{} container root", spec.name))?;
            let probe = env.task(probe_pid, &format!("{} probe identity", spec.name))?;
            assert_eq!(
                root.snapshot.root_class.as_deref(),
                Some("initial_container_root")
            );
            assert_eq!(probe.snapshot.creator_task_cookie, None);
            assert_eq!(
                probe.snapshot.root_class.as_deref(),
                Some("external_runtime_root")
            );
            assert_eq!(
                probe.snapshot.installed_role_class.as_deref(),
                Some("qualified_registered_role")
            );
            assert_ne!(probe.snapshot.active_role_id, root.snapshot.active_role_id);
            assert_ne!(probe.snapshot.admitted_entry_rule_id, 0);
            states.extend([root.snapshot, probe.snapshot]);
            fs::write(
                env.work().join(format!("{}.release", spec.name)),
                b"release\n",
            )?;
        }
        for (index, state) in states.iter().enumerate() {
            for peer in states.iter().skip(index + 1) {
                assert_ne!(state.task_cookie, peer.task_cookie);
                assert_ne!(state.process_state_id, peer.process_state_id);
                assert_ne!(state.active_execution_id, peer.active_execution_id);
            }
        }
        checked = true;
        Ok(())
    })?;
    assert!(checked, "the stock probes were not inspected");
    assert!(
        env.workload_ready()?,
        "the released Pod did not become Ready"
    );
    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
