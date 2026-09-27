use mithril_control::WorkloadProtectionPolicy as Policy;
use std::time::Duration;

use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = staged_containers]
fn sidecar_recovers<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("staged-containers")?;
    env.start_control()?;

    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/staged_containers_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let actors = [GroupActor {
        name: "sidecar",
        script: Some("native_recovery.py"),
        args: &[],
    }];
    let mut group = env.start_actor_group("staged-containers-pod.yaml", &actors, &labels)?;
    let pid = group[0].0.id();
    env.place(pid)?;

    env.install_policy("staged_containers_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;

    let root = env.recovered(pid, "recovered sidecar")?;
    assert!(root.snapshot.task_cookie > 0);
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert!(root.snapshot.active_role_id > 0);
    assert!(root.snapshot.admitted_entry_rule_id > 0);

    let next = [
        GroupActor {
            name: "init",
            script: Some("native_recovery.py"),
            args: &[],
        },
        GroupActor {
            name: "application",
            script: Some("native_recovery.py"),
            args: &[],
        },
    ];
    let mut later = env.start_actor_group("staged-containers-pod.yaml", &next, &labels)?;
    let init = env.task(later[0].0.id(), "init identity")?;
    let app = env.task(later[1].0.id(), "application identity")?;
    let a = &root.snapshot;
    let b = &init.snapshot;
    let c = &app.snapshot;
    assert_ne!(a.task_cookie, b.task_cookie);
    assert_ne!(a.task_cookie, c.task_cookie);
    assert_ne!(b.task_cookie, c.task_cookie);
    assert_ne!(a.process_state_id, b.process_state_id);
    assert_ne!(a.process_state_id, c.process_state_id);
    assert_ne!(b.process_state_id, c.process_state_id);
    assert_ne!(a.execution_set_id, b.execution_set_id);
    assert_ne!(a.execution_set_id, c.execution_set_id);
    assert_ne!(b.execution_set_id, c.execution_set_id);
    assert_ne!(a.active_role_id, b.active_role_id);
    assert_ne!(a.active_role_id, c.active_role_id);
    assert_ne!(b.active_role_id, c.active_role_id);
    let roots = [a, b, c].map(|task| task.runtime_binding.as_ref().map(|v| v.root_cgroup_id));
    assert!(roots.iter().all(Option::is_some));
    assert_ne!(roots[0], roots[1]);
    assert_ne!(roots[0], roots[2]);
    assert_ne!(roots[1], roots[2]);
    assert_eq!(env.task(pid, "stable sidecar")?.snapshot, root.snapshot);

    group[0].0.send(b"effect\n")?;
    group[0].0.close();
    let code = group[0]
        .0
        .wait_exit("denied executable", Duration::from_secs(5))?
        .code()
        .ok_or("the sidecar exited without a code")?;
    assert_eq!(code, libc::EACCES);
    for (actor, _) in &mut later {
        actor.stop()?;
    }
    env.stop()
}
