use mithril_control::{ContainerKindV1, WorkloadProtectionPolicy as Policy};

use crate::platform::{platform_test, GroupActor, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = group_recovery]
fn group_roles_recover<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("group-recovery")?;
    env.start_control()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/group_roles_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let members = [
        GroupActor {
            name: "worker",
            script: Some("read_path.py"),
            args: &["worker"],
            kind: ContainerKindV1::Application,
        },
        GroupActor {
            name: "helper",
            script: Some("read_path.py"),
            args: &["helper"],
            kind: ContainerKindV1::Application,
        },
    ];
    let mut group = env.start_actor_group(&members, &labels, |_, _| Ok(()))?;
    assert_eq!(env.install_policy("group_roles_policy.json")?, labels);
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;

    let first = env.recovered(group[0].0.id(), "worker recovery")?;
    let second = env.recovered(group[1].0.id(), "helper recovery")?;
    assert_ne!(first.snapshot.task_cookie, second.snapshot.task_cookie);
    assert_ne!(
        first.snapshot.active_role_id,
        second.snapshot.active_role_id
    );
    let mut bindings = Vec::new();
    for root in [&first, &second] {
        let binding = root
            .snapshot
            .runtime_binding
            .as_ref()
            .ok_or("missing binding")?;
        let recovery = root
            .snapshot
            .recovered_container_activation
            .as_ref()
            .ok_or("missing recovery")?;
        assert_eq!(binding.lifecycle_state, "active_recovered");
        assert_eq!(binding.prepared_container_initial_host_tgid, root.pid);
        assert_eq!(binding.prepared_container_exec_task_cookie, 0);
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
        assert_eq!(root.snapshot.creator_task_cookie, None);
        assert_eq!(recovery.phase, "complete");
        assert_eq!(recovery.expected_task_count, 1);
        assert_eq!(recovery.application_task_count, 1);
        assert_eq!(recovery.external_task_count, 0);
        assert_eq!(recovery.invalid_task_count, 0);
        assert_eq!(
            recovery.application_entry_instance_id,
            root.snapshot.entry_instance_id
        );
        bindings.push(binding);
    }
    assert_ne!(bindings[0].binding_id, bindings[1].binding_id);
    assert_ne!(bindings[0].root_cgroup_id, bindings[1].root_cgroup_id);
    for (actor, _) in &mut group {
        actor.send(b"/fixtures/policy_replace.py\n")?;
    }
    let path = group[0].1.join("0.json");
    let allowed = group[0].0.wait_text(&path, "worker read")?;
    let path = group[1].1.join("0.json");
    let denied = group[1].0.wait_text(&path, "helper read")?;
    let (error, size): (i32, usize) = serde_json::from_str(&allowed)?;
    assert_eq!(error, 0, "{allowed}");
    assert!(size > 0);
    let (error, size): (i32, usize) = serde_json::from_str(&denied)?;
    assert_eq!(error, libc::EACCES, "{denied}");
    assert_eq!(size, 0);

    for (actor, _) in &mut group {
        actor.stop()?;
    }
    env.stop()
}
