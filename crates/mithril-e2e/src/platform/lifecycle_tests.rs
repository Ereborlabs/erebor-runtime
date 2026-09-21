use std::{fs, os::unix::fs::MetadataExt as _};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn lifecycle_reuses_node<P: Platform + 'static>() -> TestResult<()> {
    let mut first = P::setup("lifecycle-first")?;
    first.start_control()?;
    first.start_node()?;
    first.install_policy("python_policy.json")?;
    first.node_ready()?;
    let pin = first.maps().0.to_owned();
    let inode = std::fs::metadata(&pin)?.ino();
    let mut actor = first.start_actor("runtime_exec.py", &[])?;
    let denied = match first.add_actor(
        "python-runtime",
        &["/fixtures/ready.py", "/work/runtime-ready"],
    ) {
        Err(error) => error,
        Ok(mut added) => {
            added.stop()?;
            actor.stop()?;
            first.stop()?;
            return Err("the lifecycle admitted an unlisted runtime entry".into());
        }
    };
    let message = denied.to_string().to_lowercase();
    assert!(
        message.contains("exit status: 13") || message.contains("permission denied"),
        "the unlisted runtime entry was not denied with EACCES: {denied}"
    );
    actor.stop()?;
    first.stop()?;

    let mut second = P::setup("lifecycle-second")?;
    second.start_control()?;
    second.start_node()?;
    second.install_policy("python_policy.json")?;
    second.node_ready()?;
    assert_eq!(std::fs::metadata(&pin)?.ino(), inode);
    let mut actor = second.start_actor("ready.py", &[])?;
    second.task(actor.id(), "fresh lifecycle actor")?;
    actor.stop()?;
    second.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn churn_keeps_next_actor<P: Platform + 'static>() -> TestResult<()> {
    for index in 0..8 {
        let name = format!("lifecycle-churn-{index}");
        let policy = if index % 2 == 0 {
            "python_policy.json"
        } else {
            "actor_sleep_policy.json"
        };
        let mut env = P::setup(&name)?;
        env.start_control()?;
        env.start_node()?;
        env.install_policy(policy)?;
        env.node_ready()?;
        let mut actor = env.start_actor("task_churn.py", &["512"])?;
        let before = env.task(actor.id(), "actor identity before churn")?;
        actor.send(b"churn\n")?;
        let result = actor
            .wait_text(&env.work().join("churn"), "task churn completion")
            .map_err(|error| {
                let effects = env.snapshot().map(|snapshot| {
                    snapshot
                        .recent_effects
                        .into_iter()
                        .rev()
                        .take(8)
                        .map(|event| {
                            (
                                event.task_cookie,
                                event.effect_family,
                                event.operation,
                                event.reason,
                                event.kernel_result,
                            )
                        })
                        .collect::<Vec<_>>()
                });
                format!(
                    "{name}: {error}; actor cookie: {}; actor state: {:?}; health: {:?}; effects: {effects:?}",
                    before.snapshot.task_cookie,
                    fs::read_to_string(env.work().join("churn-state")),
                    env.health()
                )
            })?;
        assert!(result.starts_with("ok:"), "{result}");
        let task = env.task(actor.id(), "actor identity after churn")?;
        assert_eq!(task.snapshot.task_cookie, before.snapshot.task_cookie);
        assert_eq!(
            (
                task.snapshot.root_class.as_deref(),
                task.snapshot.installed_role_class.as_deref(),
            ),
            (Some("initial_container_root"), Some("initial_role"))
        );
        let health = env.health()?;
        assert_eq!(
            (
                health.allocation_failures,
                health.coordinate_failures,
                health.placement_mismatches,
                health.missing_identity_denials,
                health.exec_guard_denials,
            ),
            (0, 0, 0, 0, 0)
        );
        actor.stop()?;
        env.stop()?;
    }
    Ok(())
}
