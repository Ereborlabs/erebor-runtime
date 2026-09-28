use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn undeclared_hook_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("poststart-hook-exec")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("python_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("poststart_order.py", &["main", "actor-first"], &labels)?;
    let work = env.work().to_path_buf();
    actor.wait_text(&work.join("main.json"), "application start")?;
    let denied = env
        .add_actor(
            "python",
            &[
                "/fixtures/poststart_order.py",
                "/work",
                "hook",
                "actor-first",
            ],
        )
        .err()
        .ok_or("undeclared runtime hook exec succeeded")?;
    let reason = denied.to_string().to_lowercase();
    assert!(
        reason.contains("permission denied") || reason.contains("exit status: 13"),
        "{reason}"
    );
    assert!(!work.join("hook.json").exists(), "the denied hook ran");
    actor.ensure_running("application after denied hook")?;
    let main = env.task(actor.id(), "application after denied hook")?;
    assert_eq!(
        main.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
