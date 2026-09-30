use std::time::{Duration, Instant};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = identity]
fn evidence_gap_recovers<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("evidence-gap")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("runtime_exec.py", &[], &labels)?;
    let before = env.task(main.id(), "initial actor")?;
    let health = env.snapshot()?;
    assert!(health.negative_claim_eligible, "{health:?}");

    let args = vec!["/work/missing"; 3_000];
    let error = match env.add_actor("cat", &args) {
        Err(error) => error,
        Ok(mut actor) => {
            actor.stop()?;
            return Err("an incomplete declared entry was allowed".into());
        }
    };
    let denied = error.to_string().to_lowercase();
    assert!(
        denied.contains("exit status: 13") || denied.contains("permission denied"),
        "{error}"
    );
    assert!(env.snapshot()?.unresolved_effects > health.unresolved_effects);

    let deadline = Instant::now();
    env.running(main.id())?;
    assert!(deadline.elapsed() < Duration::from_secs(4));
    let mut next = env.start_actor("ready.py", &[], &labels)?;
    env.node_ready()?;
    let restored = env.snapshot()?;
    assert!(restored.negative_claim_eligible, "{restored:?}");
    assert_eq!(restored.evidence_errors, 0);
    assert_eq!(restored.reader_queue_dropped_events, 0);
    assert_eq!(
        env.task(main.id(), "original actor")?.snapshot,
        before.snapshot
    );
    let root = env.task(next.id(), "new actor")?;
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert_eq!(root.snapshot.creator_task_cookie, None);
    assert_ne!(root.snapshot.task_cookie, before.snapshot.task_cookie);
    assert_ne!(
        root.snapshot.process_state_id,
        before.snapshot.process_state_id
    );
    assert_ne!(
        root.snapshot.execution_set_id,
        before.snapshot.execution_set_id
    );

    next.stop()?;
    main.stop()?;
    env.stop()
}
