use std::{
    fs, thread,
    time::{Duration, Instant},
};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn large_argv_fills_effect_window<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("large-argv")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("runtime_exec.py", &[])?;

    let mut args = vec!["/fixtures/runtime_copy.txt"; 1_200];
    args.push("-");
    let mut actor = env.add_actor("cat", &args)?;
    let task = env.task(actor.id(), "large-argv actor")?;
    assert_eq!(task.snapshot.active_role_id, 5);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);

    let deadline = Instant::now() + Duration::from_secs(30);
    let count = loop {
        let count = env
            .snapshot()?
            .recent_effects
            .iter()
            .filter(|event| event.task_cookie == task.snapshot.task_cookie)
            .count();
        if count >= 1_024 {
            break count;
        }
        if Instant::now() >= deadline {
            let stderr = actor.stderr()?;
            return Err(format!(
                "large-argv effect window timed out with {count} attributed effects; stderr: {stderr:?}"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(count >= 1_024, "large argv produced {count} recent effects");

    actor.close();
    let status = actor.wait_exit("large-argv actor exit", Duration::from_secs(5))?;
    let stderr = actor.stderr()?;
    assert!(status.success(), "cat exited with {status}: {stderr}");
    actor.stop()?;
    main.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = identity]
fn runtime_entries_stay_distinct<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("runtime-entries")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("runtime_exec.py", &[])?;
    let root = env.task(main.id(), "main actor")?;

    let args = ["/fixtures/ready.py"];
    let mut python = env.add_actor("python", &args)?;
    let py = env.task(python.id(), "Python entry")?;
    let mut shell = env.add_actor("bash", &[])?;
    let sh = env.task(shell.id(), "shell entry")?;
    let mut reader = env.add_actor("cat", &[])?;
    let read = env.task(reader.id(), "reader entry")?;
    let mut counter = env.add_actor("wc", &[])?;
    let count = env.task(counter.id(), "word-count entry")?;

    let source = env
        .source()
        .join("crates/mithril-e2e/fixtures/process/runtime_copy.txt");
    let payload = fs::read(&source)?;
    let mut copy = env.add_actor("cp", &["/proc/self/fd/0", "/work/runtime_copy.txt"])?;
    let cp = env.task(copy.id(), "copy entry")?;

    assert_eq!(root.snapshot.active_role_id, 3);
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("initial_container_root")
    );
    assert_eq!(
        root.snapshot.installed_role_class.as_deref(),
        Some("initial_role")
    );
    assert_ne!(root.snapshot.admitted_entry_rule_id, 0);
    for (task, role) in [(&py, 4), (&sh, 7), (&read, 5), (&count, 8), (&cp, 2)] {
        assert_eq!(task.snapshot.creator_task_cookie, None);
        assert_eq!(
            task.snapshot.root_class.as_deref(),
            Some("external_runtime_root")
        );
        assert_eq!(
            task.snapshot.installed_role_class.as_deref(),
            Some("qualified_registered_role")
        );
        assert_eq!(task.snapshot.active_role_id, role);
        assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    }
    let tasks = [&root, &py, &sh, &read, &count, &cp];
    for (index, task) in tasks.iter().enumerate() {
        for other in &tasks[index + 1..] {
            assert_ne!(task.snapshot.task_cookie, other.snapshot.task_cookie);
            assert_ne!(
                task.snapshot.process_state_id,
                other.snapshot.process_state_id
            );
            assert_ne!(
                task.snapshot.active_execution_id,
                other.snapshot.active_execution_id
            );
            assert_ne!(task.snapshot.active_role_id, other.snapshot.active_role_id);
            assert_ne!(
                task.snapshot.admitted_entry_rule_id,
                other.snapshot.admitted_entry_rule_id
            );
        }
    }

    copy.send(&payload)?;
    copy.close();
    assert!(copy
        .wait_exit("copy exit", Duration::from_secs(5))?
        .success());
    assert_eq!(
        fs::read(format!("/proc/{}/root/work/runtime_copy.txt", main.id()))?,
        payload
    );

    python.stop()?;
    shell.stop()?;
    reader.stop()?;
    counter.stop()?;
    copy.stop()?;
    main.stop()?;
    env.stop()
}
