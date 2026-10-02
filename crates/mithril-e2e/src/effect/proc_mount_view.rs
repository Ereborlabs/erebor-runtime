use std::{fs, process::Command, time::Duration};

use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = bpf_recovery]
fn unowned_mount_view_is_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("proc-mount-view")?;
    env.start_control()?;
    env.start_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/mount_alias_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("mount_alias.py", &["cache"], &labels)?;
    let namespace = format!("/proc/{}/ns/mnt", actor.id());
    let mountinfo = format!("/proc/{}/mountinfo", actor.id());
    fs::metadata(&namespace)?;
    assert!(!fs::read(&mountinfo)?.is_empty());
    env.install_policy("mount_alias_policy.json")?;
    env.sync_policy()?;
    env.node_ready()?;
    let task = env.recovered(actor.id(), "mount observer target")?;
    assert!(task.snapshot.admitted_entry_rule_id > 0);
    actor.send(b"peer\n")?;
    actor.wait_name(
        actor.id(),
        "cache-peer-up",
        "mount observer child",
        Duration::from_secs(5),
    )?;
    let peer = actor.wait_child(actor.id(), "mount observer child PID")?;
    actor.track(peer)?;
    let child = env.task(peer, "mount observer child identity")?;
    assert_eq!(
        child.snapshot.creator_task_cookie,
        Some(task.snapshot.task_cookie)
    );
    let output = Command::new("systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "stat",
            "-Lc",
            "%i",
            &namespace,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "initial runtime target inspection failed"
    );
    let namespace = format!("/proc/{peer}/ns/mnt");
    let mountinfo = format!("/proc/{peer}/mountinfo");

    for (args, allowed) in [
        (vec!["stat", "-Lc", "%i", &namespace], false),
        (vec!["cat", &mountinfo], true),
    ] {
        let output = Command::new("systemd-run")
            .args(["--quiet", "--wait", "--pipe", "--collect"])
            .args(&args)
            .output()?;
        let error = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), allowed, "{args:?}: {error}");
        if allowed {
            assert!(!output.stdout.is_empty(), "empty child mountinfo");
        } else {
            assert!(error.contains("Permission denied"), "{args:?}: {error}");
        }
    }

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
