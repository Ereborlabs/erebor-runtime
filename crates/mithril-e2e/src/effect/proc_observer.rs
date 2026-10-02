use std::process::Command;

use mithril_control::WorkloadProtectionPolicy as Policy;

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = bpf_recovery]
fn unowned_read_is_denied<P: Platform>() -> TestResult<()> {
    let policy: Policy =
        serde_json::from_str(include_str!("../../fixtures/process/python_policy.json"))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut env = P::setup("proc-observer")?;
    env.start_control()?;
    env.start_node()?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let mut actor = env.add_actor("python", &["/fixtures/ready.py", "/work"])?;
    actor.ready()?;
    env.place(actor.id())?;
    let path = format!("/proc/{}/ns/net", actor.id());
    std::fs::read_link(&path)?;
    env.install_policy("python_policy.json")?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "observer workload")?;
    let task = env.task(actor.id(), "observer target")?;
    assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("restored_or_unknown_root")
    );

    let output = Command::new("systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "readlink",
            "-v",
            &path,
        ])
        .output()?;
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unowned namespace read succeeded");
    assert!(error.contains("Permission denied"), "{error}");

    actor.stop()?;
    init.stop()?;
    env.stop()
}
