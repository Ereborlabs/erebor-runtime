use std::{collections::BTreeSet, fs, io::Write as _, time::Duration};

use mithril_control::WorkloadProtectionPolicy as Policy;
use rustix::fs::{mkfifoat, Mode, CWD};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = recovery_entry]
fn missing_file_is_not_denied<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("missing-startup-file")?;
    env.start_control()?;
    env.stop_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../../fixtures/process/entry_isolation_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut main = env.start_actor("ready.py", &[], &labels)?;
    env.place(main.id())?;
    env.install_policy("entry_isolation_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(main.id())?;
    let root = env.recovered(main.id(), "recovered application")?;
    assert_eq!(
        root.snapshot.root_class.as_deref(),
        Some("recovered_application_root")
    );

    let file = env.work().join("startup.denied");
    fs::write(&file, b"protected\n")?;
    let gate = env.work().join("startup-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;
    let mut cat = env.add_actor("cat", &["/work/startup-gate", "/work/startup.denied"])?;
    let mut release = cat.fifo_writer(&gate, "startup gate", Duration::from_secs(5))?;
    let task = env.task(cat.id(), "recovered startup entry")?;
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let seen: BTreeSet<_> = env
        .snapshot()?
        .recent_effects
        .iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect();

    fs::rename(&file, env.work().join("startup.saved"))?;
    release.write_all(b"release\n")?;
    drop(release);
    cat.close();
    let status = cat.wait_exit("missing startup file", Duration::from_secs(5))?;
    let stderr = cat.stderr()?;
    assert!(!status.success(), "missing cat succeeded: {status}");
    assert!(stderr.contains("No such file or directory"), "{stderr}");
    let effects = env.snapshot()?.recent_effects;
    assert!(
        effects.iter().all(|event| {
            seen.contains(&(event.source_cpu_id, event.source_sequence))
                || event.task_cookie != task.snapshot.task_cookie
                || event.reason != "EXACT_POLICY_DENY"
        }),
        "missing file produced signed denial: {effects:?}"
    );

    cat.stop()?;
    main.stop()?;
    env.stop()
}
