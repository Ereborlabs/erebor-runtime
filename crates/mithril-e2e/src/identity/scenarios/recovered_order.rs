use std::{fs, io::Write as _, time::Duration};

use mithril_control::WorkloadProtectionPolicy as Policy;
use rustix::fs::{mkfifoat, Mode, CWD};

use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = recovery_entry]
fn readiness_precedes_startup<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("recovered-entry-order")?;
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

    fs::create_dir(env.work().join("secret"))?;
    fs::write(env.work().join("secret/data"), b"READY\n")?;
    let gate = env.work().join("entry-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;
    let mut grep = env.add_actor("grep", &["READY", "/work/secret/data", "/work/entry-gate"])?;
    let mut release = grep.fifo_writer(&gate, "readiness gate", Duration::from_secs(5))?;
    let ready = env.task(grep.id(), "recovered readiness entry")?;
    assert_eq!(
        ready.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_ne!(ready.snapshot.active_role_id, root.snapshot.active_role_id);
    assert_ne!(ready.snapshot.admitted_entry_rule_id, 0);
    release.write_all(b"release\n")?;
    drop(release);
    grep.close();
    let status = grep.wait_exit("readiness entry", Duration::from_secs(5))?;
    assert!(
        status.success(),
        "readiness failed: {status}; {:?}",
        grep.stderr()?
    );

    let mut cat = env.add_actor("cat", &["/work/secret/data", "/work/entry-gate"])?;
    let mut release = cat.fifo_writer(&gate, "startup gate", Duration::from_secs(5))?;
    let startup = env.task(cat.id(), "recovered startup entry")?;
    assert_eq!(
        startup.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_ne!(startup.snapshot.task_cookie, ready.snapshot.task_cookie);
    assert_ne!(
        startup.snapshot.active_role_id,
        ready.snapshot.active_role_id
    );
    assert_ne!(startup.snapshot.admitted_entry_rule_id, 0);
    assert_eq!(
        startup.snapshot.profile_generation_ref_id,
        ready.snapshot.profile_generation_ref_id
    );
    release.write_all(b"release\n")?;
    drop(release);
    cat.close();
    let status = cat.wait_exit("startup entry", Duration::from_secs(5))?;
    assert!(
        status.success(),
        "startup failed: {status}; {:?}",
        cat.stderr()?
    );

    cat.stop()?;
    grep.stop()?;
    main.stop()?;
    env.stop()
}
