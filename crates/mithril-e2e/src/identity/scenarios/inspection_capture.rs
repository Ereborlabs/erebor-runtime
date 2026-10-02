use std::process::{Command, Stdio};
use std::{env, fs, io::Write as _, path::PathBuf, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;
use rustix::fs::{mkfifoat, Mode, CWD};

use crate::effect::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host, runc)]
#[lifecycle = inspection_recovery]
fn inspection_keeps_signed_deny<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("inspection-capture")?;
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
    let root = env.recovered(main.id(), "inspected application")?.snapshot;
    assert_eq!(
        root.root_class.as_deref(),
        Some("recovered_application_root")
    );

    let limit = Duration::from_secs(5);
    fs::write(env.work().join("startup.denied"), b"protected\n")?;
    let gate = env.work().join("startup-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;
    let mut cat = env.add_actor("cat", &["/work/startup-gate", "/work/startup.denied"])?;
    let mut release = cat.fifo_writer(&gate, "startup gate", limit)?;
    let task = env.task(cat.id(), "inspected startup entry")?;
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    let effects = EffectCheck::new(&env, task)?;
    release.write_all(b"release\n")?;
    drop(release);
    cat.close();
    let status = cat.wait_exit("startup denial", limit)?;
    assert!(!status.success(), "protected cat succeeded: {status}");
    let event = effects.wait(
        &env,
        "EXACT_POLICY_DENY",
        F::File,
        O::OpenRead,
        -libc::EACCES,
        "inspected signed denial",
    )?;

    let bin = PathBuf::from(env::var("MITHRIL_BIN_DIRECTORY")?).join("mithril-inspect");
    let socket = PathBuf::from(env::var("MITHRIL_TEST_OUTPUT")?).join("observation.sock");
    let child = Command::new(&bin)
        .args(["effects", "--socket-path"])
        .arg(&socket)
        .args(["--cgroup-scope", "/", "--samples", "1"])
        .args(["--reason", "EXACT_POLICY_DENY"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut inspect = ProcessFixture::new(child, &bin);
    let status = inspect.wait_exit("public denial capture", limit);
    let stderr = inspect.stderr()?;
    let status = status.map_err(|error| format!("{error}; {socket:?}; {stderr}"))?;
    assert!(status.success(), "inspection failed: {status}; {stderr}");
    let output = String::from_utf8(inspect.stdout(status)?)?;
    let source = format!(
        "source_sequence={} source_cpu_id={} task_cookie={} ",
        event.source_sequence, event.source_cpu_id, event.task_cookie
    );
    let line = output
        .lines()
        .find(|line| line.contains(&source))
        .ok_or_else(|| format!("inspection omitted source {source}: {output}"))?;
    for field in [
        format!("admitted_entry_rule_id={} ", event.admitted_entry_rule_id),
        format!("active_role_id={} ", event.active_role_id),
        format!("family={} ", event.effect_family),
        format!("operation={} ", event.operation),
        "reason=EXACT_POLICY_DENY ".to_owned(),
        format!("kernel_result={} ", -libc::EACCES),
    ] {
        assert!(line.contains(&field), "inspection omitted {field}: {line}");
    }

    inspect.stop()?;
    cat.stop()?;
    main.stop()?;
    env.stop()
}
