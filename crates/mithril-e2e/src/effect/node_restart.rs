use std::{cell::RefCell, fs, io::Write as _, time::Duration};

use erebor_interceptor_abi::{
    EntryAdmissionRuleKeyV1, EntryAdmissionRuleV1, ExactFileObjectKeyV1, KernelEffectFamilyV1,
    KernelEffectOperationV1,
};
use rustix::fs::{mkfifoat, Mode, CWD};
use zerocopy::TryFromBytes as _;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = node_restart]
fn node_restart_keeps_actor<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("node-restart")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("ready.py", &[])?;
    let before = env.task(actor.id(), "actor before Node restart")?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    let after = env.task(actor.id(), "actor after Node restart")?;
    assert_eq!(after.snapshot, before.snapshot);
    assert_eq!(after.coordinate, before.coordinate);
    let args = ["/fixtures/ready.py"];
    let mut prestop = env.add_actor("python", &args)?;
    prestop.ready()?;
    let task = env.task(prestop.id(), "PreStop entry after Node restart")?;
    assert_eq!(
        task.snapshot.profile_generation_ref_id,
        after.snapshot.profile_generation_ref_id
    );
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(task.snapshot.active_role_id, 4);
    assert_ne!(task.snapshot.admitted_entry_rule_id, 0);
    prestop.stop()?;
    actor.stop()?;
    env.stop()
}

#[platform_test(host, runc, kubernetes)]
#[lifecycle = node_restart]
fn poststart_keeps_its_role<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("poststart-role")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    fs::write(env.work().join("application.denied"), b"application\n")?;
    fs::write(env.work().join("poststart.denied"), b"poststart\n")?;
    fs::create_dir(env.work().join("copy-out"))?;
    let gate = env.work().join("copy-gate");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;

    let mut main = env.start_actor("runtime_exec.py", &[])?;
    let root = env.task(main.id(), "application before Node restart")?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    assert_eq!(
        env.task(main.id(), "application after Node restart")?
            .snapshot,
        root.snapshot
    );

    let args = [
        "/work/application.denied",
        "/work/copy-gate",
        "/work/poststart.denied",
        "/work/copy-out",
    ];
    let mut copy = env.add_actor("cp", &args)?;
    let mut release = copy.fifo_writer(&gate, "PostStart copy gate", Duration::from_secs(5))?;
    let task = env.task(copy.id(), "PostStart entry after Node restart")?;
    let snap = &task.snapshot;
    assert_eq!(
        fs::read(env.work().join("copy-out/application.denied"))?,
        b"application\n"
    );
    assert_eq!(snap.root_class.as_deref(), Some("external_runtime_root"));
    assert_eq!(
        snap.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    assert_eq!(
        snap.profile_generation_ref_id,
        root.snapshot.profile_generation_ref_id
    );
    assert_eq!(snap.active_role_id, 2);
    assert_ne!(snap.active_role_id, root.snapshot.active_role_id);
    assert_ne!(snap.admitted_entry_rule_id, 0);
    release.write_all(b"gate\n")?;
    drop(release);
    copy.close();
    assert!(!copy
        .wait_exit("PostStart denied read", Duration::from_secs(5))?
        .success());
    let stderr = copy.stderr()?;
    assert!(stderr.contains("Permission denied"), "{stderr}");
    let path = env.maps().0.to_owned();
    let last = RefCell::new(String::from("<none>"));
    wait_for(
        &path,
        "PostStart policy denial",
        Duration::from_secs(30),
        || {
            let events = env.snapshot().map_err(|source| {
                InvalidInputSnafu {
                    path: &path,
                    reason: source.to_string(),
                }
                .build()
            })?;
            *last.borrow_mut() = format!("{:?}", events.recent_effects.iter().rev().take(8));
            Ok(events.recent_effects.into_iter().find(|event| {
                task.matches_effect(
                    event,
                    "EXACT_POLICY_DENY",
                    KernelEffectFamilyV1::File,
                    KernelEffectOperationV1::OpenRead,
                    -libc::EACCES,
                )
            }))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    copy.stop()?;
    main.stop()?;
    env.stop()
}

#[platform_test(host)]
#[lifecycle = node_restart]
fn poststart_uses_literal_path<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("poststart-path")?;
    env.start_control()?;
    env.start_node()?;
    env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let mut main = env.start_actor("ready.py", &[])?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;

    let mut copy = env.add_actor("cp", &["/proc/self/fd/0", "/work/literal.txt"])?;
    let task = env.task(copy.id(), "PostStart literal admission")?;
    let reader = env.maps().1;
    let mut matched = None;
    for key in reader.keys("entry_admission_rules")? {
        let entry = EntryAdmissionRuleKeyV1::try_read_from_bytes(&key)
            .map_err(|error| format!("invalid admission key: {error}"))?;
        if entry.profile_generation_ref_id != task.snapshot.profile_generation_ref_id {
            continue;
        }
        let bytes = reader
            .lookup("entry_admission_rules", &key)?
            .ok_or("the PostStart admission rule disappeared")?;
        let rule = EntryAdmissionRuleV1::try_read_from_bytes(&bytes)
            .map_err(|error| format!("invalid admission rule: {error}"))?;
        if rule.admitted_entry_rule_id == task.snapshot.admitted_entry_rule_id {
            matched = Some(rule);
            break;
        }
    }
    let rule = matched.ok_or("the PostStart admission rule is missing")?;
    assert_eq!(rule.target_role_id, task.snapshot.active_role_id);
    assert_ne!(rule.admitted_entry_rule_id, 0);
    assert_eq!(rule.exact_object_key_id, 0);
    assert_eq!(rule.executable_object, ExactFileObjectKeyV1::default());

    copy.send(b"literal\n")?;
    copy.close();
    assert!(copy
        .wait_exit("PostStart literal copy", Duration::from_secs(5))?
        .success());
    assert_eq!(fs::read(env.work().join("literal.txt"))?, b"literal\n");
    copy.stop()?;
    main.stop()?;
    env.stop()
}
