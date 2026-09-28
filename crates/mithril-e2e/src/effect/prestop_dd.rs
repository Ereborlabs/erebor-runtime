use std::{fs, io::Write as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use rustix::fs::{mkfifoat, Mode, CWD};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc, kubernetes)]
#[lifecycle = node_restart]
fn prestop_keeps_file_role<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("prestop-dd")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("runtime_entries_policy.json")?;
    env.node_ready()?;
    let gate = env.work().join("application.denied");
    mkfifoat(CWD, &gate, Mode::RUSR | Mode::WUSR)?;
    fs::write(env.work().join("prestop.denied"), b"prestop\n")?;
    let mut main = env.start_actor("ready.py", &[], &labels)?;
    let root = env.task(main.id(), "application before Node restart")?;
    env.stop_node()?;
    env.start_node()?;
    env.node_ready()?;
    assert_eq!(
        env.task(main.id(), "application after restart")?.snapshot,
        root.snapshot
    );

    let mut dd = env.add_actor(
        "dd",
        &["if=/work/application.denied", "of=/work/prestop-output"],
    )?;
    let mut release = dd.fifo_writer(&gate, "PreStop control read", Duration::from_secs(5))?;
    let task = env.task(dd.id(), "PreStop control entry")?;
    let role = task.snapshot.active_role_id;
    let rule = task.snapshot.admitted_entry_rule_id;
    let cookie = task.snapshot.task_cookie;
    assert_ne!(role, root.snapshot.active_role_id);
    assert_ne!(rule, 0);
    assert_eq!(task.entry_rule(&env)?.target_role_id, role);
    assert_eq!(
        task.snapshot.profile_generation_ref_id,
        root.snapshot.profile_generation_ref_id
    );
    assert_eq!(
        task.snapshot.root_class.as_deref(),
        Some("external_runtime_root")
    );
    assert_eq!(
        task.snapshot.installed_role_class.as_deref(),
        Some("qualified_registered_role")
    );
    release.write_all(b"application\n")?;
    drop(release);
    dd.close();
    assert!(dd
        .wait_exit("PreStop control read", Duration::from_secs(5))?
        .success());
    assert_eq!(
        fs::read(env.work().join("prestop-output"))?,
        b"application\n"
    );
    dd.stop()?;

    let effects = EffectCheck::new(&env, task)?;
    let denied = env.add_actor(
        "dd",
        &["if=/work/prestop.denied", "of=/work/prestop-denied-output"],
    );
    if let Ok(mut dd) = denied {
        dd.close();
        assert!(!dd
            .wait_exit("PreStop denied read", Duration::from_secs(5))?
            .success());
        dd.stop()?;
    }
    effects.wait_match(&env, "PreStop own file denial", |event| {
        event.task_cookie != cookie
            && event.active_role_id == role
            && event.admitted_entry_rule_id == rule
            && event.reason == "EXACT_POLICY_DENY"
            && event.effect_family == u32::from(KernelEffectFamilyV1::File as u16)
            && event.operation == u32::from(KernelEffectOperationV1::OpenRead as u16)
            && event.kernel_result == -libc::EACCES
    })?;
    assert!(!env.work().join("prestop-denied-output").exists());
    main.stop()?;
    env.stop()
}
