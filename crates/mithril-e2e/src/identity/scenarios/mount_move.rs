use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{platform_test, Platform, TestResult};
use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use std::cell::RefCell;
use std::os::unix::fs::MetadataExt as _;
use std::{collections::BTreeSet, fs, time::Duration};
#[platform_test(host, runc, kubernetes)]
#[lifecycle = mount_late]
fn moved_mount_keeps_policy<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-move")?;
    env.start_control()?;
    let mut actor = env.start_actor("mount_alias.py", &["move"])?;
    let pid = actor.id();
    env.place(pid)?;
    env.install_policy("mount_alias_policy.json")?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    env.recovered(pid, "move mount actor")?;
    let path = env.maps().0.to_owned();
    let bad = |reason| {
        InvalidInputSnafu {
            path: &path,
            reason,
        }
        .build()
    };
    let ns = u32::try_from(fs::metadata(format!("/proc/{pid}/ns/mnt"))?.ino())?;
    let ns_key = ns.to_ne_bytes();
    let view = |env: &P| {
        wait_for(
            &path,
            "mount security view",
            Duration::from_secs(30),
            || {
                env.maps()
                    .1
                    .lookup("mount_security_view_locks", &ns_key)
                    .map(|value| value.map(drop))
                    .map_err(|error| bad(error.to_string()))
            },
            || format!("mount namespace {ns} has no security-view lock"),
        )
    };
    view(&env)?;
    let key = 0_u32.to_ne_bytes();
    let count = |name| -> crate::Result<u64> {
        env.state(name, &key, name)
            .map_err(|error| bad(error.to_string()))?
            .ok_or_else(|| bad(format!("{name} is missing")))
    };
    let e = "mount_global_mutation_epoch";
    let a = "mount_global_activity_sequence";
    let c = "mount_global_clean_epoch";
    let p = "mount_global_pending_mutations";
    let result_path = env.work().join("mount-result.json");
    let last = RefCell::new(String::from("<none>"));
    let phase = |want: &str, name: &str| {
        wait_for(
            &result_path,
            name,
            Duration::from_secs(30),
            || {
                let text =
                    fs::read_to_string(&result_path).map_err(|error| bad(error.to_string()))?;
                let value = serde_json::from_str::<serde_json::Value>(&text).ok();
                let state = (count(e)?, count(a)?, count(c)?, count(p)?);
                *last.borrow_mut() = format!("result={text:?}; counters={state:?}");
                Ok(value
                    .filter(|value| value["phase"] == want)
                    .map(|value| (value, state)))
            },
            || last.borrow().clone(),
        )
    };
    let before = (count(e)?, count(a)?);
    actor.send(b"open\n")?;
    let (opened, opened_state) = phase("opened", "detached open_tree activity")?;
    assert_eq!(opened["open"], 0);
    assert_eq!(opened["allowed_open"], 0);
    assert_eq!(opened_state.0, before.0);
    assert!(opened_state.1 > before.1);
    actor.send(b"mount\n")?;
    let (moved, state) = phase("mounted", "move_mount attachment")?;
    assert_eq!(moved["mount"], 0);
    assert_eq!(moved["allowed_mount"], 0);
    assert!(state.0 > opened_state.0 && state.1 > opened_state.1);
    assert!(state.0 != state.2 || state.3 != 0);
    env.stop_node()?;
    env.start_node()?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(pid)?;
    let task = env.recovered(pid, "moved mount recovery")?;
    view(&env)?;
    let seen = env
        .snapshot()?
        .recent_effects
        .into_iter()
        .map(|event| (event.source_cpu_id, event.source_sequence))
        .collect::<BTreeSet<_>>();
    actor.send(b"read\n")?;
    actor.close();
    let status = actor.wait_exit("move mount reads", Duration::from_secs(5))?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value = serde_json::from_slice(&fs::read(&result_path)?)?;
    wait_for(
        &path,
        "move mount effects",
        Duration::from_secs(30),
        || {
            let fresh = env
                .snapshot()
                .map_err(|error| bad(error.to_string()))?
                .recent_effects
                .into_iter()
                .filter(|event| !seen.contains(&(event.source_cpu_id, event.source_sequence)))
                .collect::<Vec<_>>();
            *last.borrow_mut() = format!("{:?}", fresh.iter().rev().take(8));
            let matches = |reason: &str, result| {
                fresh.iter().any(|event| {
                    event.task_cookie == task.snapshot.task_cookie
                        && event.reason == reason
                        && event.effect_family == u32::from(F::File as u16)
                        && event.operation == u32::from(O::OpenRead as u16)
                        && event.active_role_id == task.snapshot.active_role_id
                        && event.admitted_entry_rule_id == task.snapshot.admitted_entry_rule_id
                        && event.kernel_result == result
                })
            };
            Ok((matches("PATH_TREE_POLICY_DENY", -libc::EACCES)
                && matches("EXACT_POLICY_ALLOW", 0))
            .then_some(()))
        },
        || format!("last effects: {}", last.borrow()),
    )?;
    assert_eq!(result["denied"], libc::EACCES);
    assert_eq!(result["allowed"], "allowed bind source\n");
    actor.stop()?;
    env.stop()
}
