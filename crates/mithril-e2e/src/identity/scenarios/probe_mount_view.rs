use std::{fs, sync::Barrier, thread, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};

use crate::effect::EffectCheck;
use crate::physical::mount_cache::MountCache;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(kubernetes)]
#[lifecycle = identity]
fn probe_keeps_mount_view<P: Platform + Sync>() -> TestResult<()> {
    const COUNT: usize = 32;
    let limit = Duration::from_secs(5);
    let reason = "PATH_TREE_POLICY_DENY";
    let (family, op, deny) = (F::File, O::OpenRead, -libc::EACCES);

    let mut env = P::setup("probe-mount-view")?;
    env.start_control()?;
    env.start_node()?;
    let labels = env.install_policy("mount_probe_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("mount_alias.py", &["overlap"], &labels)?;
    let task = env.task(actor.id(), "mount-view actor")?;
    let warm = EffectCheck::new(&env, task.clone())?;
    actor.send(b"mount\nread\n")?;
    actor.wait_name(task.pid, "overlap-warm", "warm bind read", limit)?;
    let path = env.work().join("mount-result.json");
    let result: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    assert_eq!(result["denied"], libc::EACCES, "{result:?}");
    warm.wait(&env, reason, family, op, deny, "warm denial")?;
    warm.wait_match(&env, "startup probe read", |e| {
        (e.effect_family, e.operation, e.kernel_result) == (family as u32, O::Read as u32, 0)
            && e.reason == "EXACT_POLICY_ALLOW"
            && e.composite_atom_id != 0
            && e.task_cookie != task.snapshot.task_cookie
            && e.active_role_id != task.snapshot.active_role_id
            && e.admitted_entry_rule_id != 0
    })?;
    assert!(!env.workload_ready()?, "probe passed its gate");
    let cache = MountCache::new(&env, task.pid)?;
    let before = cache.snapshot()?;
    assert!(!before.keys.is_empty(), "{before:?}");
    let ns = u32::try_from(before.namespace)?.to_ne_bytes().to_vec();
    assert_eq!(env.maps().1.keys("mount_security_views")?, vec![ns.clone()]);
    let key = 0_u32.to_ne_bytes();
    let name = "mount_global_activity_sequence";
    let initial = env.state::<u64>(name, &key, name)?.ok_or("no activity")?;
    let effects = EffectCheck::new(&env, task)?;

    let ((results, after, current, status), events) = effects.capture(&env, || {
        actor.send(b"start\n")?;
        actor.wait_name(actor.id(), "guard-ready", "protected reads", limit)?;
        let gate = Barrier::new(COUNT + 1);
        let results = thread::scope(|scope| {
            let mut entries = Vec::new();
            for _ in 0..COUNT {
                entries.push(scope.spawn(|| {
                    gate.wait();
                    env.add_actor("sleep", &["5"])
                        .map_err(|error| error.to_string())
                }));
            }
            gate.wait();
            entries
                .into_iter()
                .map(|entry| entry.join().map_err(|_| "exec worker panicked"))
                .collect::<Result<Vec<_>, _>>()
        })?;
        let after = cache.snapshot()?;
        assert_eq!(env.maps().1.keys("mount_security_views")?, vec![ns]);
        let current = env.state::<u64>(name, &key, name)?.ok_or("no activity")?;
        fs::write(env.work().join("probe-ready"), b"ready\n")?;
        env.wait_workload_ready()?;
        actor.send(b"stop\n")?;
        let status = actor.wait_exit("native probe overlap", limit)?;
        Ok((results, after, current, status))
    })?;
    assert!(status.success(), "{status}; stderr: {:?}", actor.stderr()?);
    let result: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let count = result["denied"].as_u64().ok_or("no read count")?;
    assert!(count > 0, "{result:?}");
    assert_eq!(result["allowed"], 0, "{result:?}");
    assert_eq!(result["other"], 0, "{result:?}");
    assert_eq!(result["stopped"], true, "{result:?}");
    for result in results {
        let Err(error) = result else {
            result?.stop()?;
            return Err("undeclared concurrent exec succeeded".into());
        };
        let denied = error.contains("permission denied") || error.contains("status: 13");
        assert!(denied, "{error}");
    }
    assert_eq!(after, before);
    assert!(current > initial, "mount activity: {initial} -> {current}");
    effects.wait(&env, reason, family, op, deny, "exec denial")?;
    assert!(events.iter().all(|e| e.reason != "UNRESOLVED_OBJECT"));
    actor.stop()?;
    env.stop()
}
