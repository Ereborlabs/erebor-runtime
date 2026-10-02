use std::{collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::physical::mount_cache::MountCache;
use crate::platform::{platform_test, Platform, TestResult};
use crate::process::ProcessFixture;

#[platform_test(host)]
#[lifecycle = bpf_recovery]
fn propagation_rebuilds_namespaces<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("mount-propagation")?;
    env.start_control()?;
    env.start_node()?;
    let policy: Policy = serde_json::from_str(include_str!(
        "../../fixtures/process/mount_alias_policy.json"
    ))?;
    let labels = policy.spec.pod_selector.match_labels;
    let mut actor = env.start_actor("mount_alias.py", &["shared"], &labels)?;
    let work = env.work().to_owned();
    let script = env
        .source()
        .join("crates/mithril-e2e/fixtures/process/mount_alias.py");
    let pid = actor.id().to_string();
    let mut helper = ProcessFixture::python(&script, [&pid, "external-bind"])?;
    env.install_policy("mount_alias_policy.json")?;
    env.sync_policy()?;
    env.node_ready()?;
    let wait = Duration::from_secs(5);
    actor.send(b"peer\n")?;
    actor.wait_name(actor.id(), "cache-peer-up", "mount peer readiness", wait)?;
    let peer = actor.wait_child(actor.id(), "mount peer")?;
    actor.track(peer)?;
    let cache = MountCache::new(&env, actor.id())?;

    for policy in ["mount_alias_policy.json", "mount_observe_policy.json"] {
        assert_eq!(env.install_policy(policy)?, labels);
        env.sync_policy()?;
        env.node_ready()?;
        for phase in ["b", "bind", "unmount"] {
            let before = cache.snapshot()?;
            let mut namespaces = BTreeSet::new();
            let marker = if phase == "bind" { 0 } else { libc::ENOENT };
            if phase != "b" {
                helper.send(format!("{phase}\n").as_bytes())?;
                let mounted = u8::from(phase == "bind");
                let name = format!("mnt-{phase}-{mounted}");
                helper.wait_name(helper.id(), &name, "external propagation", wait)?;
                assert!(cache.snapshot()?.epoch > before.epoch, "{policy}: {phase}");
            }
            for (pid, prefix) in [(actor.id(), ""), (peer, "p")] {
                let task = env.recovered(pid, "mount namespace actor")?;
                let cookie = task.snapshot.task_cookie;
                let effects = EffectCheck::new(&env, task)?;
                actor.send(format!("{prefix}{phase}\n").as_bytes())?;
                let name = format!("read-{prefix}{phase}");
                actor.wait_name(actor.id(), &name, "benign cache read", wait)?;
                let text = actor.wait_text(&work.join("mount-result.json"), "benign result")?;
                let result: serde_json::Value = serde_json::from_str(&text)?;
                assert_eq!(result["errno"], 0, "{policy}: {phase}: {text}");
                assert_eq!(result["value"], "allowed bind source\n");
                assert_eq!(result["marker_errno"], marker, "{policy}: {phase}: {text}");
                let namespace = result["mount_namespace"]
                    .as_u64()
                    .ok_or("missing namespace")?;
                assert_ne!(namespace, 0);
                namespaces.insert(namespace);
                let task = env.task(pid, "benign reader identity")?;
                assert_eq!(task.snapshot.task_cookie, cookie);
                let event = effects.wait_match(&env, "benign cache evidence", |event| {
                    task.matches_effect(event, "EXACT_POLICY_ALLOW", F::File, O::OpenRead, 0)
                })?;
                assert_ne!(event.composite_atom_id, 0, "{event:?}");
            }
            assert_eq!(namespaces.len(), 2, "{policy}: {phase}: {namespaces:?}");
            assert!(namespaces.contains(&before.namespace));
            let after = cache.snapshot()?;
            assert!(!after.keys.is_empty(), "{policy}: {phase}: {after:?}");
            if phase != "b" {
                assert!(
                    after.keys.difference(&before.keys).count() >= 2,
                    "{policy}: {phase}: {before:?} -> {after:?}"
                );
            }
        }
    }

    helper.send(b"stop\n")?;
    helper.stop()?;
    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
