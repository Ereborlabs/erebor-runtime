use std::{os::unix::fs::MetadataExt, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = bpf_recovery]
fn hard_link_stays_unresolved<P: Platform>() -> TestResult<()> {
    for (case, policy, error, reason) in [
        (
            "hard-link-observe",
            "hard_link_policy.json",
            0,
            "WOULD_DENY",
        ),
        (
            "hard-link-protect",
            "hard_link_protect_policy.json",
            libc::EACCES,
            "EXACT_POLICY_DENY",
        ),
    ] {
        let resource: Policy =
            serde_json::from_str(include_str!("../../fixtures/process/hard_link_policy.json"))?;
        let labels = resource.spec.pod_selector.match_labels;
        let mut env = P::setup(case)?;
        env.start_control()?;
        env.start_node()?;
        let mut init = env.start_actor("ready.py", &[], &labels)?;
        let mut actor =
            env.add_actor("python", &["/fixtures/exception.py", "/work", "hardlink"])?;
        actor.ready()?;
        let pid = actor.id();
        let root = format!("/proc/{pid}/root/tmp");
        let source = std::fs::metadata(format!("{root}/mithril-observe-secret"))?;
        let alias = std::fs::metadata(format!("{root}/mithril-observe-hard"))?;
        assert_eq!((source.dev(), source.ino()), (alias.dev(), alias.ino()));
        assert_eq!(source.nlink(), 2);
        env.install_policy("python_policy.json")?;
        env.sync_policy()?;
        env.node_ready()?;
        env.running(init.id())?;
        let task = env.recovered(pid, "hard-link actor")?;
        assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
        assert_eq!(
            task.snapshot.root_class.as_deref(),
            Some("restored_or_unknown_root")
        );
        let wait = Duration::from_secs(5);
        env.install_policy(policy)?;
        env.node_ready()?;
        let task = env.task(pid, "hard-link actor")?;
        let effects = EffectCheck::new(&env, task)?;

        actor.send(b"hard\n")?;
        actor
            .wait_name(
                pid,
                &format!("link-hard-{error}-{}", libc::EACCES),
                "original read and hard-link denial",
                wait,
            )
            .inspect_err(|_| eprintln!("hard-link failure: {:?}", env.snapshot()))?;
        let original = effects.wait(
            &env,
            reason,
            F::File,
            O::OpenRead,
            -error,
            "original exact file evidence",
        )?;
        assert_ne!(original.exact_object_key_id, 0);
        assert_ne!(original.composite_atom_id, 0);
        let linked = effects.wait(
            &env,
            "UNRESOLVED_OBJECT",
            F::File,
            O::OpenRead,
            -libc::EACCES,
            "hard-link denial evidence",
        )?;
        assert_eq!(linked.task_cookie, original.task_cookie);
        assert_eq!(linked.exact_object_key_id, 0);
        assert_eq!(linked.composite_atom_id, 0);

        actor.stop()?;
        init.stop()?;
        env.stop()?;
    }
    Ok(())
}
