use std::{fs, os::unix::fs::MetadataExt as _, path::Path, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;

use super::check::EffectCheck;
use crate::physical::FixtureBindMounts;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host, runc)]
#[lifecycle = bpf_recovery]
fn link_pin_removal_is_denied<P: Platform>() -> TestResult<()> {
    let source: Policy =
        serde_json::from_str(include_str!("../../fixtures/process/python_policy.json"))?;
    let labels = source.spec.pod_selector.match_labels;
    let mut env = P::setup("link-pin")?;
    env.start_control()?;
    env.start_node()?;
    fs::create_dir(env.work().join("protected"))?;
    let mut init = env.start_actor("ready.py", &[], &labels)?;
    env.place(init.id())?;
    let args = [
        "/fixtures/file_mutation.py",
        "/work",
        "unlink",
        "/work/protected/erebor_identity_file_open",
    ];
    let mut actors = Vec::new();
    for _ in 0..2 {
        let mut actor = env.add_actor("python", &args)?;
        actor.ready()?;
        env.place(actor.id())?;
        actors.push(actor);
    }
    let mut mounts = FixtureBindMounts::in_actor(init.id())?;
    let links = env.maps().0.join("links");
    let pin = links.join("erebor_identity_file_open");
    let original = fs::metadata(&pin)?;
    mounts.bind(&links, Path::new("/work/protected"))?;
    let target = Path::new("/work/protected/erebor_identity_file_open");
    let mounted = fs::File::from(mounts.target(target)?).metadata()?;
    assert_eq!(mounted.dev(), original.dev());
    assert_eq!(mounted.ino(), original.ino());
    env.install_policy("python_policy.json")?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "link removal workload")?;
    for (mut actor, policy) in actors
        .into_iter()
        .zip(["python_policy.json", "exec_observe_policy.json"])
    {
        env.install_policy(policy)?;
        env.node_ready()?;
        let pid = actor.id();
        let task = env.task(pid, "link removal actor")?;
        assert_eq!(
            task.snapshot.root_class.as_deref(),
            Some("restored_or_unknown_root")
        );
        assert_eq!(task.snapshot.admitted_entry_rule_id, 0);
        let effects = EffectCheck::new(&env, task)?;

        actor.send(b"unlink\n")?;
        actor.wait_name(
            pid,
            &format!("effect-{}", libc::EACCES),
            "BPF link removal denial",
            Duration::from_secs(5),
        )?;
        let denied = effects.wait(
            &env,
            "UNRESOLVED_OBJECT",
            F::File,
            O::Unlink,
            -libc::EACCES,
            "BPF link removal evidence",
        )?;
        assert_eq!(denied.exact_object_key_id, 0);
        assert_eq!(denied.composite_atom_id, 0);
        assert_eq!(fs::metadata(&pin)?.ino(), original.ino());
        assert_eq!(
            fs::File::from(mounts.target(target)?).metadata()?.ino(),
            original.ino()
        );
        actor.send(b"release\n")?;
        actor.wait_gone(pid, "link removal actor exit")?;
        actor.stop()?;
    }
    mounts.cleanup()?;
    init.stop()?;
    env.stop()
}
