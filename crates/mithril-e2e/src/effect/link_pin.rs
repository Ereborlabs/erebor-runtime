use std::{fs, os::unix::fs::MetadataExt as _, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionPolicy as Policy;
use rustix::fs::{statat, AtFlags};

use super::check::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult, PROCESS_FIXTURES};
use crate::process::ProcessFixture;

#[platform_test(host, runc, kubernetes)]
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
    let mut actors = [
        env.add_actor("python", &args)?,
        env.add_actor("python", &args)?,
    ];
    for actor in &mut actors {
        actor.ready()?;
        env.place(actor.id())?;
    }
    let links = env.maps().0.join("links");
    let pin = links.join("erebor_identity_file_open");
    let original = fs::metadata(&pin)?;
    let root = fs::File::open(format!("/proc/{}/root", init.id()))?;
    let script = env.source().join(PROCESS_FIXTURES).join("link_pin.py");
    let pid = init.id().to_string();
    let mut helper = ProcessFixture::python(&script, [pid.as_ref(), links.as_os_str()])?;
    let target = "work/protected/erebor_identity_file_open";
    let mounted = statat(&root, target, AtFlags::empty())?;
    assert_eq!(
        (mounted.st_dev, mounted.st_ino),
        (original.dev(), original.ino())
    );
    env.install_policy("python_policy.json")?;
    env.sync_policy()?;
    env.node_ready()?;
    env.running(init.id())?;
    env.recovered(init.id(), "link removal workload")?;
    let wait = Duration::from_secs(5);
    let denied_name = format!("effect-{}", libc::EACCES);
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
        actor.wait_name(pid, &denied_name, "BPF unlink denial", wait)?;
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
        let mounted = statat(&root, target, AtFlags::empty())?;
        assert_eq!(
            (mounted.st_dev, mounted.st_ino),
            (original.dev(), original.ino())
        );
        actor.send(b"release\n")?;
        actor.wait_gone(pid, "link removal actor exit")?;
        actor.stop()?;
    }
    helper.stop()?;
    let status = helper.wait_exit("BPF link mount cleanup", wait)?;
    assert!(status.success(), "{status}; stderr: {:?}", helper.stderr()?);
    init.stop()?;
    env.stop()
}
