use std::{collections::BTreeSet, fs};

use erebor_interceptor_abi::{KernelEffectFamilyV1 as F, KernelEffectOperationV1 as O};
use mithril_control::WorkloadProtectionException as Exception;

use super::EffectCheck;
use crate::platform::{platform_test, Platform, TestResult};

#[platform_test(host)]
#[lifecycle = exception]
fn excess_uses_are_rejected<P: Platform>() -> TestResult<()> {
    let mut env = P::setup("exception-limit")?;
    env.start_control()?;
    env.start_node()?;
    fs::write(env.work().join("expired-secret"), b"")?;
    let labels = env.install_policy("exception_policy.json")?;
    env.node_ready()?;
    let mut actor = env.start_actor("exception.py", &["single"], &labels)?;
    let task = env.task(actor.id(), "exception actor")?;
    let mut request: Exception = serde_json::from_str(include_str!(
        "../../fixtures/process/one_use_exception.json"
    ))?;
    request.metadata.name = Some("excessive-write".into());
    request.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
    request.spec.requested_uses = 2;
    let file = env.work().join("exception.json");
    fs::write(&file, serde_json::to_vec(&request)?)?;
    let file = file.to_str().ok_or("invalid exception path")?;
    let maps = ["exception_runtime_states", "exception_use_receipts"];
    let before = maps
        .iter()
        .map(|map| Ok((*map, BTreeSet::from_iter(env.maps().1.keys(map)?))))
        .collect::<TestResult<Vec<_>>>()?;
    let error = env
        .install_policy(file)
        .expect_err("excess uses were accepted");
    let detail = error.to_string();
    assert!(
        detail.contains("the exception desired transaction failed: active base policy")
            || (detail.contains("Kubernetes exception rejected:")
                && detail.contains("state: Failed")
                && detail.contains("ReconcileRejected")),
        "{detail}"
    );
    for (map, keys) in before {
        let after = BTreeSet::from_iter(env.maps().1.keys(map)?);
        assert!(after.is_subset(&keys), "{map}: {keys:?} -> {after:?}");
    }

    let mut atom = None;
    for (command, output, code) in [
        ("before", "expired-result", libc::EACCES),
        ("first", "again-result", 0),
        ("second", "race-result", libc::EACCES),
    ] {
        if command == "first" {
            request.metadata.name = Some("valid-write".into());
            request.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
            request.spec.requested_uses = 1;
            fs::write(file, serde_json::to_vec(&request)?)?;
            env.install_policy(file)?;
        }
        let check = EffectCheck::new(&env, task.clone())?;
        actor.send(format!("{command}\n").as_bytes())?;
        let text = actor.wait_text(&env.work().join(output), command)?;
        assert_eq!(text.trim().parse::<i32>()?, code, "{command}");
        let reason = if code == 0 {
            "EXACT_POLICY_ALLOW"
        } else {
            "EXCEPTION_UNAVAILABLE"
        };
        let event = check.wait_match(&env, command, |event| {
            task.matches_effect(event, reason, F::File, O::OpenWrite, -code)
                && atom.is_none_or(|value| event.composite_atom_id == value)
        })?;
        assert_eq!(
            event.profile_generation_ref_id,
            task.snapshot.profile_generation_ref_id
        );
        assert_eq!(event.exact_object_key_id, 0);
        let target = atom.get_or_insert(event.composite_atom_id);
        assert_ne!(*target, 0);
        assert_eq!(event.composite_atom_id, *target);
    }

    actor.send(b"stop\n")?;
    actor.stop()?;
    env.stop()
}
